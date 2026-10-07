package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store holds entry and blob metadata in postgres.
type Store struct {
	pool *pgxpool.Pool
}

func OpenStore(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Migrate applies embedded migrations in order. A session advisory lock keeps
// concurrently starting servers from racing.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	const lockID = 0x6763_7072_6f67 // "gcprog"
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Entry is a resolved cache entry.
type Entry struct {
	Scope      string
	OutputID   []byte
	BlobHash   []byte
	Size       int64
	CreatedAt  time.Time
	AccessedAt time.Time
	// Inline is non-nil when the blob body is stored in postgres.
	Inline []byte
	IsInline bool
}

// Lookup finds the entry for actionID in the first matching scope, in the
// order given.
func (s *Store) Lookup(ctx context.Context, namespace string, scopes []string, actionID []byte) (*Entry, error) {
	var e Entry
	err := s.pool.QueryRow(ctx, `
		SELECT e.scope, e.output_id, e.blob_hash, e.size, e.created_at, e.accessed_at,
		       b.inline_data, b.inline_data IS NOT NULL
		FROM entries e JOIN blobs b ON b.hash = e.blob_hash
		WHERE e.namespace = $1 AND e.scope = ANY($2) AND e.action_id = $3
		ORDER BY array_position($2, e.scope)
		LIMIT 1`, namespace, scopes, actionID).
		Scan(&e.Scope, &e.OutputID, &e.BlobHash, &e.Size, &e.CreatedAt, &e.AccessedAt, &e.Inline, &e.IsInline)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Touch bumps access timestamps on an entry and its blob when they are older
// than interval. Timestamps are loose on purpose to avoid a write per read.
func (s *Store) Touch(ctx context.Context, namespace, scope string, actionID, blobHash []byte, interval time.Duration) error {
	cutoff := time.Now().Add(-interval)
	if _, err := s.pool.Exec(ctx, `UPDATE entries SET accessed_at = now()
		WHERE namespace=$1 AND scope=$2 AND action_id=$3 AND accessed_at < $4`,
		namespace, scope, actionID, cutoff); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE blobs SET accessed_at = now() WHERE hash=$1 AND accessed_at < $2`, blobHash, cutoff)
	return err
}

// BlobInfo is the metadata of a stored blob.
type BlobInfo struct {
	Hash   []byte
	SHA256 []byte
	Size   int64
}

// LinkableBlob returns blob metadata when an entry in one of scopes of
// namespace already references the blob. Linking is limited to these so a
// token cannot obtain content it could not already read by knowing hashes.
func (s *Store) LinkableBlob(ctx context.Context, namespace string, scopes []string, hash []byte) (*BlobInfo, error) {
	var b BlobInfo
	err := s.pool.QueryRow(ctx, `
		SELECT b.hash, b.sha256, b.size FROM blobs b
		WHERE b.hash = $3 AND EXISTS (
			SELECT 1 FROM entries e WHERE e.namespace = $1 AND e.scope = ANY($2) AND e.blob_hash = $3)`,
		namespace, scopes, hash).Scan(&b.Hash, &b.SHA256, &b.Size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &b, err
}

// errBlobGone signals that a blob row vanished (collected) between checks.
var errBlobGone = errors.New("blob row is gone")

// LinkExisting creates or replaces an entry pointing at an existing blob. The
// UPDATE takes the blob row lock, which serializes with GC: if GC holds the
// row it waits, then sees the row gone and returns errBlobGone so the caller
// can upload instead.
func (s *Store) LinkExisting(ctx context.Context, namespace, scope string, actionID, outputID []byte, b BlobInfo) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE blobs SET accessed_at = now() WHERE hash = $1`, b.Hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errBlobGone
		}
		return upsertEntry(ctx, tx, namespace, scope, actionID, outputID, b)
	})
}

// StartUpload records a lease for an upload of hash. GC does not delete S3
// objects for hashes with a live lease. The lease is removed by InsertBlob or
// EndUpload.
func (s *Store) StartUpload(ctx context.Context, hash []byte) (int64, error) {
	var id int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Waits for a GC delete of this hash's object to finish.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared("+hashLockKey+")", hash); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO upload_leases (hash) VALUES ($1) RETURNING id`, hash).Scan(&id)
	})
	return id, err
}

// hashLockKey is the advisory lock key expression for a blob hash.
const hashLockKey = "hashtextextended(encode($1::bytea, 'hex'), 0)"

// EndUpload removes a lease after a failed upload.
func (s *Store) EndUpload(ctx context.Context, lease int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM upload_leases WHERE id = $1`, lease)
	return err
}

// InsertBlob records a blob and the entry that points at it, and releases
// the upload lease if one is given.
func (s *Store) InsertBlob(ctx context.Context, namespace, scope string, actionID, outputID []byte, b BlobInfo, inline []byte, lease int64) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var data any
		if inline != nil {
			data = inline
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO blobs (hash, sha256, size, inline_data) VALUES ($1, $2, $3, $4)
			ON CONFLICT (hash) DO UPDATE SET accessed_at = now()`,
			b.Hash, b.SHA256, b.Size, data); err != nil {
			return err
		}
		if lease != 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM upload_leases WHERE id = $1`, lease); err != nil {
				return err
			}
		}
		return upsertEntry(ctx, tx, namespace, scope, actionID, outputID, b)
	})
}

// BlobIsInline reports whether the blob row stores its data inline.
func (s *Store) BlobIsInline(ctx context.Context, hash []byte) (bool, error) {
	var inline bool
	err := s.pool.QueryRow(ctx, `SELECT inline_data IS NOT NULL FROM blobs WHERE hash = $1`, hash).Scan(&inline)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return inline, err
}

func upsertEntry(ctx context.Context, tx pgx.Tx, namespace, scope string, actionID, outputID []byte, b BlobInfo) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO entries (namespace, scope, action_id, output_id, blob_hash, size)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (namespace, scope, action_id) DO UPDATE SET
			output_id = EXCLUDED.output_id, blob_hash = EXCLUDED.blob_hash, size = EXCLUDED.size,
			created_at = now(), accessed_at = now()`,
		namespace, scope, actionID, outputID, b.Hash, b.Size)
	return err
}

// BlobExists returns blob metadata if the row exists.
func (s *Store) BlobExists(ctx context.Context, hash []byte) (*BlobInfo, error) {
	var b BlobInfo
	err := s.pool.QueryRow(ctx, `SELECT hash, sha256, size FROM blobs WHERE hash = $1`, hash).Scan(&b.Hash, &b.SHA256, &b.Size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &b, err
}

// DropBlob removes a blob row and every entry that references it. Used when
// the object is found missing from S3 so the cache heals itself.
func (s *Store) DropBlob(ctx context.Context, hash []byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM entries WHERE blob_hash = $1", hash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM blobs WHERE hash = $1", hash)
		return err
	})
}
