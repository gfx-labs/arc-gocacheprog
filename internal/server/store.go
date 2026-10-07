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

// NamespaceHasBlob reports whether namespace already references blob hash.
// Linking is limited to these blobs so a client cannot read content it never
// possessed by guessing a hash.
func (s *Store) NamespaceHasBlob(ctx context.Context, namespace string, hash []byte) (*BlobInfo, error) {
	var b BlobInfo
	err := s.pool.QueryRow(ctx, `
		SELECT b.hash, b.sha256, b.size FROM blobs b
		WHERE b.hash = $2 AND EXISTS (SELECT 1 FROM entries e WHERE e.namespace = $1 AND e.blob_hash = $2)`,
		namespace, hash).Scan(&b.Hash, &b.SHA256, &b.Size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &b, err
}

// errBlobGone signals that a blob row vanished (collected) between checks.
var errBlobGone = errors.New("blob row is gone")

// LinkExisting creates or replaces an entry pointing at an existing blob. It
// bumps the blob's access time inside the transaction, which serializes with
// GC: if GC holds the row it waits, then sees the row gone and returns
// errBlobGone so the caller can upload instead.
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

// hashLockSQL is the advisory lock key for a blob hash. Uploads hold it
// shared while writing the object and row, GC holds it exclusive while
// deleting either.
const hashLockKey = "hashtextextended(encode($1::bytea, 'hex'), 0)"

// InsertBlob records a blob and the entry that points at it. upload, if not
// nil, writes the object to S3 while the per-hash shared lock is held so GC
// cannot delete it between the write and the row insert.
func (s *Store) InsertBlob(ctx context.Context, namespace, scope string, actionID, outputID []byte, b BlobInfo, inline []byte, upload func() error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared("+hashLockKey+")", b.Hash); err != nil {
			return err
		}
		if upload != nil {
			if err := upload(); err != nil {
				return err
			}
		}
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
		return upsertEntry(ctx, tx, namespace, scope, actionID, outputID, b)
	})
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
