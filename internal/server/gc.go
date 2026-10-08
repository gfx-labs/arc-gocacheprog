package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const gcBatch = 500

// minEntryQuotaBytes is the least an entry counts against the namespace
// quota, so empty or tiny entries cannot grow the entries table unbounded.
// Quota accounting is a charge, not exact physical storage.
const minEntryQuotaBytes = 1024

// GCStats reports what one GC pass removed.
type GCStats struct {
	ExpiredEntries int64
	EvictedEntries int64
	DeletedBlobs   int64
	DeletedBytes   int64
	OrphanObjects  int64
}

// GC removes expired entries and unreferenced blobs.
type GC struct {
	cfg   GCConfig
	store *Store
	blobs *BlobStore
	log   *slog.Logger
	now   func() time.Time
}

func NewGC(cfg GCConfig, store *Store, blobs *BlobStore, log *slog.Logger) *GC {
	if log == nil {
		log = slog.Default()
	}
	return &GC{cfg: cfg, store: store, blobs: blobs, log: log, now: time.Now}
}

// Loop runs GC every interval until ctx is done. Only one server holding the
// advisory lock runs a pass at a time.
func (g *GC) Loop(ctx context.Context) {
	t := time.NewTicker(g.cfg.Interval)
	defer t.Stop()
	for {
		st, ran, err := g.RunLocked(ctx)
		switch {
		case err != nil:
			g.log.Error("gc failed", "err", err)
		case ran:
			g.log.Info("gc done", "expired", st.ExpiredEntries, "evicted", st.EvictedEntries,
				"blobs", st.DeletedBlobs, "bytes", st.DeletedBytes, "orphans", st.OrphanObjects)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunLocked runs a pass if no other server is running one.
func (g *GC) RunLocked(ctx context.Context) (GCStats, bool, error) {
	conn, err := g.store.pool.Acquire(ctx)
	if err != nil {
		return GCStats{}, false, err
	}
	defer conn.Release()
	const lockID = 0x6763_6763 // "gcgc"
	var got bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&got); err != nil {
		return GCStats{}, false, err
	}
	if !got {
		return GCStats{}, false, nil
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockID) //nolint:errcheck
	st, err := g.Run(ctx)
	return st, true, err
}

// Run performs one GC pass.
func (g *GC) Run(ctx context.Context) (GCStats, error) {
	var st GCStats
	var err error
	if g.cfg.EntryTTL > 0 {
		if st.ExpiredEntries, err = g.expireEntries(ctx); err != nil {
			return st, fmt.Errorf("expire entries: %w", err)
		}
	}
	if g.cfg.NamespaceMaxBytes > 0 {
		if st.EvictedEntries, err = g.evictOverQuota(ctx); err != nil {
			return st, fmt.Errorf("evict: %w", err)
		}
	}
	if err := g.expireLeases(ctx); err != nil {
		return st, fmt.Errorf("expire leases: %w", err)
	}
	if err := g.deleteUnreferencedBlobs(ctx, &st); err != nil {
		return st, fmt.Errorf("delete blobs: %w", err)
	}
	if g.cfg.OrphanSweep && g.blobs != nil {
		if st.OrphanObjects, err = g.sweepOrphans(ctx); err != nil {
			return st, fmt.Errorf("orphan sweep: %w", err)
		}
	}
	return st, nil
}

func (g *GC) expireEntries(ctx context.Context) (int64, error) {
	cutoff := g.now().Add(-g.cfg.EntryTTL)
	var total int64
	for {
		tag, err := g.store.pool.Exec(ctx, `
			DELETE FROM entries WHERE ctid IN (
				SELECT ctid FROM entries WHERE accessed_at < $1 LIMIT $2)`, cutoff, gcBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < gcBatch {
			return total, nil
		}
	}
}

// evictOverQuota deletes entries in namespaces whose total entry size
// exceeds the quota. Entries in protected scopes are kept over others, then
// most recently accessed first. Sizes are logical, so a blob shared by two
// entries counts twice, and each entry is charged at least
// minEntryQuotaBytes. Deletes run in batches.
func (g *GC) evictOverQuota(ctx context.Context) (int64, error) {
	protected := g.cfg.ProtectedScopes
	if protected == nil {
		protected = []string{}
	}
	var total int64
	for {
		tag, err := g.store.pool.Exec(ctx, `
			DELETE FROM entries e USING (
				SELECT namespace, scope, action_id FROM (
					SELECT namespace, scope, action_id,
					       sum(GREATEST(size, $4::bigint)) OVER (PARTITION BY namespace
					                       ORDER BY (scope = ANY($2)) DESC, accessed_at DESC,
					                                created_at DESC, scope, action_id) AS running
					FROM entries
				) r WHERE running > $1
				LIMIT $3
			) v
			WHERE e.namespace = v.namespace AND e.scope = v.scope AND e.action_id = v.action_id`,
			g.cfg.NamespaceMaxBytes, protected, gcBatch, minEntryQuotaBytes)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < gcBatch {
			return total, nil
		}
	}
}

// deleteUnreferencedBlobs removes blob rows no entry points at that have not
// been touched within the grace period, then deletes their S3 objects after
// the row deletion commits. Linking a blob takes its row lock, so a link
// either commits first (and the NOT EXISTS recheck keeps the row) or waits
// and then sees the row gone and uploads again under a lease.
func (g *GC) deleteUnreferencedBlobs(ctx context.Context, st *GCStats) error {
	cutoff := g.now().Add(-g.cfg.BlobGrace)
	for {
		type cand struct {
			hash   []byte
			size   int64
			inline bool
		}
		var deleted []cand
		err := pgx.BeginFunc(ctx, g.store.pool, func(tx pgx.Tx) error {
			deleted = deleted[:0]
			rows, err := tx.Query(ctx, `
				SELECT b.hash, b.size, b.inline_data IS NOT NULL FROM blobs b
				WHERE b.accessed_at < $1
				  AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.blob_hash = b.hash)
				LIMIT $2
				FOR UPDATE SKIP LOCKED`, cutoff, gcBatch)
			if err != nil {
				return err
			}
			cands, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cand, error) {
				var c cand
				err := r.Scan(&c.hash, &c.size, &c.inline)
				return c, err
			})
			if err != nil {
				return err
			}
			for _, c := range cands {
				tag, err := tx.Exec(ctx, `DELETE FROM blobs b WHERE b.hash = $1
					AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.blob_hash = b.hash)`, c.hash)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 1 {
					deleted = append(deleted, c)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, c := range deleted {
			st.DeletedBlobs++
			st.DeletedBytes += c.size
			if c.inline {
				continue
			}
			// If this fails the object becomes an orphan for the sweep.
			if _, err := g.deleteObjectIfUnowned(ctx, c.hash); err != nil {
				g.log.Warn("delete object", "hash", hex.EncodeToString(c.hash), "err", err)
			}
		}
		if len(deleted) < gcBatch {
			return nil
		}
	}
}

// deleteObjectIfUnowned deletes the S3 object for hash when no blob row and
// no live upload lease exist. The exclusive per-hash advisory lock blocks
// StartUpload for the duration of the check and delete, so an upload either
// registers its lease first (and we skip) or starts after the delete.
func (g *GC) deleteObjectIfUnowned(ctx context.Context, hash []byte) (bool, error) {
	deleted := false
	err := pgx.BeginFunc(ctx, g.store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock("+hashLockKey+")", hash); err != nil {
			return err
		}
		var owned bool
		if err := tx.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM blobs WHERE hash = $1) OR
			EXISTS (SELECT 1 FROM upload_leases WHERE hash = $1)`, hash).Scan(&owned); err != nil {
			return err
		}
		if owned {
			return nil
		}
		if err := g.blobs.Delete(ctx, hash); err != nil {
			return err
		}
		deleted = true
		return nil
	})
	return deleted, err
}

// expireLeases removes leases of uploads that died without cleaning up.
func (g *GC) expireLeases(ctx context.Context) error {
	if g.cfg.UploadLease <= 0 {
		return nil
	}
	_, err := g.store.pool.Exec(ctx, `DELETE FROM upload_leases WHERE started_at < $1`, g.now().Add(-g.cfg.UploadLease))
	return err
}

// sweepOrphans deletes S3 objects that have no blob row and are older than
// the grace period. These come from uploads that failed between the S3 put
// and the metadata insert, or from failed deletes.
func (g *GC) sweepOrphans(ctx context.Context) (int64, error) {
	cutoff := g.now().Add(-g.cfg.BlobGrace)
	var deleted int64
	err := g.blobs.List(ctx, func(objs []ObjectInfo) error {
		var hashes [][]byte
		for _, o := range objs {
			if o.LastModified.After(cutoff) {
				continue
			}
			if h, ok := g.blobs.HashFromKey(o.Key); ok {
				hashes = append(hashes, h)
			}
		}
		if len(hashes) == 0 {
			return nil
		}
		rows, err := g.store.pool.Query(ctx, `
			SELECT h FROM unnest($1::bytea[]) AS h
			WHERE NOT EXISTS (SELECT 1 FROM blobs b WHERE b.hash = h)`, hashes)
		if err != nil {
			return err
		}
		missing, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			return err
		}
		for _, h := range missing {
			ok, err := g.deleteObjectIfUnowned(ctx, h)
			if err != nil {
				return err
			}
			if ok {
				deleted++
			}
		}
		return nil
	})
	return deleted, err
}
