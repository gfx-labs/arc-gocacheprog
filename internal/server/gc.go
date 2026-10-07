package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const gcBatch = 500

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

// evictOverQuota deletes least recently accessed entries in namespaces whose
// total entry size exceeds the quota. Sizes are logical, so a blob shared by
// two entries counts twice.
func (g *GC) evictOverQuota(ctx context.Context) (int64, error) {
	tag, err := g.store.pool.Exec(ctx, `
		DELETE FROM entries e USING (
			SELECT namespace, scope, action_id FROM (
				SELECT namespace, scope, action_id,
				       sum(size) OVER (PARTITION BY namespace
				                       ORDER BY accessed_at DESC, created_at DESC, scope, action_id) AS running
				FROM entries
			) r WHERE running > $1
		) v
		WHERE e.namespace = v.namespace AND e.scope = v.scope AND e.action_id = v.action_id`,
		g.cfg.NamespaceMaxBytes)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// deleteUnreferencedBlobs removes blobs no entry points at and that have not
// been touched within the grace period. Each candidate is locked FOR UPDATE.
// Uploads that dedup against a blob update its accessed_at under the same row
// lock, so they either finish first (and the recheck on accessed_at skips the
// row) or wait and then see the row gone and upload again.
func (g *GC) deleteUnreferencedBlobs(ctx context.Context, st *GCStats) error {
	cutoff := g.now().Add(-g.cfg.BlobGrace)
	for {
		n := 0
		err := pgx.BeginFunc(ctx, g.store.pool, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `
				SELECT b.hash, b.size, b.inline_data IS NOT NULL FROM blobs b
				WHERE b.accessed_at < $1
				  AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.blob_hash = b.hash)
				LIMIT $2
				FOR UPDATE SKIP LOCKED`, cutoff, gcBatch)
			if err != nil {
				return err
			}
			type cand struct {
				hash   []byte
				size   int64
				inline bool
			}
			var cands []cand
			for rows.Next() {
				var c cand
				if err := rows.Scan(&c.hash, &c.size, &c.inline); err != nil {
					return err
				}
				cands = append(cands, c)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			for _, c := range cands {
				// Skip hashes an upload is writing right now. Try-lock so we
				// never wait while holding row locks.
				var got bool
				if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock("+hashLockKey+")", c.hash).Scan(&got); err != nil {
					return err
				}
				if !got {
					continue
				}
				tag, err := tx.Exec(ctx, `DELETE FROM blobs b WHERE b.hash = $1
					AND NOT EXISTS (SELECT 1 FROM entries e WHERE e.blob_hash = b.hash)`, c.hash)
				if err != nil {
					return err
				}
				if tag.RowsAffected() == 0 {
					continue
				}
				if !c.inline {
					if err := g.blobs.Delete(ctx, c.hash); err != nil {
						return err
					}
				}
				n++
				st.DeletedBlobs++
				st.DeletedBytes += c.size
			}
			return nil
		})
		if err != nil {
			return err
		}
		if n < gcBatch {
			return nil
		}
	}
}

// sweepOrphans deletes S3 objects that have no blob row and are older than
// the grace period. These come from uploads that failed between the S3 put
// and the metadata insert.
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
			err := pgx.BeginFunc(ctx, g.store.pool, func(tx pgx.Tx) error {
				// An upload holding the shared lock may be about to insert the row.
				var got bool
				if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock("+hashLockKey+")", h).Scan(&got); err != nil {
					return err
				}
				if !got {
					return nil
				}
				var exists bool
				if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM blobs WHERE hash=$1)", h).Scan(&exists); err != nil {
					return err
				}
				if exists {
					return nil
				}
				deleted++
				return g.blobs.Delete(ctx, h)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return deleted, err
}
