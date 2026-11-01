package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zeebo/blake3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// DiskCacheConfig configures the local blob cache in front of S3.
type DiskCacheConfig struct {
	// Dir enables the cache. Empty disables it.
	Dir string `yaml:"dir"`
	// MaxBytes is the size the cache is kept under by LRU eviction.
	MaxBytes int64 `yaml:"max_bytes"`
	// MaxBlobBytes is the largest blob kept locally. 0 caches every size.
	MaxBlobBytes int64 `yaml:"max_blob_bytes"`
}

// diskCache keeps recently used S3 blobs on local disk. Blobs are
// content-addressed by BLAKE3 and never change, so a cached copy cannot go
// stale. Copies are only installed after their BLAKE3 hash is verified.
// Access time is the file mtime, refreshed at most once a minute.
type diskCache struct {
	cfg DiskCacheConfig
	log *slog.Logger

	used     atomic.Int64
	evicting atomic.Bool

	hits, misses, fillCount metric.Int64Counter
	evicted                 metric.Int64Counter
	usedGauge               metric.Int64ObservableGauge

	// fillMu dedups concurrent fills of the same blob.
	fillMu sync.Mutex
	fills  map[string]struct{}
}

func newDiskCache(cfg DiskCacheConfig, log *slog.Logger) (*diskCache, error) {
	for _, d := range []string{"b", "tmp"} {
		if err := os.MkdirAll(filepath.Join(cfg.Dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	// Temp files left behind are fills interrupted by a restart.
	if ents, err := os.ReadDir(filepath.Join(cfg.Dir, "tmp")); err == nil {
		for _, e := range ents {
			os.Remove(filepath.Join(cfg.Dir, "tmp", e.Name())) //nolint:errcheck
		}
	}
	c := &diskCache{cfg: cfg, log: log, fills: map[string]struct{}{}}
	var n int64
	for _, f := range c.walk() {
		n += f.size
	}
	c.used.Store(n)

	m := otel.Meter(instrumentationName)
	c.hits, _ = m.Int64Counter("gocache.diskcache.hits", metric.WithDescription("Blob reads served from local disk."))
	c.misses, _ = m.Int64Counter("gocache.diskcache.misses", metric.WithDescription("Blob reads that went to S3."))
	c.fillCount, _ = m.Int64Counter("gocache.diskcache.fills", metric.WithDescription("Blobs written to local disk, by source: get or put."))
	c.evicted, _ = m.Int64Counter("gocache.diskcache.evicted.size", metric.WithUnit("By"), metric.WithDescription("Bytes evicted from local disk."))
	c.usedGauge, _ = m.Int64ObservableGauge("gocache.diskcache.used", metric.WithUnit("By"),
		metric.WithDescription("Bytes held on local disk."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(c.used.Load())
			return nil
		}))
	return c, nil
}

func (c *diskCache) cacheable(size int64) bool {
	return c.cfg.MaxBlobBytes <= 0 || size <= c.cfg.MaxBlobBytes
}

func (c *diskCache) path(hash []byte) string {
	h := hex.EncodeToString(hash)
	return filepath.Join(c.cfg.Dir, "b", h[:2], h)
}

// open returns the cached blob when present and intact. The file is hashed
// before use so disk corruption or tampering falls back to S3 rather than
// sending wrong bytes after the response headers are out. BLAKE3 over a
// local file is far cheaper than the S3 round trip it replaces.
func (c *diskCache) open(ctx context.Context, hash []byte, size int64) io.ReadCloser {
	p := c.path(hash)
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	fi, err := f.Stat()
	h := blake3.New()
	ok := err == nil && fi.Size() == size
	if ok {
		n, err := io.Copy(h, f)
		ok = err == nil && n == size && bytes.Equal(h.Sum(nil), hash)
	}
	if ok {
		_, err = f.Seek(0, io.SeekStart)
		ok = err == nil
	}
	if !ok {
		f.Close()
		c.log.Warn("disk cache copy failed verification, dropping", "hash", hex.EncodeToString(hash))
		c.remove(hash)
		return nil
	}
	if now := time.Now(); now.Sub(fi.ModTime()) > time.Minute {
		os.Chtimes(p, now, now) //nolint:errcheck
	}
	c.hits.Add(ctx, 1)
	return f
}

// claim reserves a fill of hash. It returns false if one is already running.
func (c *diskCache) claim(hash []byte) bool {
	k := string(hash)
	c.fillMu.Lock()
	defer c.fillMu.Unlock()
	if _, ok := c.fills[k]; ok {
		return false
	}
	c.fills[k] = struct{}{}
	return true
}

func (c *diskCache) release(hash []byte) {
	c.fillMu.Lock()
	delete(c.fills, string(hash))
	c.fillMu.Unlock()
}

// install moves a temp file that holds exactly the blob into the cache.
func (c *diskCache) install(ctx context.Context, tmp string, hash []byte, size int64, source string) error {
	dst := c.path(hash)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	c.fillCount.Add(ctx, 1, resultAttr(source))
	if c.used.Add(size) > c.cfg.MaxBytes {
		go c.evict()
	}
	return nil
}

// storeFile copies an uploaded file whose hash the server already verified.
func (c *diskCache) storeFile(ctx context.Context, hash []byte, src *os.File, size int64) {
	if !c.cacheable(size) || !c.claim(hash) {
		return
	}
	defer c.release(hash)
	if _, err := os.Stat(c.path(hash)); err == nil {
		return
	}
	err := func() error {
		tmp, err := os.CreateTemp(filepath.Join(c.cfg.Dir, "tmp"), "put-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		n, err := io.Copy(tmp, io.NewSectionReader(src, 0, size))
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if n != size {
			return fmt.Errorf("copied %d of %d bytes", n, size)
		}
		return c.install(ctx, tmp.Name(), hash, size, "put")
	}()
	if err != nil {
		c.log.Warn("disk cache store", "err", err)
	}
}

// remove drops a blob, for example when GC deletes it from S3.
func (c *diskCache) remove(hash []byte) {
	p := c.path(hash)
	if fi, err := os.Stat(p); err == nil && os.Remove(p) == nil {
		c.used.Add(-fi.Size())
	}
}

// teeReader writes S3 bytes to a temp file as the response streams, and
// installs the file on Close only if the whole blob arrived with the right
// BLAKE3 hash. Any short read, error or mismatch discards it.
type teeReader struct {
	c      *diskCache
	ctx    context.Context
	body   io.ReadCloser
	tmp    *os.File
	hash   []byte
	size   int64
	n      int64
	h      *blake3.Hasher
	failed bool
}

func (c *diskCache) tee(ctx context.Context, body io.ReadCloser, hash []byte, size int64) io.ReadCloser {
	c.misses.Add(ctx, 1)
	if !c.cacheable(size) || !c.claim(hash) {
		return body
	}
	tmp, err := os.CreateTemp(filepath.Join(c.cfg.Dir, "tmp"), "get-*")
	if err != nil {
		c.release(hash)
		c.log.Warn("disk cache temp file", "err", err)
		return body
	}
	return &teeReader{c: c, ctx: context.WithoutCancel(ctx), body: body, tmp: tmp, hash: hash, size: size, h: blake3.New()}
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.body.Read(p)
	if n > 0 && !t.failed {
		if _, werr := t.tmp.Write(p[:n]); werr != nil {
			t.failed = true
		}
		t.h.Write(p[:n]) //nolint:errcheck
		t.n += int64(n)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		t.failed = true
	}
	return n, err
}

func (t *teeReader) Close() error {
	err := t.body.Close()
	defer t.c.release(t.hash)
	name := t.tmp.Name()
	cerr := t.tmp.Close()
	ok := !t.failed && cerr == nil && t.n == t.size && bytes.Equal(t.h.Sum(nil), t.hash)
	if !ok {
		os.Remove(name) //nolint:errcheck
		return err
	}
	if ierr := t.c.install(t.ctx, name, t.hash, t.size, "get"); ierr != nil {
		os.Remove(name) //nolint:errcheck
		t.c.log.Warn("disk cache install", "err", ierr)
	}
	return err
}

type cachedFile struct {
	path  string
	size  int64
	mtime time.Time
}

func (c *diskCache) walk() []cachedFile {
	var out []cachedFile
	filepath.WalkDir(filepath.Join(c.cfg.Dir, "b"), func(p string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			out = append(out, cachedFile{p, fi.Size(), fi.ModTime()})
		}
		return nil
	})
	return out
}

// evict removes least recently used blobs until the cache is at 90% of MaxBytes.
func (c *diskCache) evict() {
	if !c.evicting.CompareAndSwap(false, true) {
		return
	}
	defer c.evicting.Store(false)
	files := c.walk()
	sort.Slice(files, func(i, j int) bool { return files[i].mtime.Before(files[j].mtime) })
	var total int64
	for _, f := range files {
		total += f.size
	}
	target := c.cfg.MaxBytes / 10 * 9
	var freed int64
	for _, f := range files {
		if total <= target {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
			freed += f.size
		}
	}
	c.used.Store(total)
	c.evicted.Add(context.Background(), freed)
	c.log.Info("disk cache evicted", "bytes", freed, "used", total)
}
