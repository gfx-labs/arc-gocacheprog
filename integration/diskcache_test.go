package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

// With the disk cache on, a blob read once is served from local disk, and a
// cached copy that no longer matches its hash is not served.
func TestDiskCache(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, func(c *server.Config) {
		c.Storage.DiskCache = server.DiskCacheConfig{Dir: dir, MaxBytes: 1 << 30}
	})
	ctx := context.Background()
	r := remote(e, testKey)
	b := newBlob(t, 64<<10)
	if err := put(t, r, action("a"), b); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(b.blake3)
	cached := filepath.Join(dir, "b", h[:2], h)
	if got, err := os.ReadFile(cached); err != nil || !bytes.Equal(got, b.data) {
		t.Fatalf("upload not written through to disk cache: %v", err)
	}

	// Remove the object from S3 behind the server's back: hits now prove the
	// body came from disk.
	if _, err := e.S3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(e.Config.S3.Bucket), Key: aws.String(e.Blobs.Key(b.blake3)),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := get(t, r, action("a"))
	if err != nil || !bytes.Equal(got, b.data) {
		t.Fatalf("disk cache hit: %v", err)
	}

	// A corrupted copy of the same size is not served; with S3 gone the
	// entry heals to a miss instead of returning wrong bytes.
	bad := bytes.Repeat([]byte{0}, len(b.data))
	if err := os.WriteFile(cached, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := get(t, r, action("a")); err == nil && bytes.Equal(got, bad) {
		t.Fatal("served corrupted disk cache copy")
	}

	// A read through S3 fills the cache for the next reader.
	c := newBlob(t, 64<<10)
	if err := put(t, r, action("c"), c); err != nil {
		t.Fatal(err)
	}
	hc := hex.EncodeToString(c.blake3)
	cc := filepath.Join(dir, "b", hc[:2], hc)
	if err := os.Remove(cc); err != nil {
		t.Fatal(err)
	}
	if got, err := get(t, r, action("c")); err != nil || !bytes.Equal(got, c.data) {
		t.Fatalf("s3 read: %v", err)
	}
	if got, err := os.ReadFile(cc); err != nil || !bytes.Equal(got, c.data) {
		t.Fatalf("s3 read did not fill disk cache: %v", err)
	}
}
