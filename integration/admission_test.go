package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

// Writes over a namespace's op or byte burst are rejected with 429 before
// the body is spooled or stored, without affecting other namespaces. The op
// refill rate is tiny so a wait computation that overflows would admit.
func TestWriteAdmission(t *testing.T) {
	const maxBlob = 4096
	e := newEnv(t, func(c *server.Config) {
		c.Storage.MaxBlobBytes = maxBlob
		c.Limits.WriteBurst = 3
		c.Limits.WritesPerSec = 1e-300
		c.Limits.WriteBytesBurst = 2 * maxBlob
		c.Limits.WriteBytesPerSec = 1
	})
	ctx := context.Background()
	count := func(q string) int {
		var n int
		if err := e.Store.Pool().QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	objects := func() int {
		var n int
		if err := e.Blobs.List(ctx, func(o []server.ObjectInfo) error { n += len(o); return nil }); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Op burst: three empty writes (3 KiB charged) pass, the fourth is
	// rejected by the op bucket alone.
	r := remote(e, testKey)
	for i := range 3 {
		if err := put(t, r, action(fmt.Sprint("e", i)), newBlob(t, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := put(t, r, action("e3"), newBlob(t, 0)); statusCode(err) != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for fourth write, got %v", err)
	}

	// Byte burst, in another namespace with its own buckets: two max-size
	// uploads use it all and the next is rejected without being stored.
	gh := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)))
	for i := range 2 {
		if err := put(t, gh, action(fmt.Sprint("big", i)), newBlob(t, maxBlob)); err != nil {
			t.Fatal(err)
		}
	}
	blobs, objs := count("SELECT count(*) FROM blobs"), objects()
	if err := put(t, gh, action("over"), newBlob(t, maxBlob)); statusCode(err) != http.StatusTooManyRequests {
		t.Fatalf("expected 429 over byte burst, got %v", err)
	}
	if count("SELECT count(*) FROM blobs") != blobs || objects() != objs {
		t.Fatal("rejected upload was stored")
	}
	// An op remains, but empty writes still pay the minimum byte charge.
	if err := put(t, gh, action("empty"), newBlob(t, 0)); statusCode(err) != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for empty write over byte burst, got %v", err)
	}
}

// The global request limit applies before auth, including health checks.
func TestRequestAdmission(t *testing.T) {
	e := newEnv(t, func(c *server.Config) {
		c.Limits.RequestBurst = 2
		c.Limits.RequestsPerSec = 1e-6
	})
	codes := make([]int, 3)
	for i := range codes {
		resp, err := http0().Get(e.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes[i] = resp.StatusCode
		if i == 2 && resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("unexpected status codes %v", codes)
	}
}
