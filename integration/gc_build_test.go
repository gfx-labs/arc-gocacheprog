package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/gfx-labs/arc-gocacheprog/internal/client"
	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

func TestGC(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := remote(e, testKey)
	pool := e.Store.Pool()

	old, fresh, shared := newBlob(t, 8192), newBlob(t, 8192), newBlob(t, 50)
	for name, b := range map[string]blob{"old": old, "fresh": fresh, "shared1": shared, "shared2": shared} {
		if err := put(t, r, action(name), b); err != nil {
			t.Fatal(err)
		}
	}
	// Age "old" and one of the two entries sharing a blob past the TTL.
	if _, err := pool.Exec(ctx, `UPDATE entries SET accessed_at = now() - interval '30 days'
		WHERE action_id = ANY($1)`, [][]byte{action("old"), action("shared1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE blobs SET accessed_at = now() - interval '30 days'`); err != nil {
		t.Fatal(err)
	}

	gc := server.NewGC(server.GCConfig{EntryTTL: 7 * 24 * time.Hour, BlobGrace: time.Hour, OrphanSweep: true}, e.Store, e.Blobs, nil)
	st, err := gc.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.ExpiredEntries != 2 || st.DeletedBlobs != 1 {
		t.Fatalf("unexpected stats %+v", st)
	}
	if _, err := e.Blobs.Get(ctx, old.blake3); !errors.Is(err, server.ErrBlobMissing) {
		t.Fatalf("old blob still in s3: %v", err)
	}
	if got, _ := get(t, r, action("fresh")); !bytes.Equal(got, fresh.data) {
		t.Fatal("fresh entry lost")
	}
	if got, _ := get(t, r, action("shared2")); !bytes.Equal(got, shared.data) {
		t.Fatal("blob still referenced by a live entry was collected")
	}

	// Reads bump accessed_at once it is older than the touch interval.
	if _, err := pool.Exec(ctx, `UPDATE entries SET accessed_at = now() - interval '2 hours' WHERE action_id = $1`, action("fresh")); err != nil {
		t.Fatal(err)
	}
	get(t, r, action("fresh")) //nolint:errcheck
	var age time.Duration
	pool.QueryRow(ctx, `SELECT extract(epoch from now() - accessed_at)::bigint * 1000000000 FROM entries WHERE action_id = $1`, action("fresh")).Scan(&age) //nolint:errcheck
	if age > time.Minute {
		t.Fatalf("access time not bumped, age %v", age)
	}

	// Orphaned S3 objects (no blob row) are swept once past the grace period.
	orphan := newBlob(t, 4096)
	f := filepath.Join(t.TempDir(), "o")
	os.WriteFile(f, orphan.data, 0o644) //nolint:errcheck
	fh, _ := os.Open(f)
	if err := e.Blobs.Put(ctx, orphan.blake3, fh, int64(len(orphan.data))); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	gcNow := server.NewGC(server.GCConfig{BlobGrace: -time.Hour, OrphanSweep: true}, e.Store, e.Blobs, nil)
	st, err = gcNow.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.OrphanObjects != 1 {
		t.Fatalf("expected 1 orphan, got %+v", st)
	}

	// Objects with a live upload lease are not swept even without a row.
	leased := newBlob(t, 4096)
	os.WriteFile(f, leased.data, 0o644) //nolint:errcheck
	fh, _ = os.Open(f)
	lease, err := e.Store.StartUpload(ctx, leased.blake3)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Blobs.Put(ctx, leased.blake3, fh, int64(len(leased.data))); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	if st, err = gcNow.Run(ctx); err != nil || st.OrphanObjects != 0 {
		t.Fatalf("leased object swept: %+v %v", st, err)
	}
	e.Store.EndUpload(ctx, lease) //nolint:errcheck
	if st, err = gcNow.Run(ctx); err != nil || st.OrphanObjects != 1 {
		t.Fatalf("object not swept after lease ended: %+v %v", st, err)
	}

	// Quota eviction keeps the most recently used entries.
	gcQuota := server.NewGC(server.GCConfig{NamespaceMaxBytes: 9000, BlobGrace: time.Hour}, e.Store, e.Blobs, nil)
	if _, err := pool.Exec(ctx, `UPDATE entries SET accessed_at = now() - interval '1 hour' WHERE action_id = $1`, action("shared2")); err != nil {
		t.Fatal(err)
	}
	big := newBlob(t, 8192)
	put(t, r, action("big"), big) //nolint:errcheck
	st, err = gcQuota.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.EvictedEntries == 0 {
		t.Fatalf("expected evictions, got %+v", st)
	}
	if got, _ := get(t, r, action("big")); !bytes.Equal(got, big.data) {
		t.Fatal("most recent entry was evicted")
	}
}

// TestGoBuild runs a real go build through the client binary twice with
// separate local caches. The second build must be served from the server.
func TestGoBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds Go code")
	}
	e := newEnv(t)
	bin := filepath.Join(t.TempDir(), "arc-gocacheprog")
	build := exec.Command("go", "build", "-o", bin, "github.com/gfx-labs/arc-gocacheprog/cmd/arc-gocacheprog")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build client: %v\n%s", err, out)
	}

	// A small module with a dependency on the standard library only.
	mod := t.TempDir()
	os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module example.com/m\n\ngo 1.24\n"), 0o644) //nolint:errcheck
	os.WriteFile(filepath.Join(mod, "main.go"), []byte(`package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {
	b, _ := json.Marshal(map[string]int{"a": 1})
	fmt.Println(string(b), http.StatusOK)
}
`), 0o644) //nolint:errcheck

	run := func(name, token string) map[string]int64 {
		t.Helper()
		local := filepath.Join(t.TempDir(), name)
		cmd := exec.Command("go", "build", "-o", filepath.Join(t.TempDir(), "out"), ".")
		cmd.Dir = mod
		cmd.Env = append(os.Environ(),
			"GOCACHEPROG="+bin,
			"GOFLAGS=-trimpath",
			"ARC_GOCACHE_URL="+e.URL,
			"ARC_GOCACHE_AUTH=key",
			"ARC_GOCACHE_KEY="+token,
			"ARC_GOCACHE_DIR="+local,
			"ARC_GOCACHE_VERBOSE=1",
			"GOTOOLCHAIN=local",
		)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s go build: %v\n%s", name, err, stderr.String())
		}
		return parseStats(t, stderr.String())
	}

	first := run("first", testKey)
	if first["uploads"] == 0 || first["remote_hits"] != 0 {
		t.Fatalf("first build stats: %v", first)
	}
	second := run("second", testKey)
	if second["remote_hits"] == 0 || second["get_errors"] != 0 {
		t.Fatalf("second build stats: %v", second)
	}
	// Nearly everything should come from the server; misses are only the
	// few actions cmd/go never caches remotely the first time.
	if second["misses"] > second["remote_hits"]/10 {
		t.Fatalf("too many misses on second build: %v", second)
	}
	t.Logf("first=%v second=%v goos=%s", first, second, runtime.GOOS)
}

var statRe = regexp.MustCompile(`(\w+)=(\d+)`)

func parseStats(t testing.TB, stderr string) map[string]int64 {
	for _, line := range bytes.Split([]byte(stderr), []byte("\n")) {
		if !bytes.Contains(line, []byte("cache stats")) {
			continue
		}
		m := map[string]int64{}
		for _, s := range statRe.FindAllStringSubmatch(string(line), -1) {
			n, _ := strconv.ParseInt(s[2], 10, 64)
			m[s[1]] = n
		}
		return m
	}
	t.Fatalf("no stats line in output:\n%s", stderr)
	return nil
}

func TestQuotaProtectsDefaultRefs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok := func(ref string) *client.Remote {
		return remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", ref, nil)))
	}
	main, feat := tok("refs/heads/main"), tok("refs/heads/feature")
	mb := newBlob(t, 4096)
	if err := put(t, main, action("main"), mb); err != nil {
		t.Fatal(err)
	}
	// Main's entry is older than every feature entry.
	e.Store.Pool().Exec(ctx, `UPDATE entries SET accessed_at = now() - interval '1 day'`) //nolint:errcheck
	for i := range 4 {
		if err := put(t, feat, action(fmt.Sprint("f", i)), newBlob(t, 4096)); err != nil {
			t.Fatal(err)
		}
	}
	gc := server.NewGC(server.GCConfig{NamespaceMaxBytes: 3 * 4096, ProtectedScopes: e.Config.GC.ProtectedScopes, BlobGrace: time.Hour}, e.Store, e.Blobs, nil)
	st, err := gc.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.EvictedEntries != 2 {
		t.Fatalf("expected 2 evictions, got %+v", st)
	}
	if got, _ := get(t, main, action("main")); !bytes.Equal(got, mb.data) {
		t.Fatal("protected default branch entry was evicted")
	}
}

func TestMissingObjectHeals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	r := remote(e, testKey)
	b := newBlob(t, 4096)
	if err := put(t, r, action("a"), b); err != nil {
		t.Fatal(err)
	}
	if err := e.Blobs.Delete(ctx, b.blake3); err != nil {
		t.Fatal(err)
	}
	if got, err := get(t, r, action("a")); got != nil || err != nil {
		t.Fatalf("expected miss, got %v %v", got != nil, err)
	}
	var n int
	e.Store.Pool().QueryRow(ctx, "SELECT count(*) FROM blobs").Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Fatal("missing blob row was not dropped")
	}
	// Uploading again restores it rather than linking to the dead blob.
	if err := put(t, r, action("a"), b); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, r, action("a")); !bytes.Equal(got, b.data) {
		t.Fatal("re-upload did not restore the object")
	}
}
