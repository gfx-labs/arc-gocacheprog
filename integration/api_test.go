package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/blake3"

	"github.com/gfx-labs/arc-gocacheprog/internal/client"
	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

func remote(e *env, tok string) *client.Remote {
	return &client.Remote{BaseURL: e.URL, HTTP: http0(), Tokens: client.StaticToken(tok)}
}

type blob struct {
	data           []byte
	sha256, blake3 []byte
}

func newBlob(t testing.TB, size int) blob {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	h := blake3.Sum256(b)
	return blob{data: b, sha256: s[:], blake3: h[:]}
}

func put(t testing.TB, r *client.Remote, action []byte, b blob) error {
	t.Helper()
	p := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(p, b.data, 0o644); err != nil {
		t.Fatal(err)
	}
	return r.Put(context.Background(), action, b.sha256, b.blake3, int64(len(b.data)), p)
}

// get returns the body or nil on a miss.
func get(t testing.TB, r *client.Remote, action []byte) ([]byte, error) {
	t.Helper()
	var buf bytes.Buffer
	e, err := r.Get(context.Background(), action, &buf)
	if err != nil || e == nil {
		return nil, err
	}
	return append([]byte{}, buf.Bytes()...), nil
}

func action(name string) []byte {
	s := sha256.Sum256([]byte(name))
	return s[:]
}

func statusCode(err error) int {
	var se *client.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestGHAScopes(t *testing.T) {
	e := newEnv(t)
	iss := e.Issuer
	tok := func(repo, id, ref string, extra map[string]any) *client.Remote {
		return remote(e, iss.sign(t, ghaClaims(repo, id, ref, extra)))
	}
	main := tok("gfx-labs/app", "100", "refs/heads/main", nil)
	feature := tok("gfx-labs/app", "100", "refs/heads/feature", nil)
	pr := tok("gfx-labs/app", "100", "refs/pull/7/merge", map[string]any{
		"event_name": "pull_request", "base_ref": "release", "ref_type": "",
	})
	release := tok("gfx-labs/app", "100", "refs/heads/release", nil)
	otherRepo := tok("gfx-labs/other", "200", "refs/heads/main", nil)

	small, large := newBlob(t, 100), newBlob(t, 64<<10)
	aMain, aFeat, aRel := action("main"), action("feature"), action("release")

	for _, b := range []blob{small, large} {
		if err := put(t, main, aMain, b); err != nil {
			t.Fatal(err)
		}
		// Feature and PR runs read main through default_refs.
		for name, r := range map[string]*client.Remote{"feature": feature, "pr": pr, "main": main} {
			got, err := get(t, r, aMain)
			if err != nil || !bytes.Equal(got, b.data) {
				t.Fatalf("%s reading main entry: got %d bytes, err %v", name, len(got), err)
			}
		}
		// Other repositories never see it.
		if got, err := get(t, otherRepo, aMain); err != nil || got != nil {
			t.Fatalf("other repo read main entry: %v %v", got != nil, err)
		}
	}

	// A feature branch write is invisible to main and to other branches.
	if err := put(t, feature, aFeat, small); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]*client.Remote{"main": main, "release": release, "pr": pr} {
		if got, _ := get(t, r, aFeat); got != nil {
			t.Fatalf("%s read a feature branch entry", name)
		}
	}
	// A feature branch cannot overwrite main's entry for the same action.
	poison := newBlob(t, 100)
	if err := put(t, feature, aMain, poison); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, main, aMain); !bytes.Equal(got, large.data) {
		t.Fatal("main entry was replaced by a feature branch write")
	}
	// The feature branch sees its own entry first.
	if got, _ := get(t, feature, aMain); !bytes.Equal(got, poison.data) {
		t.Fatal("feature branch did not prefer its own scope")
	}

	// PRs read their base branch.
	if err := put(t, release, aRel, small); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, pr, aRel); !bytes.Equal(got, small.data) {
		t.Fatal("pr could not read base branch entry")
	}
	if got, _ := get(t, feature, aRel); got != nil {
		t.Fatal("feature read release entry without being based on it")
	}

	// Rejected tokens.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := map[string]string{
		"disallowed owner": iss.sign(t, ghaClaims("evil/app", "300", "refs/heads/main", nil)),
		"wrong audience":   iss.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"aud": "sts.amazonaws.com"})),
		"expired":          iss.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"exp": 1})),
		"wrong issuer":     iss.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"iss": "https://evil.example"})),
		"bad signature":    iss.signWith(t, otherKey, ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)),
		"unsigned":         unsigned(ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)),
		"wrong static key": "nope",
	}
	for name, tk := range bad {
		_, err := get(t, remote(e, tk), aMain)
		if c := statusCode(err); c != 401 && c != 403 {
			t.Errorf("%s: expected 401/403, got %v", name, err)
		}
	}

	// Static keys live in their own namespace.
	local := remote(e, testKey)
	if got, _ := get(t, local, aMain); got != nil {
		t.Fatal("static key read a gha namespace entry")
	}
}

func unsigned(claims map[string]any) string {
	// alg=none token
	return "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + b64json(claims) + "."
}

func TestRuntimeTokenScopes(t *testing.T) {
	e := newEnv(t)
	iss := e.RuntimeIssuer
	rt := func(ac string) *client.Remote {
		return remote(e, iss.sign(t, map[string]any{
			"aud":           "vstoken.actions.githubusercontent.com|vso:abc",
			"repository_id": "100",
			"repository":    "gfx-labs/app",
			"ac":            ac,
		}))
	}
	feat := rt(`[{"Scope":"refs/heads/feature","Permission":3},{"Scope":"refs/heads/main","Permission":1}]`)
	main := rt(`[{"Scope":"refs/heads/main","Permission":3}]`)
	oidcFeat := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/feature", nil)))

	b := newBlob(t, 10)
	if err := put(t, main, action("x"), b); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, feat, action("x")); !bytes.Equal(got, b.data) {
		t.Fatal("runtime token could not read granted scope")
	}
	// Runtime and OIDC tokens for the same repo share the namespace.
	if err := put(t, feat, action("y"), b); err != nil {
		t.Fatal(err)
	}
	if got, _ := get(t, oidcFeat, action("y")); !bytes.Equal(got, b.data) {
		t.Fatal("oidc token could not read runtime token write in same ref")
	}
	if got, _ := get(t, main, action("y")); got != nil {
		t.Fatal("main read feature write")
	}
	// A runtime-style token signed by the OIDC issuer's key is rejected
	// because it claims the runtime issuer.
	forged := e.Issuer.sign(t, map[string]any{"iss": iss.URL(), "repository_id": "100", "ac": `[{"Scope":"refs/heads/main","Permission":3}]`})
	if err := put(t, remote(e, forged), action("z"), b); statusCode(err) != 401 {
		t.Fatalf("runtime token signed with wrong issuer key: expected 401, got %v", err)
	}
}

func TestEventWritePolicy(t *testing.T) {
	e := newEnv(t)
	b := newBlob(t, 10)
	for _, ev := range []string{"pull_request_target", "workflow_run", "issue_comment"} {
		r := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"event_name": ev})))
		if err := put(t, r, action(ev), b); statusCode(err) != 403 {
			t.Fatalf("%s write: expected 403, got %v", ev, err)
		}
		if _, err := get(t, r, action(ev)); err != nil {
			t.Fatalf("%s read: %v", ev, err)
		}
	}
	for _, ev := range []string{"push", "pull_request", "merge_group"} {
		r := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"event_name": ev})))
		if err := put(t, r, action(ev), b); err != nil {
			t.Fatalf("%s write: %v", ev, err)
		}
	}
}

func TestLinkRequiresReadableScope(t *testing.T) {
	e := newEnv(t)
	tok := func(ref string) *client.Remote {
		return remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", ref, nil)))
	}
	featA, featB, main := tok("refs/heads/a"), tok("refs/heads/b"), tok("refs/heads/main")
	b := newBlob(t, 4096)
	if err := put(t, featA, action("x"), b); err != nil {
		t.Fatal(err)
	}
	// Branch b cannot read branch a, so it may not link to a's content.
	ok, err := featB.Link(context.Background(), action("y"), b.sha256, b.blake3, int64(len(b.data)))
	if err != nil || ok {
		t.Fatalf("link from unreadable scope: ok=%v err=%v", ok, err)
	}
	// Once main has it, every branch can link to it.
	if err := put(t, main, action("m"), b); err != nil {
		t.Fatal(err)
	}
	ok, err = featB.Link(context.Background(), action("y"), b.sha256, b.blake3, int64(len(b.data)))
	if err != nil || !ok {
		t.Fatalf("link from main scope: ok=%v err=%v", ok, err)
	}
}

func TestUploadVerification(t *testing.T) {
	e := newEnv(t)
	r := remote(e, testKey)
	b := newBlob(t, 4096)

	// Body that does not match the declared OutputID (sha256) is rejected.
	wrong := b
	wrong.sha256 = action("not the body")
	if err := put(t, r, action("a"), wrong); statusCode(err) != 400 {
		t.Fatalf("expected 400 for sha256 mismatch, got %v", err)
	}
	wrong = b
	wrong.blake3 = action("not the body")
	if err := put(t, r, action("a"), wrong); statusCode(err) != 400 {
		t.Fatalf("expected 400 for blake3 mismatch, got %v", err)
	}

	// Link only works for content already in this namespace.
	ok, err := r.Link(context.Background(), action("a"), b.sha256, b.blake3, int64(len(b.data)))
	if err != nil || ok {
		t.Fatalf("link of unknown blob: ok=%v err=%v", ok, err)
	}
	if err := put(t, r, action("a"), b); err != nil {
		t.Fatal(err)
	}
	ok, err = r.Link(context.Background(), action("b"), b.sha256, b.blake3, int64(len(b.data)))
	if err != nil || !ok {
		t.Fatalf("link of known blob: ok=%v err=%v", ok, err)
	}
	if got, _ := get(t, r, action("b")); !bytes.Equal(got, b.data) {
		t.Fatal("linked entry returned wrong body")
	}
	// Another namespace that knows the hash cannot link to it.
	gh := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)))
	ok, err = gh.Link(context.Background(), action("c"), b.sha256, b.blake3, int64(len(b.data)))
	if err != nil || ok {
		t.Fatalf("cross-namespace link: ok=%v err=%v", ok, err)
	}
	// But uploading the same content dedups to one blob.
	if err := put(t, gh, action("c"), b); err != nil {
		t.Fatal(err)
	}
	var blobs, entries int
	pool := e.Store.Pool()
	pool.QueryRow(context.Background(), "SELECT count(*) FROM blobs").Scan(&blobs)     //nolint:errcheck
	pool.QueryRow(context.Background(), "SELECT count(*) FROM entries").Scan(&entries) //nolint:errcheck
	if blobs != 1 || entries != 3 {
		t.Fatalf("expected 1 blob and 3 entries, got %d and %d", blobs, entries)
	}

	// Large blobs land in S3 at the sharded key, small ones inline.
	key := e.Blobs.Key(b.blake3)
	h := strings.TrimPrefix(key, e.Config.S3.Prefix)
	if parts := strings.Split(h, "/"); len(parts) != 3 || len(parts[2]) != 64 || parts[0] != parts[2][:2] || parts[1] != parts[2][2:4] {
		t.Fatalf("unexpected key layout %q", key)
	}
	rc, err := e.Blobs.Get(context.Background(), b.blake3)
	if err != nil {
		t.Fatalf("large blob not in s3: %v", err)
	}
	rc.Close()
	small := newBlob(t, 10)
	if err := put(t, r, action("small"), small); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Blobs.Get(context.Background(), small.blake3); !errors.Is(err, server.ErrBlobMissing) {
		t.Fatalf("small blob should be inline, s3 get returned %v", err)
	}

	// Empty bodies work.
	empty := newBlob(t, 0)
	if err := put(t, r, action("empty"), empty); err != nil {
		t.Fatal(err)
	}
	if got, err := get(t, r, action("empty")); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty body round trip: %v %v", got, err)
	}

	// Read-only keys cannot write.
	e2 := newEnv(t, func(c *server.Config) {
		c.Auth.Static = append(c.Auth.Static, server.StaticKey{Name: "ro", Key: "ro-key", Namespace: "local", ReadScopes: []string{"dev"}, ReadOnly: true})
	})
	if err := put(t, remote(e2, "ro-key"), action("ro"), small); statusCode(err) != 403 {
		t.Fatalf("read-only key write: expected 403, got %v", err)
	}
}

func TestRequestDeadline(t *testing.T) {
	e := newEnv(t, func(c *server.Config) { c.Storage.RequestTimeout = time.Second })
	r := remote(e, testKey)
	b := newBlob(t, 10)
	if err := put(t, r, action("a"), b); err != nil {
		t.Fatal(err)
	}
	// Hold the blob row lock so the dedup path of the next PUT blocks in postgres.
	ctx := context.Background()
	tx, err := e.Store.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SELECT 1 FROM blobs WHERE hash = $1 FOR UPDATE", b.blake3); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	p := filepath.Join(t.TempDir(), "body")
	os.WriteFile(p, b.data, 0o644) //nolint:errcheck
	err = r.Put(cctx, action("b"), b.sha256, b.blake3, int64(len(b.data)), p)
	if statusCode(err) != 500 {
		t.Fatalf("PUT blocked on a row lock: expected 500 from the request deadline, got %v", err)
	}
	tx.Rollback(ctx) //nolint:errcheck
	if err := put(t, r, action("b"), b); err != nil {
		t.Fatalf("PUT after lock release: %v", err)
	}
}

func TestAuthBackendErrorHidden(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	e := newEnv(t, func(c *server.Config) { c.Auth.GHA.Issuer = dead.URL })
	tok := e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", map[string]any{"iss": dead.URL}))
	_, err := remote(e, tok).Whoami(context.Background())
	var se *client.StatusError
	if !errors.As(err, &se) || se.Code != 503 {
		t.Fatalf("expected 503, got %v", err)
	}
	if host := strings.TrimPrefix(dead.URL, "http://"); strings.Contains(se.Msg, host) {
		t.Fatalf("response leaks issuer address: %q", se.Msg)
	}
}

func TestAllowAnyOwnerKeepsRepositoryAllowlist(t *testing.T) {
	e := newEnv(t, func(c *server.Config) {
		c.Auth.GHA.AllowedOwners = nil
		c.Auth.GHA.AllowAnyOwner = true
		c.Auth.GHA.AllowedRepositories = []string{"gfx-labs/app"}
	})
	ok := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)))
	if _, err := ok.Whoami(context.Background()); err != nil {
		t.Fatalf("allowed repository: %v", err)
	}
	evil := remote(e, e.Issuer.sign(t, ghaClaims("evil/app", "300", "refs/heads/main", nil)))
	if _, err := evil.Whoami(context.Background()); statusCode(err) != 403 {
		t.Fatalf("repository outside allowed_repositories: expected 403, got %v", err)
	}
}

func TestSpoolDiskErrorHidden(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	e := newEnv(t, func(c *server.Config) { c.Storage.TempDir = missing })
	err := put(t, remote(e, testKey), action("a"), newBlob(t, 4096))
	var se *client.StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("expected 500 for a server disk failure, got %v", err)
	}
	if strings.Contains(se.Msg, missing) {
		t.Fatalf("response leaks temp dir: %q", se.Msg)
	}
}

// heldPut starts a PUT and sends one byte of the body, leaving the upload
// slot held until finish is called.
type heldPut struct {
	w    *io.PipeWriter
	b    blob
	done chan int
}

func startPut(t *testing.T, e *env, tok string, act []byte, b blob) *heldPut {
	t.Helper()
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPut, e.URL+"/v1/actions/"+hex.EncodeToString(act), pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(b.data))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Cache-Output-Id", hex.EncodeToString(b.sha256))
	req.Header.Set("X-Cache-Blake3", hex.EncodeToString(b.blake3))
	req.Header.Set("X-Cache-Size", strconv.Itoa(len(b.data)))
	h := &heldPut{w: pw, b: b, done: make(chan int, 1)}
	go func() {
		resp, err := http0().Do(req)
		if err != nil {
			h.done <- 0
			return
		}
		resp.Body.Close()
		h.done <- resp.StatusCode
	}()
	if _, err := pw.Write(b.data[:1]); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *heldPut) finish(t *testing.T) int {
	t.Helper()
	if _, err := h.w.Write(h.b.data[1:]); err != nil {
		t.Fatal(err)
	}
	h.w.Close()
	return <-h.done
}

func TestUploadSlotsPerNamespace(t *testing.T) {
	e := newEnv(t, func(c *server.Config) {
		c.Storage.InlineMaxBytes = 0
		c.Storage.MaxConcurrentUploads = 4
		c.Storage.MaxConcurrentUploadsPerNamespace = 2
	})
	gh := remote(e, e.Issuer.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/main", nil)))
	var held []*heldPut
	for i := range 2 {
		held = append(held, startPut(t, e, testKey, action(fmt.Sprint("held", i)), newBlob(t, 64)))
	}
	// Both uploads hold a slot once their spool files exist.
	deadline := time.Now().Add(10 * time.Second)
	for {
		m, _ := filepath.Glob(filepath.Join(e.Config.Storage.TempDir, "upload-*"))
		if len(m) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("held uploads did not start, %d spool files", len(m))
		}
		time.Sleep(10 * time.Millisecond)
	}
	local := remote(e, testKey)
	if err := put(t, local, action("excess"), newBlob(t, 64)); statusCode(err) != 503 {
		t.Fatalf("upload over the namespace cap: expected 503, got %v", err)
	}
	if err := put(t, gh, action("other"), newBlob(t, 64)); err != nil {
		t.Fatalf("other namespace blocked by a full namespace: %v", err)
	}
	for _, h := range held {
		if code := h.finish(t); code != 204 {
			t.Fatalf("held upload: got %d", code)
		}
	}
	for i := range 2 {
		if err := put(t, local, action(fmt.Sprint("after", i)), newBlob(t, 64)); err != nil {
			t.Fatalf("slots not released: %v", err)
		}
	}
}
