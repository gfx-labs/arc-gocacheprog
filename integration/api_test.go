package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	iss := e.Issuer
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
	oidcFeat := remote(e, iss.sign(t, ghaClaims("gfx-labs/app", "100", "refs/heads/feature", nil)))

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
