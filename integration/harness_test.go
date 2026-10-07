package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	s3mock "github.com/grafana/s3-mock"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gfx-labs/arc-gocacheprog/internal/server"
)

// One embedded postgres per test binary. Each test gets its own database.
var (
	pgOnce sync.Once
	pgURL  string
	pgErr  error
	pgStop func()
)

func freePort(t testing.TB) uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func TestMain(m *testing.M) {
	code := m.Run()
	if pgStop != nil {
		pgStop()
	}
	os.Exit(code)
}

func startPostgres(t testing.TB) string {
	pgOnce.Do(func() {
		port := freePort(t)
		dir, err := os.MkdirTemp("", "arc-gocache-pg-*")
		if err != nil {
			pgErr = err
			return
		}
		cache := os.Getenv("EMBEDDED_POSTGRES_CACHE")
		if cache == "" {
			if base, err := os.UserCacheDir(); err == nil {
				cache = filepath.Join(base, "embedded-postgres-go")
			}
		}
		cfg := embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V17).
			Port(port).
			RuntimePath(filepath.Join(dir, "rt")).
			DataPath(filepath.Join(dir, "data")).
			CachePath(cache).
			Logger(io.Discard).
			StartTimeout(2 * time.Minute)
		pg := embeddedpostgres.NewDatabase(cfg)
		if pgErr = pg.Start(); pgErr != nil {
			return
		}
		pgStop = func() { pg.Stop(); os.RemoveAll(dir) }
		pgURL = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	})
	if pgErr != nil {
		t.Fatalf("start embedded postgres: %v", pgErr)
	}
	return pgURL
}

var dbSeq struct {
	sync.Mutex
	n int
}

// newDatabase creates a fresh database and returns its URL.
func newDatabase(t testing.TB) string {
	base := startPostgres(t)
	dbSeq.Lock()
	dbSeq.n++
	name := fmt.Sprintf("t%d_%d", os.Getpid(), dbSeq.n)
	dbSeq.Unlock()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s&dbname=%s", base, name)
}

// fakeIssuer is an OIDC issuer that signs tokens like GitHub Actions.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIssuer(t testing.TB) *fakeIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"issuer":                                f.srv.URL,
			"jwks_uri":                              f.srv.URL + "/.well-known/jwks",
			"subject_types_supported":               []string{"public"},
			"response_types_supported":              []string{"id_token"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{ //nolint:errcheck
			Key: &key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig",
		}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) URL() string { return f.srv.URL }

// sign signs claims. iss, iat, nbf and exp are filled in when missing.
func (f *fakeIssuer) sign(t testing.TB, claims map[string]any) string {
	return f.signWith(t, f.key, claims)
}

func (f *fakeIssuer) signWith(t testing.TB, key *rsa.PrivateKey, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.kid))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := map[string]any{
		"iss": f.srv.URL,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	for k, v := range claims {
		c[k] = v
	}
	tok, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ghaClaims builds OIDC claims for a workflow run.
func ghaClaims(repo, repoID, ref string, extra map[string]any) map[string]any {
	owner := repo[:indexByte(repo, '/')]
	c := map[string]any{
		"aud":                 "arc-gocacheprog",
		"sub":                 "repo:" + repo + ":ref:" + ref,
		"repository":          repo,
		"repository_id":       repoID,
		"repository_owner":    owner,
		"repository_owner_id": "1",
		"ref":                 ref,
		"ref_type":            "branch",
		"event_name":          "push",
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func indexByte(s string, b byte) int {
	for i := range len(s) {
		if s[i] == b {
			return i
		}
	}
	return len(s)
}

// env is a running server with its dependencies.
type env struct {
	URL    string
	Issuer *fakeIssuer
	// RuntimeIssuer signs ACTIONS_RUNTIME_TOKEN style tokens with its own keys.
	RuntimeIssuer *fakeIssuer
	Store  *server.Store
	Blobs  *server.BlobStore
	Config server.Config
	GC     *server.GC
}

const testKey = "local-test-key"

func newEnv(t testing.TB, mutate ...func(*server.Config)) *env {
	t.Helper()
	ctx := context.Background()
	iss := newFakeIssuer(t)
	rtIss := newFakeIssuer(t)

	cfg := server.DefaultConfig()
	cfg.DatabaseURL = newDatabase(t)
	cfg.S3.Bucket = "gocache"
	cfg.Storage.InlineMaxBytes = 1024
	cfg.Storage.TempDir = t.TempDir()
	cfg.GC.Enabled = false
	cfg.Auth.GHA = &server.GHAConfig{
		Issuer:             iss.URL(),
		AllowedOwners:      []string{"gfx-labs"},
		DefaultRefs:        []string{"main"},
		AcceptRuntimeToken:  true,
		RuntimeTokenIssuers: []string{rtIss.URL()},
	}
	cfg.Auth.Static = []server.StaticKey{{
		Name: "local", Key: testKey, Namespace: "local", WriteScope: "dev",
	}}
	for _, m := range mutate {
		m(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	store, err := server.OpenStore(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	s3c, closeS3, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeS3(context.Background()) }) //nolint:errcheck
	blobs := server.NewBlobStore(s3c, cfg.S3.Bucket, cfg.S3.Prefix)
	if err := blobs.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}

	auth, err := server.NewAuthenticator(cfg.Auth)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	srv := server.New(cfg, store, blobs, auth, log)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &env{
		URL: hs.URL, Issuer: iss, RuntimeIssuer: rtIss, Store: store, Blobs: blobs, Config: cfg,
		GC: server.NewGC(cfg.GC, store, blobs, log),
	}
}

func http0() *http.Client { return &http.Client{Timeout: time.Minute} }

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}
