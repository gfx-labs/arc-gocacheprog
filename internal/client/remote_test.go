package client

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

// Credentials must not follow a redirect to another origin, whether it is the
// cache server token or the runner's OIDC request token.
func TestCredentialsNotSentAcrossRedirect(t *testing.T) {
	var leaked atomic.Value
	leaked.Store("")
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"value":"x"}`)) //nolint:errcheck
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	caller := &http.Client{}
	cases := map[string]func() error{
		"remote": func() error {
			r := &Remote{BaseURL: origin.URL, HTTP: caller, Tokens: StaticToken("cache-secret")}
			_, err := r.Get(context.Background(), []byte{1}, &bytes.Buffer{})
			return err
		},
		"gha": func() error {
			g := &GHAToken{RequestURL: origin.URL + "/token?api-version=2.0", RequestToken: "runner-secret", HTTP: caller}
			_, err := g.Token(context.Background())
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			leaked.Store("")
			if err := call(); err == nil {
				t.Fatal("expected redirect to be refused")
			}
			if got := leaked.Load().(string); got != "" {
				t.Fatalf("redirect target received Authorization %q", got)
			}
		})
	}
	if caller.CheckRedirect != nil {
		t.Fatal("caller's http.Client was modified")
	}
}

func TestRemoteRejectsPlaintextNonLoopbackURL(t *testing.T) {
	var fetched atomic.Int32
	r := &Remote{BaseURL: "http://cache.example.com", HTTP: &http.Client{}, Tokens: tokenFunc(func() { fetched.Add(1) })}
	_, err := r.Get(context.Background(), []byte{1}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https error, got %v", err)
	}
	if fetched.Load() != 0 {
		t.Fatal("token was fetched for a plaintext URL")
	}
}

// A server that streams more than its declared size must not fill the disk.
func TestRemoteGetBoundsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(api.HeaderOutputID, strings.Repeat("ab", 32))
		w.Header().Set(api.HeaderSize, "1")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		for range 160 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	var buf bytes.Buffer
	r := &Remote{BaseURL: srv.URL, HTTP: &http.Client{}, Tokens: StaticToken("k")}
	if _, err := r.Get(context.Background(), []byte{1}, &buf); err == nil {
		t.Fatal("expected size mismatch error")
	}
	if buf.Len() > 2 {
		t.Fatalf("wrote %d bytes for a declared size of 1", buf.Len())
	}
}

type tokenFunc func()

func (f tokenFunc) Token(context.Context) (string, error) { f(); return "k", nil }
