package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestAuthenticatorBoundsJWKSRefresh(t *testing.T) {
	const issuer = "https://issuer.test"
	newKey := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	sign := func(key *rsa.PrivateKey, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		tok, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer: issuer, Subject: "repo:o/r:ref:refs/heads/main", Audience: jwt.Audience{"arc-gocacheprog"},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour)),
		}).Claims(map[string]any{
			"repository": "o/r", "repository_id": "1", "repository_owner": "o", "ref": "refs/heads/main", "event_name": "push",
		}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	serve := func(key *rsa.PrivateKey, kid string, status int) (*httptest.Server, *atomic.Int64) {
		var hits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{ //nolint:errcheck
				Key: key.Public(), KeyID: kid, Algorithm: string(jose.RS256), Use: "sig",
			}}})
		}))
		t.Cleanup(srv.Close)
		return srv, &hits
	}
	newAuth := func(jwksURL string) *Authenticator {
		a, err := NewAuthenticator(Auth{GHA: &GHAConfig{
			Issuer: issuer, JWKSURL: jwksURL, Audience: "arc-gocacheprog",
			AllowedOwners: []string{"o"}, WriteEvents: DefaultWriteEvents,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	ctx := context.Background()
	attacker := newKey()

	t.Run("unknown kids do not refetch", func(t *testing.T) {
		key := newKey()
		srv, hits := serve(key, "k1", http.StatusOK)
		a := newAuth(srv.URL)
		valid := sign(key, "k1")
		if _, err := a.Authenticate(ctx, valid); err != nil {
			t.Fatalf("valid token rejected: %v", err)
		}
		for i := range 20 {
			if _, err := a.Authenticate(ctx, sign(attacker, "unknown-"+string(rune('a'+i)))); err == nil {
				t.Fatal("token with unknown kid accepted")
			}
		}
		if n := hits.Load(); n > 1 {
			t.Fatalf("JWKS endpoint fetched %d times, want at most 1", n)
		}
		if _, err := a.Authenticate(ctx, valid); err != nil {
			t.Fatalf("valid token rejected after refresh storm: %v", err)
		}
	})

	t.Run("unavailable endpoint backs off", func(t *testing.T) {
		key := newKey()
		srv, hits := serve(key, "k1", http.StatusServiceUnavailable)
		a := newAuth(srv.URL)
		for range 20 {
			if _, err := a.Authenticate(ctx, sign(key, "k1")); err == nil {
				t.Fatal("token accepted without reachable JWKS")
			}
		}
		if n := hits.Load(); n != 1 {
			t.Fatalf("JWKS endpoint fetched %d times, want exactly 1", n)
		}
	})
}

func TestAuthenticatorBoundsDiscoveryResponse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		padding int
		ok      bool
	}{
		{"small document", 0, true},
		{"oversized document", 2 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/jwks" {
					json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{ //nolint:errcheck
						Key: key.Public(), KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig",
					}}})
					return
				}
				json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
					"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks",
					"padding": strings.Repeat("x", tc.padding),
				})
			}))
			t.Cleanup(srv.Close)
			a, err := NewAuthenticator(Auth{GHA: &GHAConfig{
				Issuer: srv.URL, Audience: "arc-gocacheprog", AllowedOwners: []string{"o"}, WriteEvents: DefaultWriteEvents,
			}})
			if err != nil {
				t.Fatal(err)
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
				(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			tok, err := jwt.Signed(signer).Claims(jwt.Claims{
				Issuer: srv.URL, Subject: "s", Audience: jwt.Audience{"arc-gocacheprog"},
				IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour)),
			}).Claims(map[string]any{
				"repository": "o/r", "repository_id": "1", "repository_owner": "o", "ref": "refs/heads/main", "event_name": "push",
			}).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Authenticate(context.Background(), tok)
			if tc.ok && err != nil {
				t.Fatalf("valid discovery rejected: %v", err)
			}
			var ae *authError
			if !tc.ok && (!errors.As(err, &ae) || ae.status != http.StatusServiceUnavailable) {
				t.Fatalf("oversized discovery document: expected 503, got %v", err)
			}
		})
	}
}
