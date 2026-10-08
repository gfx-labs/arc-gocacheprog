package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource supplies bearer tokens for the cache server.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed key.
type StaticToken string

func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

// GHAToken requests GitHub Actions OIDC ID tokens from the runner's token
// endpoint (ACTIONS_ID_TOKEN_REQUEST_URL), caching each until shortly before
// it expires. The workflow needs "permissions: id-token: write".
type GHAToken struct {
	RequestURL   string
	RequestToken string
	Audience     string
	HTTP         *http.Client

	mu  sync.Mutex
	tok string
	exp time.Time
}

// NewGHATokenFromEnv builds a GHAToken from the runner environment.
func NewGHATokenFromEnv(audience string) (*GHAToken, error) {
	u := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	t := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if u == "" || t == "" {
		return nil, fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN not set; the job needs `permissions: id-token: write`")
	}
	return &GHAToken{RequestURL: u, RequestToken: t, Audience: audience, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (g *GHAToken) Token(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.tok != "" && time.Until(g.exp) > time.Minute {
		return g.tok, nil
	}
	u, err := CheckCredentialURL(g.RequestURL, true)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	if g.Audience != "" {
		q := u.Query()
		q.Set("audience", g.Audience)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.RequestToken)
	req.Header.Set("Accept", "application/json")
	resp, err := credentialClient(g.HTTP).Do(req)
	if err != nil {
		return "", fmt.Errorf("request oidc token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request oidc token: status %d", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return "", fmt.Errorf("request oidc token: unexpected response")
	}
	g.tok = out.Value
	g.exp = jwtExpiry(out.Value)
	return g.tok, nil
}

// RuntimeToken uses ACTIONS_RUNTIME_TOKEN. It is only visible to actions,
// not run steps, so it usually has to be exported by a small action step.
type RuntimeToken struct{}

func (RuntimeToken) Token(context.Context) (string, error) {
	t := os.Getenv("ACTIONS_RUNTIME_TOKEN")
	if t == "" {
		return "", fmt.Errorf("ACTIONS_RUNTIME_TOKEN is not set")
	}
	return t, nil
}

// jwtExpiry returns the exp claim, or a short default when unparseable.
func jwtExpiry(tok string) time.Time {
	parts := strings.Split(tok, ".")
	if len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
			var c struct {
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(b, &c) == nil && c.Exp > 0 {
				return time.Unix(c.Exp, 0)
			}
		}
	}
	return time.Now().Add(4 * time.Minute)
}
