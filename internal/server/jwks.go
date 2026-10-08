package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	jwksRefreshInterval = 30 * time.Second
	maxJWKSBytes        = 1 << 20
)

type cachedJWKS struct {
	body   []byte
	header http.Header
}

// jwksTransport bounds refreshes without changing go-oidc's signature checks.
type jwksTransport struct {
	mu        sync.Mutex
	base      http.RoundTripper
	url       string
	nextFetch time.Time
	cached    *cachedJWKS
}

func newJWKSClient() *http.Client {
	return &http.Client{
		Timeout:   discoveryTimeout,
		Transport: &jwksTransport{base: http.DefaultTransport},
	}
}

func (t *jwksTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if t.url == "" {
		t.url = req.URL.String()
	} else if req.URL.String() != t.url {
		return nil, fmt.Errorf("JWKS client cannot fetch a different URL")
	}
	if time.Now().Before(t.nextFetch) {
		return t.replay(req)
	}
	t.nextFetch = time.Now().Add(jwksRefreshInterval)
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("JWKS response exceeds size limit")
	}
	t.cached = &cachedJWKS{body: body, header: resp.Header.Clone()}
	return t.replay(req)
}

func (t *jwksTransport) replay(req *http.Request) (*http.Response, error) {
	if t.cached == nil {
		return nil, fmt.Errorf("JWKS refresh is temporarily unavailable")
	}
	h := t.cached.header.Clone()
	h.Del("Content-Encoding")
	h.Del("Transfer-Encoding")
	h.Del("Content-Length")
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(t.cached.body)),
		ContentLength: int64(len(t.cached.body)),
		Request:       req,
	}, nil
}
