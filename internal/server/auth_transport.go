package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func validateAuthURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("authentication endpoint must be an absolute URL without userinfo or a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("authentication endpoint must use HTTPS, except loopback HTTP for development")
}

func validateGHAURLs(g GHAConfig) error {
	if g.JWKSURL == "" {
		if err := validateAuthURL(g.Issuer); err != nil {
			return fmt.Errorf("auth.gha.issuer: %w", err)
		}
	}
	for _, endpoint := range []struct{ name, value string }{
		{"jwks_url", g.JWKSURL},
		{"runtime_token_jwks_url", g.RuntimeTokenJWKSURL},
	} {
		if endpoint.value != "" {
			if err := validateAuthURL(endpoint.value); err != nil {
				return fmt.Errorf("auth.gha.%s: %w", endpoint.name, err)
			}
		}
	}
	if g.AcceptRuntimeToken {
		for _, issuer := range g.RuntimeTokenIssuers {
			if issuer != g.Issuer && g.RuntimeTokenJWKSURL == "" {
				if err := validateAuthURL(issuer); err != nil {
					return fmt.Errorf("auth.gha.runtime_token_issuers: %w", err)
				}
			}
		}
	}
	return nil
}

func authRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many authentication redirects")
	}
	return validateAuthURL(req.URL.String())
}

// maxDiscoveryBytes bounds OIDC discovery responses, which go-oidc reads whole.
const maxDiscoveryBytes = 1 << 20

var errResponseTooLarge = errors.New("authentication endpoint response exceeds size limit")

// limitBodyTransport fails reads once a response body passes max bytes.
type limitBodyTransport struct {
	base http.RoundTripper
	max  int64
}

func (t limitBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body, left: t.max}
	return resp, nil
}

type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.rc.Read(p)
	if c.left -= int64(n); c.left < 0 {
		return 0, errResponseTooLarge
	}
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }
