package server

import (
	"fmt"
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
