package client

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// CheckCredentialURL validates a URL that bearer credentials are sent to.
// It requires https, except plain http to a loopback host for local use, and
// rejects userinfo and fragments. Queries are rejected unless allowQuery is set.
func CheckCredentialURL(raw string, allowQuery bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, fmt.Errorf("url %q must be absolute with a host", u.Redacted())
	}
	if u.User != nil {
		return nil, fmt.Errorf("url %q must not contain userinfo", u.Redacted())
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, fmt.Errorf("url %q must not contain a fragment", u.Redacted())
	}
	if !allowQuery && (u.RawQuery != "" || u.ForceQuery) {
		return nil, fmt.Errorf("url %q must not contain a query", u.Redacted())
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("url %q: plain http is only allowed to loopback hosts, use https", u.Redacted())
		}
	default:
		return nil, fmt.Errorf("url %q: scheme must be https", u.Redacted())
	}
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// credentialClient returns a shallow copy of c that refuses redirects leaving
// the scheme, host and port of the first request, so the Authorization header
// is never replayed to another origin. c is not modified.
func credentialClient(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	cc := *c
	prev := c.CheckRedirect
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || !strings.EqualFold(req.URL.Host, first.Host) {
			return errors.New("refusing cross-origin redirect for authenticated request")
		}
		if prev != nil {
			return prev(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &cc
}
