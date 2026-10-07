// Package api defines the HTTP contract between the arc-gocacheprog client and server.
//
// Endpoints (all require "Authorization: Bearer <token>" except healthz):
//
//	GET  /v1/actions/{actionID}       hit: 200 + body + metadata headers. miss: 404.
//	PUT  /v1/actions/{actionID}       store body. Requires metadata headers and Content-Length. 204 on success.
//	POST /v1/actions/{actionID}/link  store entry for a blob the namespace already has, no body.
//	                                  204 if linked, 404 if the body must be uploaded with PUT.
//	GET  /v1/whoami                   JSON Identity for the presented token.
//	GET  /healthz                     200 when the server is up.
//
// actionID and output IDs are lowercase hex. Blob hashes are lowercase hex BLAKE3-256.
package api

import (
	"encoding/hex"
	"fmt"
)

const (
	HeaderOutputID = "X-Cache-Output-Id"
	HeaderBlake3   = "X-Cache-Blake3"
	HeaderSize     = "X-Cache-Size"
	// HeaderTime is the RFC3339Nano time the entry was stored.
	HeaderTime = "X-Cache-Time"
	// HeaderScope is the scope the entry was found in (informational).
	HeaderScope = "X-Cache-Scope"

	PathActions = "/v1/actions/"
	PathWhoami  = "/v1/whoami"
	PathHealthz = "/healthz"

	// MaxIDLen bounds action and output IDs in bytes.
	MaxIDLen = 64
	HashLen  = 32
)

// Identity is what the server derived from a token.
type Identity struct {
	Kind       string   `json:"kind"`
	Subject    string   `json:"subject"`
	Namespace  string   `json:"namespace"`
	WriteScope string   `json:"write_scope,omitempty"`
	ReadScopes []string `json:"read_scopes"`
}

// ErrorBody is returned as JSON on non-2xx responses.
type ErrorBody struct {
	Error string `json:"error"`
}

// DecodeID decodes a hex action or output ID.
func DecodeID(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex id: %w", err)
	}
	if len(b) == 0 || len(b) > MaxIDLen {
		return nil, fmt.Errorf("id length %d out of range", len(b))
	}
	return b, nil
}

// DecodeHash decodes a hex BLAKE3-256 hash.
func DecodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex hash: %w", err)
	}
	if len(b) != HashLen {
		return nil, fmt.Errorf("hash must be %d bytes, got %d", HashLen, len(b))
	}
	return b, nil
}
