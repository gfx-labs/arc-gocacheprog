package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

// Remote talks to the cache server.
type Remote struct {
	BaseURL string
	HTTP    *http.Client
	Tokens  TokenSource
}

// RemoteEntry is the metadata of a remote hit.
type RemoteEntry struct {
	OutputID []byte
	Size     int64
	Time     time.Time
	Scope    string
}

// StatusError is a non-success HTTP response.
type StatusError struct {
	Code int
	Msg  string
}

func (e *StatusError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Code, e.Msg) }

func (r *Remote) do(ctx context.Context, method, path string, body io.Reader, hdr http.Header, size int64) (*http.Response, error) {
	tok, err := r.Tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(r.BaseURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.ContentLength = size
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", "arc-gocacheprog")
	return r.HTTP.Do(req)
}

func readErr(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var eb api.ErrorBody
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &eb) == nil && eb.Error != "" {
		msg = eb.Error
	}
	return &StatusError{Code: resp.StatusCode, Msg: msg}
}

// Get fetches actionID. On a hit it writes the body to w and returns the
// entry. On a miss it returns nil, nil.
func (r *Remote) Get(ctx context.Context, actionID []byte, w io.Writer) (*RemoteEntry, error) {
	resp, err := r.do(ctx, http.MethodGet, api.PathActions+hex.EncodeToString(actionID), nil, nil, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, readErr(resp)
	}
	var e RemoteEntry
	if e.OutputID, err = api.DecodeID(resp.Header.Get(api.HeaderOutputID)); err != nil {
		return nil, err
	}
	if e.Size, err = strconv.ParseInt(resp.Header.Get(api.HeaderSize), 10, 64); err != nil {
		return nil, fmt.Errorf("bad size header: %w", err)
	}
	if t, err := time.Parse(time.RFC3339Nano, resp.Header.Get(api.HeaderTime)); err == nil {
		e.Time = t
	}
	e.Scope = resp.Header.Get(api.HeaderScope)
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return nil, err
	}
	if n != e.Size {
		return nil, fmt.Errorf("short body: %d of %d bytes", n, e.Size)
	}
	return &e, nil
}

func putHeaders(outputID, blake3 []byte, size int64) http.Header {
	h := http.Header{}
	h.Set(api.HeaderOutputID, hex.EncodeToString(outputID))
	h.Set(api.HeaderBlake3, hex.EncodeToString(blake3))
	h.Set(api.HeaderSize, strconv.FormatInt(size, 10))
	return h
}

// Link asks the server to reuse a blob it already has. ok is false when the
// body must be uploaded.
func (r *Remote) Link(ctx context.Context, actionID, outputID, blake3 []byte, size int64) (bool, error) {
	resp, err := r.do(ctx, http.MethodPost, api.PathActions+hex.EncodeToString(actionID)+"/link",
		nil, putHeaders(outputID, blake3, size), 0)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, readErr(resp)
	}
}

// Put uploads the file at path.
func (r *Remote) Put(ctx context.Context, actionID, outputID, blake3 []byte, size int64, path string) error {
	var body io.Reader = http.NoBody
	if size > 0 {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		body = f
	}
	h := putHeaders(outputID, blake3, size)
	h.Set("Content-Type", "application/octet-stream")
	resp, err := r.do(ctx, http.MethodPut, api.PathActions+hex.EncodeToString(actionID), body, h, size)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return readErr(resp)
	}
	return nil
}

// Whoami returns the identity the server derived from the token.
func (r *Remote) Whoami(ctx context.Context) (*api.Identity, error) {
	resp, err := r.do(ctx, http.MethodGet, api.PathWhoami, nil, nil, 0)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readErr(resp)
	}
	var id api.Identity
	if err := json.NewDecoder(resp.Body).Decode(&id); err != nil {
		return nil, err
	}
	return &id, nil
}

// IsAuthError reports whether err is a 401 or 403 from the server.
func IsAuthError(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden)
}
