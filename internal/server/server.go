package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/zeebo/blake3"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

// Server is the HTTP cache server.
type Server struct {
	cfg     Config
	store   *Store
	blobs   *BlobStore
	auth    *Authenticator
	log     *slog.Logger
	uploads *uploadLimiter
}

func New(cfg Config, store *Store, blobs *BlobStore, auth *Authenticator, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, store: store, blobs: blobs, auth: auth, log: log,
		uploads: newUploadLimiter(cfg.Storage.MaxConcurrentUploads, cfg.Storage.MaxConcurrentUploadsPerNamespace)}
}

// uploadLimiter bounds concurrent PUTs (spooled bodies and S3 writes) in
// total and per namespace, so one tenant cannot hold every slot.
type uploadLimiter struct {
	mu           sync.Mutex
	max, perNS   int
	total        int
	perNamespace map[string]int
}

func newUploadLimiter(max, perNS int) *uploadLimiter {
	if max <= 0 {
		max = 32
	}
	if perNS <= 0 {
		perNS = 8
	}
	return &uploadLimiter{max: max, perNS: perNS, perNamespace: map[string]int{}}
}

// acquire reserves a slot without waiting. release must be called once.
func (l *uploadLimiter) acquire(ns string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max || l.perNamespace[ns] >= l.perNS {
		return nil, false
	}
	l.total++
	l.perNamespace[ns]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.total--
		if l.perNamespace[ns]--; l.perNamespace[ns] <= 0 {
			delete(l.perNamespace, ns)
		}
	}, true
}

// cleanupTimeout bounds bookkeeping that runs after the request context ended.
const cleanupTimeout = 5 * time.Second

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.PathHealthz, func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.pool.Ping(r.Context()); err != nil {
			http.Error(w, "db unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET "+api.PathWhoami, s.authed(s.handleWhoami))
	mux.HandleFunc("GET "+api.PathActions+"{id}", s.authed(s.handleGet))
	mux.HandleFunc("PUT "+api.PathActions+"{id}", s.authed(s.handlePut))
	mux.HandleFunc("POST "+api.PathActions+"{id}/link", s.authed(s.handleLink))
	// http.Server timeouts do not cancel the request context, so database,
	// S3 and JWKS calls get their own deadline.
	timeout := s.cfg.Storage.RequestTimeout
	if timeout <= 0 {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

type authedHandler func(w http.ResponseWriter, r *http.Request, id *Identity)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := bearer(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		id, err := s.auth.Authenticate(r.Context(), tok)
		if err != nil {
			var ae *authError
			if errors.As(err, &ae) {
				if ae.status >= 500 {
					s.log.Error("auth backend error", "err", ae.cause)
				}
				writeErr(w, ae.status, ae.msg)
				return
			}
			s.log.Error("auth error", "err", err)
			writeErr(w, http.StatusInternalServerError, "auth error")
			return
		}
		h(w, r, id)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(api.ErrorBody{Error: msg}) //nolint:errcheck
}

func (s *Server) handleWhoami(w http.ResponseWriter, r *http.Request, id *Identity) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.Identity{ //nolint:errcheck
		Kind: id.Kind, Subject: id.Subject, Namespace: id.Namespace,
		WriteScope: id.WriteScope, ReadScopes: id.ReadScopes,
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, id *Identity) {
	actionID, err := api.DecodeID(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(id.ReadScopes) == 0 {
		writeErr(w, http.StatusForbidden, "token has no read scopes")
		return
	}
	ctx := r.Context()
	e, err := s.store.Lookup(ctx, id.Namespace, id.ReadScopes, actionID)
	if err != nil {
		s.log.Error("lookup", "err", err)
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if e == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var body io.ReadCloser
	if e.IsInline {
		body = io.NopCloser(bytes.NewReader(e.Inline))
	} else {
		body, err = s.blobs.Get(ctx, e.BlobHash)
		if errors.Is(err, ErrBlobMissing) {
			s.log.Warn("blob missing from object store", "hash", hex.EncodeToString(e.BlobHash))
			dropped, derr := s.store.DropMissingBlob(ctx, e.BlobHash, s.blobs.Exists)
			if derr != nil {
				s.log.Error("drop blob", "err", derr)
			} else if dropped {
				s.log.Warn("dropped blob and its entries", "hash", hex.EncodeToString(e.BlobHash))
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err != nil {
			s.log.Error("blob get", "err", err)
			writeErr(w, http.StatusBadGateway, "object store error")
			return
		}
	}
	defer body.Close()

	if err := s.store.Touch(ctx, id.Namespace, e.Scope, actionID, e.BlobHash, s.cfg.Storage.TouchInterval); err != nil {
		s.log.Warn("touch", "err", err)
	}

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(e.Size, 10))
	h.Set(api.HeaderOutputID, hex.EncodeToString(e.OutputID))
	h.Set(api.HeaderBlake3, hex.EncodeToString(e.BlobHash))
	h.Set(api.HeaderSize, strconv.FormatInt(e.Size, 10))
	h.Set(api.HeaderTime, e.CreatedAt.UTC().Format(time.RFC3339Nano))
	h.Set(api.HeaderScope, e.Scope)
	w.WriteHeader(http.StatusOK)
	n, err := io.Copy(w, io.LimitReader(body, e.Size+1))
	if err != nil || n != e.Size {
		// Headers are sent. Abort the connection so the client sees a broken
		// response instead of a short body.
		s.log.Warn("short or failed body", "hash", hex.EncodeToString(e.BlobHash), "sent", n, "size", e.Size, "err", err)
		panic(http.ErrAbortHandler)
	}
}

// putMeta is parsed from request headers.
type putMeta struct {
	actionID []byte
	outputID []byte
	blake3   []byte
	size     int64
}

func (s *Server) parsePutMeta(r *http.Request, needHash bool) (*putMeta, error) {
	var m putMeta
	var err error
	if m.actionID, err = api.DecodeID(r.PathValue("id")); err != nil {
		return nil, err
	}
	if m.outputID, err = api.DecodeID(r.Header.Get(api.HeaderOutputID)); err != nil {
		return nil, fmt.Errorf("%s: %w", api.HeaderOutputID, err)
	}
	if hv := r.Header.Get(api.HeaderBlake3); hv != "" || needHash {
		if m.blake3, err = api.DecodeHash(hv); err != nil {
			return nil, fmt.Errorf("%s: %w", api.HeaderBlake3, err)
		}
	}
	if m.size, err = strconv.ParseInt(r.Header.Get(api.HeaderSize), 10, 64); err != nil || m.size < 0 {
		return nil, fmt.Errorf("%s: invalid size", api.HeaderSize)
	}
	if m.size > s.cfg.Storage.MaxBlobBytes {
		return nil, fmt.Errorf("size %d exceeds limit %d", m.size, s.cfg.Storage.MaxBlobBytes)
	}
	return &m, nil
}

// handleLink records an entry for content the namespace already has, so
// clients can skip uploading bodies the server has.
func (s *Server) handleLink(w http.ResponseWriter, r *http.Request, id *Identity) {
	if id.WriteScope == "" {
		writeErr(w, http.StatusForbidden, "token has no write scope")
		return
	}
	m, err := s.parsePutMeta(r, true)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	b, err := s.store.LinkableBlob(ctx, id.Namespace, id.ReadScopes, m.blake3)
	if err != nil {
		s.log.Error("link lookup", "err", err)
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if b == nil || b.Size != m.size || !bytes.Equal(b.SHA256, m.outputID) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	err = s.store.LinkExisting(ctx, id.Namespace, id.WriteScope, m.actionID, m.outputID, *b)
	if errors.Is(err, errBlobGone) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.Error("link", "err", err)
		writeErr(w, http.StatusInternalServerError, "link failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request, id *Identity) {
	if id.WriteScope == "" {
		writeErr(w, http.StatusForbidden, "token has no write scope")
		return
	}
	m, err := s.parsePutMeta(r, false)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.ContentLength != m.size {
		writeErr(w, http.StatusBadRequest, "Content-Length must equal "+api.HeaderSize)
		return
	}
	release, ok := s.uploads.acquire(id.Namespace)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "too many concurrent uploads")
		return
	}
	defer release()
	ctx := r.Context()
	body := http.MaxBytesReader(w, r.Body, m.size)

	sp, err := s.spool(body, m.size)
	var de *diskError
	if errors.As(err, &de) {
		s.log.Error("spool upload", "err", err)
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	defer sp.cleanup()

	// cmd/go defines OutputID as the sha256 of the body. Enforcing it means a
	// token can only map actions to content it actually sent.
	if !bytes.Equal(sp.sha256, m.outputID) {
		writeErr(w, http.StatusBadRequest, "body sha256 does not match output id")
		return
	}
	if m.blake3 != nil && !bytes.Equal(sp.blake3, m.blake3) {
		writeErr(w, http.StatusBadRequest, "body blake3 does not match header")
		return
	}
	info := BlobInfo{Hash: sp.blake3, SHA256: sp.sha256, Size: sp.size}

	if err := s.storeBlob(ctx, id, m, info, sp); err != nil {
		s.log.Error("store", "err", err)
		writeErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) storeBlob(ctx context.Context, id *Identity, m *putMeta, info BlobInfo, sp *spooled) error {
	// Dedup: if the blob row exists, LinkExisting locks it while linking, which
	// keeps GC from deleting the object underneath us.
	err := s.store.LinkExisting(ctx, id.Namespace, id.WriteScope, m.actionID, m.outputID, info)
	if !errors.Is(err, errBlobGone) {
		return err
	}
	if sp.mem != nil {
		return s.store.InsertBlob(ctx, id.Namespace, id.WriteScope, m.actionID, m.outputID, info, sp.mem, 0)
	}
	// The lease keeps GC from deleting the object between the S3 write and
	// the row insert, without holding a transaction open during the upload.
	lease, err := s.store.StartUpload(ctx, info.Hash)
	if err != nil {
		return err
	}
	if err := s.blobs.Put(ctx, info.Hash, sp.file, info.Size); err != nil {
		s.endUpload(ctx, lease)
		return err
	}
	if err := s.store.InsertBlob(ctx, id.Namespace, id.WriteScope, m.actionID, m.outputID, info, nil, lease); err != nil {
		s.endUpload(ctx, lease)
		return err
	}
	return nil
}

// endUpload drops a lease after a failed upload. It runs even when ctx is
// done, but bounded so it cannot hold the upload slot indefinitely. A lease
// that is not removed expires after gc.upload_lease.
func (s *Server) endUpload(ctx context.Context, lease int64) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := s.store.EndUpload(cctx, lease); err != nil {
		s.log.Warn("end upload", "err", err)
	}
}

// diskError marks a local filesystem failure while spooling, as opposed to a
// bad request body.
type diskError struct{ err error }

func (e *diskError) Error() string { return e.err.Error() }
func (e *diskError) Unwrap() error { return e.err }

// diskWriter tags write errors as diskError.
type diskWriter struct{ f *os.File }

func (d diskWriter) Write(p []byte) (int, error) {
	n, err := d.f.Write(p)
	if err != nil {
		err = &diskError{err}
	}
	return n, err
}

// spooled is a fully received and hashed request body.
type spooled struct {
	size   int64
	sha256 []byte
	blake3 []byte
	mem    []byte
	file   *os.File
}

func (sp *spooled) cleanup() {
	if sp.file != nil {
		name := sp.file.Name()
		sp.file.Close()
		os.Remove(name)
	}
}

// spool reads the body, hashing it. Bodies at or below the inline threshold
// stay in memory, others go to a temp file for the S3 upload.
func (s *Server) spool(r io.Reader, size int64) (*spooled, error) {
	sh := sha256.New()
	bh := blake3.New()
	hashes := io.MultiWriter(sh, bh)
	sp := &spooled{}
	if size <= s.cfg.Storage.InlineMaxBytes {
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if err := expectEOF(r); err != nil {
			return nil, err
		}
		hashes.Write(buf)
		sp.mem = buf
	} else {
		f, err := os.CreateTemp(s.cfg.Storage.TempDir, "upload-*")
		if err != nil {
			return nil, &diskError{err}
		}
		sp.file = f
		n, err := io.Copy(io.MultiWriter(diskWriter{f}, hashes), r)
		if err != nil {
			sp.cleanup()
			return nil, err
		}
		if n != size {
			sp.cleanup()
			return nil, fmt.Errorf("short body: got %d of %d bytes", n, size)
		}
	}
	sp.size = size
	sp.sha256 = sum(sh)
	sp.blake3 = sum(bh)
	return sp, nil
}

func sum(h hash.Hash) []byte { return h.Sum(nil) }

func expectEOF(r io.Reader) error {
	var one [1]byte
	n, err := r.Read(one[:])
	if n > 0 {
		return errors.New("body longer than declared size")
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
