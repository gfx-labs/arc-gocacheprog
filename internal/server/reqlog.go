package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/gfx-labs/arc-gocacheprog/internal/api"
)

// HeaderRequestID is set on every response so clients can report it.
const HeaderRequestID = "X-Request-Id"

// reqInfo is per-request logging state. Handlers fill it in as they learn
// the route, the identity and the reason for an error response.
type reqInfo struct {
	id       string
	route    string
	identity *Identity
	errMsg   string
	attrs    []any
}

type reqInfoKey struct{}

func infoFrom(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(reqInfoKey{}).(*reqInfo)
	return ri
}

func (ri *reqInfo) logAttrs(r *http.Request) []any {
	a := []any{"request_id", ri.id, "method", r.Method, "route", ri.route}
	if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
		a = append(a, "trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String())
	}
	if id := ri.identity; id != nil {
		a = append(a, "auth_kind", id.Kind, "namespace", id.Namespace, "write_scope", id.WriteScope)
	}
	return a
}

// reqLog returns s.log with the request's ID, route and identity.
func (s *Server) reqLog(r *http.Request) *slog.Logger {
	ri := infoFrom(r.Context())
	if ri == nil {
		return s.log
	}
	return s.log.With(ri.logAttrs(r)...)
}

// addLogAttrs attaches attributes to the request's access log line.
func addLogAttrs(r *http.Request, attrs ...any) {
	if ri := infoFrom(r.Context()); ri != nil {
		ri.attrs = append(ri.attrs, attrs...)
	}
}

// statusRecorder captures the status and size of a response.
type statusRecorder struct {
	http.ResponseWriter
	ri     *reqInfo
	status int
	bytes  int64
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newRequestID() string {
	var b [8]byte
	rand.Read(b[:]) //nolint:errcheck
	return hex.EncodeToString(b[:])
}

// logRequests assigns a request ID and writes one log line per request.
// Successes and cache misses log at Info when accessLog is set and at Debug
// otherwise, other 4xx at Warn and 5xx or panics at Error. Successful health
// checks are not logged.
func (s *Server) logRequests(next http.Handler) http.Handler {
	okLevel := slog.LevelDebug
	if s.cfg.AccessLog {
		okLevel = slog.LevelInfo
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ri := &reqInfo{id: newRequestID()}
		w.Header().Set(HeaderRequestID, ri.id)
		rec := &statusRecorder{ResponseWriter: w, ri: ri}
		r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, ri))
		defer func() {
			// Re-panic after logging so net/http still aborts the connection.
			p := recover()
			status := rec.status
			if status == 0 {
				status = http.StatusOK
				if p != nil {
					status = http.StatusInternalServerError
				}
			}
			level := okLevel
			switch {
			case status >= 500 || (p != nil && p != http.ErrAbortHandler):
				level = slog.LevelError
			case status >= 400 && status != http.StatusNotFound:
				level = slog.LevelWarn
			}
			if r.URL.Path != api.PathHealthz || level >= slog.LevelWarn {
				attrs := append(ri.logAttrs(r), "status", status,
					"duration_ms", time.Since(start).Milliseconds(),
					"bytes_in", max(r.ContentLength, 0), "bytes_out", rec.bytes)
				if ri.errMsg != "" {
					attrs = append(attrs, "error", ri.errMsg)
				}
				if p == http.ErrAbortHandler {
					attrs = append(attrs, "aborted", true)
				} else if p != nil {
					attrs = append(attrs, "panic", p)
				}
				attrs = append(attrs, ri.attrs...)
				s.log.Log(r.Context(), level, "request", attrs...)
			}
			if p != nil {
				panic(p)
			}
		}()
		next.ServeHTTP(rec, r)
	})
}
