package server

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LimitsConfig configures in-memory admission control. State is per replica:
// N replicas admit up to N times these rates and bursts, and a restart grants
// a fresh burst. Admission bounds how fast a tenant can add entries and bytes;
// it does not bound storage already accumulated, which GC quota and TTL do.
type LimitsConfig struct {
	// Enabled turns admission control on. The zero value is disabled;
	// DefaultLimits enables it, so an explicit false in YAML opts out.
	Enabled bool `yaml:"enabled"`
	// RequestsPerSec and RequestBurst bound all requests, before auth, across
	// all clients.
	RequestsPerSec float64 `yaml:"requests_per_sec"`
	RequestBurst   int     `yaml:"request_burst"`
	// Per-namespace write limits, applied to PUT and link before the body is
	// read. Each write costs one op and max(size, minEntryQuotaBytes) bytes.
	WritesPerSec     float64 `yaml:"writes_per_sec"`
	WriteBurst       int     `yaml:"write_burst"`
	WriteBytesPerSec int64   `yaml:"write_bytes_per_sec"`
	WriteBytesBurst  int64   `yaml:"write_bytes_burst"`
	// MaxTenants bounds tracked namespaces. When full, writes from untracked
	// namespaces are rejected until tracked ones fully refill and are
	// dropped. Partially depleted tenants are never evicted.
	MaxTenants int `yaml:"max_tenants"`
}

func DefaultLimits() LimitsConfig {
	return LimitsConfig{
		Enabled:          true,
		RequestsPerSec:   1000,
		RequestBurst:     4096,
		WritesPerSec:     50,
		WriteBurst:       20000,
		WriteBytesPerSec: 4 << 20,
		WriteBytesBurst:  4 << 30,
		MaxTenants:       10000,
	}
}

// maxByteTokens keeps byte counts exact in rate's float64 token math and
// within int on every platform.
const maxByteTokens = min(1<<53, math.MaxInt)

// validRate reports whether f is a usable finite rate. rate.Inf is
// math.MaxFloat64 and disables limiting, so it is rejected too.
func validRate(f float64) bool { return f > 0 && f < float64(rate.Inf) && !math.IsNaN(f) }

// Validate checks enabled limits against the largest accepted blob.
func (c LimitsConfig) Validate(maxBlob int64) error {
	if !c.Enabled {
		return nil
	}
	if !validRate(c.RequestsPerSec) || c.RequestBurst <= 0 {
		return fmt.Errorf("limits: requests_per_sec must be finite and > 0 and request_burst > 0")
	}
	if !validRate(c.WritesPerSec) || c.WriteBurst <= 0 || c.WriteBytesPerSec <= 0 {
		return fmt.Errorf("limits: writes_per_sec must be finite and > 0, write_burst and write_bytes_per_sec > 0")
	}
	if min := max(maxBlob, minEntryQuotaBytes); c.WriteBytesBurst < min {
		return fmt.Errorf("limits: write_bytes_burst must be >= %d (max_blob_bytes and the minimum entry charge)", min)
	}
	if c.WriteBytesBurst > maxByteTokens {
		return fmt.Errorf("limits: write_bytes_burst must be <= %d", int64(maxByteTokens))
	}
	if c.MaxTenants <= 0 {
		return fmt.Errorf("limits: max_tenants must be > 0")
	}
	return nil
}

type tenant struct{ ops, bytes *rate.Limiter }

// Limiter applies LimitsConfig. A nil *Limiter admits everything.
type Limiter struct {
	cfg LimitsConfig
	now func() time.Time
	// mu serializes reserve and cancel so a rejected admission refunds its
	// tokens before any other admission sees the buckets.
	mu        sync.Mutex
	req       *rate.Limiter
	tenants   map[string]*tenant
	lastSweep time.Time
}

// NewLimiter returns nil when limits are disabled.
func NewLimiter(c LimitsConfig) *Limiter {
	if !c.Enabled {
		return nil
	}
	return &Limiter{
		cfg:     c,
		now:     time.Now,
		req:     rate.NewLimiter(rate.Limit(c.RequestsPerSec), c.RequestBurst),
		tenants: map[string]*tenant{},
	}
}

// reserve takes n tokens from each limiter only if all have them now. It
// returns the longest delay otherwise. The caller holds l.mu.
func reserve(now time.Time, lims []*rate.Limiter, ns []int) (time.Duration, bool) {
	rs := make([]*rate.Reservation, len(lims))
	var wait time.Duration
	for i, lim := range lims {
		rs[i] = lim.ReserveN(now, ns[i])
		wait = max(wait, rs[i].DelayFrom(now))
	}
	if wait == 0 {
		return 0, true
	}
	for _, r := range rs {
		r.CancelAt(now)
	}
	return wait, false
}

// AdmitRequest takes one token from the global request bucket.
func (l *Limiter) AdmitRequest() (time.Duration, bool) {
	if l == nil {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return reserve(l.now(), []*rate.Limiter{l.req}, []int{1})
}

// AdmitWrite charges a write of size bytes to namespace. Tokens are not
// refunded when the write later fails, so invalid or retried uploads pay too.
func (l *Limiter) AdmitWrite(namespace string, size int64) (time.Duration, bool) {
	if l == nil {
		return 0, true
	}
	cost := max(size, minEntryQuotaBytes)
	if cost > l.cfg.WriteBytesBurst {
		return rate.InfDuration, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	t := l.tenants[namespace]
	if t == nil {
		if len(l.tenants) >= l.cfg.MaxTenants {
			l.sweepLocked(now)
		}
		if len(l.tenants) >= l.cfg.MaxTenants {
			return time.Second, false
		}
		t = &tenant{
			ops:   rate.NewLimiter(rate.Limit(l.cfg.WritesPerSec), l.cfg.WriteBurst),
			bytes: rate.NewLimiter(rate.Limit(l.cfg.WriteBytesPerSec), int(l.cfg.WriteBytesBurst)),
		}
		l.tenants[namespace] = t
	}
	return reserve(now, []*rate.Limiter{t.ops, t.bytes}, []int{1, int(cost)})
}

// sweepLocked drops tenants whose buckets have fully refilled, which carry
// no state. It runs at most once per second.
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Second {
		return
	}
	l.lastSweep = now
	for ns, t := range l.tenants {
		if t.ops.TokensAt(now) >= float64(t.ops.Burst()) && t.bytes.TokensAt(now) >= float64(t.bytes.Burst()) {
			delete(l.tenants, ns)
		}
	}
}

// limitRequests rejects requests over the global request rate with 429.
func (s *Server) limitRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wait, ok := s.limits.AdmitRequest(); !ok {
			s.metrics.reject(r.Context(), rejectRateLimit)
			s.limited(w, r, wait, "request rate limit")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeLimited sends 429 with Retry-After in whole seconds, at least 1.
func writeLimited(w http.ResponseWriter, wait time.Duration, msg string) {
	secs := max(int64(math.Ceil(wait.Seconds())), 1)
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeErr(w, http.StatusTooManyRequests, msg)
}

// limited is writeLimited that also records msg for the access log.
func (s *Server) limited(w http.ResponseWriter, r *http.Request, wait time.Duration, msg string) {
	if ri := infoFrom(r.Context()); ri != nil {
		ri.errMsg = msg
	}
	writeLimited(w, wait, msg)
}
