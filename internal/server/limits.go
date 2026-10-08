package server

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
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

func positiveFinite(f float64) bool { return f > 0 && !math.IsInf(f, 0) && !math.IsNaN(f) }

// Validate checks enabled limits against the largest accepted blob.
func (c LimitsConfig) Validate(maxBlob int64) error {
	if !c.Enabled {
		return nil
	}
	if !positiveFinite(c.RequestsPerSec) || c.RequestBurst <= 0 {
		return fmt.Errorf("limits: requests_per_sec must be finite and > 0 and request_burst > 0")
	}
	if !positiveFinite(c.WritesPerSec) || c.WriteBurst <= 0 || c.WriteBytesPerSec <= 0 {
		return fmt.Errorf("limits: writes_per_sec must be finite and > 0, write_burst and write_bytes_per_sec > 0")
	}
	if min := max(maxBlob, minEntryQuotaBytes); c.WriteBytesBurst < min {
		return fmt.Errorf("limits: write_bytes_burst must be >= %d (max_blob_bytes and the minimum entry charge)", min)
	}
	if c.MaxTenants <= 0 {
		return fmt.Errorf("limits: max_tenants must be > 0")
	}
	return nil
}

// bucket is a token bucket. tokens is valid as of last.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = math.Min(burst, b.tokens+dt*rate)
	}
	b.last = now
}

// wait is how long until the bucket holds cost tokens. It is positive
// whenever the bucket is short, even for extreme rates.
func (b *bucket) wait(cost, rate float64) time.Duration {
	if b.tokens >= cost {
		return 0
	}
	secs := (cost - b.tokens) / rate
	if !(secs < float64(math.MaxInt64)/float64(time.Second)) {
		return time.Duration(math.MaxInt64)
	}
	return max(time.Duration(secs*float64(time.Second)), time.Nanosecond)
}

type tenant struct{ ops, bytes bucket }

// Limiter applies LimitsConfig. A nil *Limiter admits everything.
type Limiter struct {
	cfg       LimitsConfig
	now       func() time.Time
	mu        sync.Mutex
	req       bucket
	tenants   map[string]*tenant
	lastSweep time.Time
}

// NewLimiter returns nil when limits are disabled.
func NewLimiter(c LimitsConfig) *Limiter {
	if !c.Enabled {
		return nil
	}
	l := &Limiter{cfg: c, now: time.Now, tenants: map[string]*tenant{}}
	l.req = bucket{tokens: float64(c.RequestBurst), last: l.now()}
	return l
}

// AdmitRequest takes one token from the global request bucket.
func (l *Limiter) AdmitRequest() (time.Duration, bool) {
	if l == nil {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.req.refill(l.now(), l.cfg.RequestsPerSec, float64(l.cfg.RequestBurst))
	if w := l.req.wait(1, l.cfg.RequestsPerSec); w > 0 {
		return w, false
	}
	l.req.tokens--
	return 0, true
}

// AdmitWrite charges a write of size bytes to namespace. Tokens are not
// refunded when the write later fails, so invalid or retried uploads pay too.
func (l *Limiter) AdmitWrite(namespace string, size int64) (time.Duration, bool) {
	if l == nil {
		return 0, true
	}
	c := l.cfg
	opBurst, byteBurst := float64(c.WriteBurst), float64(c.WriteBytesBurst)
	byteRate := float64(c.WriteBytesPerSec)
	cost := float64(max(size, minEntryQuotaBytes))
	if cost > byteBurst {
		return time.Minute, false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.tenants[namespace]
	if t == nil {
		if len(l.tenants) >= c.MaxTenants {
			l.sweepLocked(now)
		}
		if len(l.tenants) >= c.MaxTenants {
			return time.Second, false
		}
		t = &tenant{ops: bucket{opBurst, now}, bytes: bucket{byteBurst, now}}
		l.tenants[namespace] = t
	}
	t.ops.refill(now, c.WritesPerSec, opBurst)
	t.bytes.refill(now, byteRate, byteBurst)
	if w := max(t.ops.wait(1, c.WritesPerSec), t.bytes.wait(cost, byteRate)); w > 0 {
		return w, false
	}
	t.ops.tokens--
	t.bytes.tokens -= cost
	return 0, true
}

// sweepLocked drops tenants whose buckets have fully refilled, which carry
// no state. It runs at most once per second.
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Second {
		return
	}
	l.lastSweep = now
	opBurst, byteBurst := float64(l.cfg.WriteBurst), float64(l.cfg.WriteBytesBurst)
	for ns, t := range l.tenants {
		t.ops.refill(now, l.cfg.WritesPerSec, opBurst)
		t.bytes.refill(now, float64(l.cfg.WriteBytesPerSec), byteBurst)
		if t.ops.tokens >= opBurst && t.bytes.tokens >= byteBurst {
			delete(l.tenants, ns)
		}
	}
}

// Middleware rejects requests over the global request rate with 429.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wait, ok := l.AdmitRequest(); !ok {
			writeLimited(w, wait, "request rate limit")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeLimited sends 429 with Retry-After rounded up to whole seconds.
func writeLimited(w http.ResponseWriter, wait time.Duration, msg string) {
	secs := max(int64(math.Ceil(wait.Seconds())), 1)
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeErr(w, http.StatusTooManyRequests, msg)
}
