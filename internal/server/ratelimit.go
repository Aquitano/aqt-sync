package server

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Rate-limit defaults for the unauthenticated routes (account creation, salt
// lookup, challenge, device attach). These bound brute-force and account-
// enumeration bursts and keep the challenge table from being pumped, while
// leaving plenty of headroom for a normal multi-step login from one client.
const (
	unauthRatePerSec = 1
	unauthBurst      = 30
)

// ipRateLimiter is a per-key token-bucket limiter. Buckets refill lazily and are
// pruned once fully refilled, so the map cannot grow without bound.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rps     float64
	burst   float64
	now     func() time.Time // overridable in tests
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// maxBuckets triggers a prune sweep; well above the count of real concurrent
// clients a single-instance server sees, but a hard ceiling on the map.
const maxBuckets = 4096

func newIPRateLimiter(rps, burst float64) *ipRateLimiter {
	return &ipRateLimiter{buckets: make(map[string]*tokenBucket), rps: rps, burst: burst, now: time.Now}
}

// allow reports whether a request from key may proceed, consuming one token.
func (l *ipRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.buckets) > maxBuckets {
		l.prune(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops buckets that have fully refilled: such a bucket is
// indistinguishable from a fresh one, so removing it loses no rate state.
func (l *ipRateLimiter) prune(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rps >= l.burst {
			delete(l.buckets, key)
		}
	}
}

// middleware rejects a request that exceeds the per-client rate with 429.
func (l *ipRateLimiter) middleware(c *gin.Context) {
	if !l.allow(clientKey(c)) {
		abort(c, http.StatusTooManyRequests, "rate limit exceeded; slow down")
		return
	}
	c.Next()
}

// clientKey is the rate-limit bucket key: the TCP peer address, not a forwarded
// header. The header is client-controlled and would let an attacker mint a fresh
// bucket per request; the peer cannot be spoofed over an established TCP
// connection. Behind a trusted reverse proxy this would instead read the proxy's
// forwarded client header (with trusted-proxy config).
func clientKey(c *gin.Context) string {
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}
