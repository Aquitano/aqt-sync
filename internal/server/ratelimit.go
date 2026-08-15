// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

// Rate-limit defaults for the unauthenticated routes (account creation, salt
// lookup, challenge, device attach). These bound brute-force and account-
// enumeration bursts and keep the challenge table from being pumped, while
// leaving plenty of headroom for a normal multi-step login from one client.
const (
	unauthRatePerSec = 1
	unauthBurst      = 30
)

// Rate-limit defaults for the authenticated routes, keyed per device token (not per
// peer address, so a NAT'd office does not share one bucket). Generous enough that a
// large sync or clone — which fires many chunk-check, pack, and range-fetch calls in
// quick succession — never trips it, while still capping a single token's sustained
// request rate so one credential cannot hammer the API.
const (
	authedRatePerSec = 50
	authedBurst      = 500
)

// Rate-limit defaults for POST /v1/gc, keyed per owner. GC planning scales with the
// owner's whole object table, so it gets a far tighter budget than the general authed
// limit; the client already self-throttles to at most one GC per folder per hour, so
// this only bounds a token deliberately spinning on it.
const (
	gcRatePerSec = 0.2
	gcBurst      = 10
)

// Rate-limit defaults for POST /v1/public/resources/:id/objects, keyed by peer
// address (there is no identity on this unauthenticated path). The unauth limiter
// (1 rps) is tuned for auth brute force and would strangle a legitimate bulk
// download: a large streamed file pulls hundreds of ~8 MiB object batches. This
// budget is far looser than the unauth one while still capping one peer's sustained
// rate against a scraper.
const (
	publicObjectsRatePerSec = 10
	publicObjectsBurst      = 200
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
	ok, _ := l.reserve(key)
	return ok
}

// reserve is allow with the caller's Retry-After hint: on a denial it returns how
// long until the bucket has refilled one token, so the middleware can advertise it.
// The duration is zero when the request is allowed.
func (l *ipRateLimiter) reserve(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.buckets) > maxBuckets {
		l.prune(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true, 0
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false, retryAfter(1-b.tokens, l.rps)
	}
	b.tokens--
	return true, 0
}

// retryAfter is the wait until deficit tokens have refilled at rps tokens/sec,
// rounded up to whole seconds (the Retry-After delay-seconds form), and never below
// one second so a client always backs off measurably. A non-positive rps has no
// refill schedule, so it falls back to one second.
func retryAfter(deficit, rps float64) time.Duration {
	if rps <= 0 {
		return time.Second
	}
	secs := math.Ceil(deficit / rps)
	if secs < 1 {
		secs = 1
	}
	return time.Duration(secs) * time.Second
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
	l.middlewareKeyed(clientKey)(c)
}

// middlewareKeyed rejects a request that exceeds the rate for the bucket key returns,
// with 429. It lets the authenticated limiters bucket by device id or owner handle
// (set on the context by authMiddleware) instead of the peer address.
func (l *ipRateLimiter) middlewareKeyed(key func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, wait := l.reserve(key(c)); !ok {
			abortRateLimited(c, wait)
			return
		}
		c.Next()
	}
}

// abortRateLimited answers 429 with the wait advertised twice from one limiter
// result: the standards-compatible Retry-After header, and the same number in the
// body for a client behind an intermediary that strips unknown headers. retryAfter
// already rounds up to whole seconds and floors at one, which is exactly the
// Retry-After delay-seconds form.
func abortRateLimited(c *gin.Context, wait time.Duration) {
	secs := int(wait.Seconds())
	if secs < 1 {
		secs = 1
	}
	c.Header("Retry-After", strconv.Itoa(secs))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, api.ErrorResponse{
		Error:             "rate limit exceeded; slow down",
		Code:              api.ErrCodeRateLimited,
		RetryAfterSeconds: secs,
	})
}

func deviceKey(c *gin.Context) string { return c.GetString(deviceContextKey) }
func ownerKey(c *gin.Context) string  { return c.GetString(ownerContextKey) }

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
