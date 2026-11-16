// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/gin-gonic/gin"
)

func TestRateLimiterBurstThenRefill(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	l := newIPRateLimiter(1, 3) // burst 3, 1 token/sec
	l.now = func() time.Time { return now }

	for i := range 3 {
		if ok, _ := l.reserve("ip"); !ok {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if ok, _ := l.reserve("ip"); ok {
		t.Fatal("request beyond the burst should be denied")
	}

	now = now.Add(time.Second) // one token refills
	if ok, _ := l.reserve("ip"); !ok {
		t.Fatal("a refilled token should be allowed")
	}
	if ok, _ := l.reserve("ip"); ok {
		t.Fatal("only one token should have refilled")
	}

	if ok, _ := l.reserve("other"); !ok {
		t.Fatal("a different client must have its own bucket")
	}
}

func TestRateLimiterPrunesIdleBuckets(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	l := newIPRateLimiter(1, 1)
	l.now = func() time.Time { return now }

	for i := range maxBuckets + 10 {
		l.reserve(fmt.Sprintf("ip-%d", i))
	}
	now = now.Add(time.Hour) // every bucket fully refills
	l.reserve("trigger")     // crosses maxBuckets, so it sweeps the idle ones
	if n := len(l.buckets); n > 2 {
		t.Fatalf("idle buckets not pruned: %d remain", n)
	}
}

// 429 carries a stable code like every other error condition, so a client can branch
// on it without string-matching the message.
func TestRateLimitCarriesStableCode(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	limiter := newIPRateLimiter(0.01, 1)
	h.router.GET("/audit-ratelimit", limiter.middleware, func(c *gin.Context) { c.Status(http.StatusOK) })

	if got := h.get("/audit-ratelimit"); got.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got.Code)
	}
	got := h.get("/audit-ratelimit")
	if got.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", got.Code)
	}
	var body api.ErrorResponse
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != api.ErrCodeRateLimited {
		t.Fatalf("429 code = %q, want %q", body.Code, api.ErrCodeRateLimited)
	}
	if got.Header().Get("Retry-After") == "" {
		t.Fatal("429 carries no Retry-After")
	}
}

// TestRateLimitSetsRetryAfter covers item 27: a 429 carries a Retry-After header of
// whole seconds computed from the limiter's own refill rate.
func TestRateLimitSetsRetryAfter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	var rec *httptest.ResponseRecorder
	for range unauthBurst + 5 {
		rec = h.get("/v1/account/salt?email=rl@example.com")
		if rec.Code == http.StatusTooManyRequests {
			break
		}
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("never tripped the rate limit; last status %d", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("429 response is missing the Retry-After header")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer of seconds", ra)
	}

	// The same limiter result must also ride in the body, so a client behind an
	// intermediary that strips unknown headers still learns how long to wait.
	var body api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if body.Code != api.ErrCodeRateLimited {
		t.Fatalf("429 code = %q, want %q", body.Code, api.ErrCodeRateLimited)
	}
	if body.RetryAfterSeconds != secs {
		t.Fatalf("retryAfterSeconds = %d, Retry-After = %d; both must come from one limiter result",
			body.RetryAfterSeconds, secs)
	}
}

// Behind a trusted proxy each client keys its own bucket from the right-most
// untrusted X-Forwarded-For hop; the same headers from any other peer are ignored.
func TestClientKeyTrustsForwardedHeadersOnlyFromProxies(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{}.WithTrustedProxies([]string{"10.0.0.0/8"}))
	h.router.GET("/audit-client", func(c *gin.Context) {
		c.String(http.StatusOK, clientKey(c)+" "+h.srv.shareURL(c, "id"))
	})
	for _, tc := range []struct {
		name, peer string
		header     map[string]string
		want       string
	}{
		{"proxied client", "10.0.0.5:4000", map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"}, "203.0.113.7 https://example.com/x/id"},
		{"spoofed left hop", "10.0.0.5:4000", map[string]string{"X-Forwarded-For": "6.6.6.6, 203.0.113.7, 10.0.0.9"}, "203.0.113.7 http://example.com/x/id"},
		{"untrusted peer", "198.51.100.4:4000", map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Forwarded-Proto": "https"}, "198.51.100.4 http://example.com/x/id"},
		{"x-real-ip ignored", "10.0.0.5:4000", map[string]string{"X-Real-IP": "203.0.113.7"}, "10.0.0.5 http://example.com/x/id"},
		{"ipv6 peer keyed by its /64", "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4000", nil, "2001:db8:1:2::/64 http://example.com/x/id"},
		{"proxied ipv6 client keyed by its /64", "10.0.0.5:4000", map[string]string{"X-Forwarded-For": "2001:db8:1:2::9"}, "2001:db8:1:2::/64 http://example.com/x/id"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/audit-client", nil)
		req.RemoteAddr = tc.peer
		for k, v := range tc.header {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The public resource read draws anonymous callers from the per-client public
// bucket; an owner's token read at the same address uses its device's bucket.
func TestPublicResourceReadIsRateLimited(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	now := time.Unix(0, 0)
	h.srv.publicLimiter.now = func() time.Time { return now }
	token, mk := h.signup("public-read-limit@example.com", "passphrase for limits")
	put, code := h.putSized(token, mk, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("put = %d, want 201", code)
	}

	for i := range publicObjectsBurst {
		if got := h.get("/v1/resources/" + put.ID); got.Code == http.StatusTooManyRequests {
			t.Fatalf("anonymous read %d throttled inside the burst", i)
		}
	}
	if got := h.get("/v1/resources/" + put.ID); got.Code != http.StatusTooManyRequests {
		t.Fatalf("anonymous read past the burst = %d, want 429", got.Code)
	}
	if got := h.getCap(put.ID, token, ""); got.Code != http.StatusOK {
		t.Fatalf("owner read after anonymous burst = %d, want 200", got.Code)
	}
}
