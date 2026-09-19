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
