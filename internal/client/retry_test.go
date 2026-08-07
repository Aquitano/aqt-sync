package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

// fakeClock drives cooldown deterministically: time only moves when a sleeper is
// released, so a test never waits on a real timer.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	sleeps  []time.Duration
	release chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0), release: make(chan time.Time, 64)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// After records the requested duration and returns a channel the test fires by
// calling releaseAll.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.mu.Unlock()
	ch := make(chan time.Time, 1)
	go func() {
		<-c.release
		ch <- c.Now()
	}()
	return ch
}

func (c *fakeClock) releaseAll(n int) {
	for range n {
		c.release <- c.Now()
	}
}

func (c *fakeClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, len(c.sleeps))
	copy(out, c.sleeps)
	return out
}

// testCooldown builds a cooldown on the fake clock with a fixed jitter, so the
// waits a test asserts on are exact.
func testCooldown(c *fakeClock, jitter time.Duration) *cooldown {
	return &cooldown{
		now:    c.Now,
		after:  c.After,
		jitter: func(time.Duration) time.Duration { return jitter },
	}
}

func TestCooldownGatesConcurrentWaitersOnOneDeadline(t *testing.T) {
	clk := newFakeClock()
	cd := testCooldown(clk, 0)

	// One request observes a 429 and publishes a 5s floor.
	cd.enter(5 * time.Second)

	const waiters = 8
	var released atomic.Int32
	var wg sync.WaitGroup
	for range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cd.wait(context.Background()); err != nil {
				t.Errorf("wait: %v", err)
				return
			}
			released.Add(1)
		}()
	}

	// Every waiter must be parked on the shared deadline, not through it.
	waitFor(t, func() bool { return len(clk.recorded()) == waiters })
	if got := released.Load(); got != 0 {
		t.Fatalf("waiters released before the cooldown elapsed: %d", got)
	}
	for i, d := range clk.recorded() {
		if d != 5*time.Second {
			t.Errorf("waiter %d slept %s, want the shared 5s deadline", i, d)
		}
	}

	clk.advance(5 * time.Second)
	clk.releaseAll(waiters)
	wg.Wait()
	if got := released.Load(); got != waiters {
		t.Fatalf("released %d waiters, want %d", got, waiters)
	}
}

func TestCooldownKeepsTheLaterDeadline(t *testing.T) {
	clk := newFakeClock()
	cd := testCooldown(clk, 0)

	long := cd.enter(20 * time.Second)
	// A second 429 advertising a shorter wait must not shorten a cooldown another
	// request already established.
	short := cd.enter(2 * time.Second)
	if !short.Equal(long) {
		t.Fatalf("shorter wait moved the deadline from %s to %s", long, short)
	}
	if got := cd.deadline().Sub(clk.Now()); got != 20*time.Second {
		t.Fatalf("deadline is %s away, want 20s", got)
	}
}

func TestCooldownWaitAddsPositiveJitter(t *testing.T) {
	clk := newFakeClock()
	cd := testCooldown(clk, 300*time.Millisecond)
	cd.enter(2 * time.Second)

	done := make(chan struct{})
	go func() { defer close(done); cd.wait(context.Background()) }()
	waitFor(t, func() bool { return len(clk.recorded()) == 1 })

	got := clk.recorded()[0]
	if want := 2*time.Second + 300*time.Millisecond; got != want {
		t.Fatalf("slept %s, want %s (advertised minimum plus jitter)", got, want)
	}
	clk.advance(got)
	clk.releaseAll(1)
	<-done
}

func TestCooldownJitterStaysInBounds(t *testing.T) {
	cd := newCooldown()
	for range 500 {
		d := cd.jitter(retryJitter)
		if d < 0 || d > retryJitter {
			t.Fatalf("jitter %s outside [0, %s]", d, retryJitter)
		}
	}
}

func TestCooldownWaitIsCancellable(t *testing.T) {
	clk := newFakeClock()
	cd := testCooldown(clk, 0)
	cd.enter(time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cd.wait(ctx) }()
	waitFor(t, func() bool { return len(clk.recorded()) == 1 })

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("wait returned %v, want context.Canceled", err)
	}
}

func TestCooldownWaitReturnsImmediatelyWhenClear(t *testing.T) {
	clk := newFakeClock()
	cd := testCooldown(clk, 500*time.Millisecond)
	if err := cd.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got := clk.recorded(); len(got) != 0 {
		t.Fatalf("slept %v with no cooldown active", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	httpDate := func(d time.Duration) string { return now.Add(d).UTC().Format(http.TimeFormat) }

	for _, tc := range []struct {
		name string
		raw  string
		want time.Duration
		ok   bool
	}{
		{"delay seconds", "5", 5 * time.Second, true},
		{"delay seconds with spaces", "  5  ", 5 * time.Second, true},
		{"zero floors to the minimum", "0", minRetryAfter, true},
		{"excessive delay is clamped", "86400", maxRetryAfter, true},
		{"negative is rejected", "-5", 0, false},
		{"empty is rejected", "", 0, false},
		{"garbage is rejected", "soon", 0, false},
		{"http date", httpDate(10 * time.Second), 10 * time.Second, true},
		{"past http date floors to the minimum", httpDate(-time.Hour), minRetryAfter, true},
		{"far-future http date is clamped", httpDate(48 * time.Hour), maxRetryAfter, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.raw, now)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRetryAfterFromPrefersTheHeader(t *testing.T) {
	body, _ := json.Marshal(api.ErrorResponse{Code: api.ErrCodeRateLimited, RetryAfterSeconds: 9})
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"3"}}}
	if got := retryAfterFrom(resp, body, time.Now()); got != 3*time.Second {
		t.Fatalf("got %s, want the header's 3s", got)
	}
}

func TestRetryAfterFromFallsBackToTheBody(t *testing.T) {
	body, _ := json.Marshal(api.ErrorResponse{Code: api.ErrCodeRateLimited, RetryAfterSeconds: 9})
	// An intermediary stripped the header.
	resp := &http.Response{Header: http.Header{}}
	if got := retryAfterFrom(resp, body, time.Now()); got != 9*time.Second {
		t.Fatalf("got %s, want the body's 9s", got)
	}
}

func TestRetryAfterFromFallsBackToTheFloor(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"not-a-delay"}}}
	if got := retryAfterFrom(resp, []byte("not json"), time.Now()); got != minRetryAfter {
		t.Fatalf("got %s, want the %s floor", got, minRetryAfter)
	}
}

func TestSanitizeServerText(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"plain text passes", "upgrade aqt", "upgrade aqt"},
		{"escape sequences are dropped", "safe\x1b[2Kforged", "safe[2Kforged"},
		{"newlines cannot forge a line", "line one\nerror: fake", "line oneerror: fake"},
		{"carriage return is dropped", "real\rfake", "realfake"},
		{"nul is dropped", "a\x00b", "ab"},
		{"c1 controls are dropped", "ab", "ab"},
		{"tabs become spaces", "a\tb", "a b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeServerText(tc.in, 200); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSanitizeServerTextIsBounded(t *testing.T) {
	got := sanitizeServerText(strings.Repeat("x", 500), 32)
	if len([]rune(got)) > 33 { // 32 plus the ellipsis
		t.Fatalf("got %d runes, want at most 33", len([]rune(got)))
	}
}

func TestRateLimitedErrorMatchesTheSentinel(t *testing.T) {
	err := error(&RateLimitedError{Attempts: 4, LastDelay: 2 * time.Second, NextRetryAt: time.Now()})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("RateLimitedError does not satisfy errors.Is(err, ErrRateLimited)")
	}
	var typed *RateLimitedError
	if !errors.As(err, &typed) || typed.Attempts != 4 {
		t.Fatalf("errors.As lost the detail: %+v", typed)
	}
}

// TestSendRidesOutRateLimitsThenGivesUp exercises the whole loop against a real
// server that answers 429 forever: the client must retry within its budget and
// then fail with the typed error rather than hanging.
func TestSendRidesOutRateLimitsThenGivesUp(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(api.ErrorResponse{
			Error: "rate limit exceeded; slow down", Code: api.ErrCodeRateLimited, RetryAfterSeconds: 1,
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	// Keep the test quick: the retry budget is what is under test, not the wait.
	c.cooldown.after = func(time.Duration) <-chan time.Time { return closedTimeChan() }

	err := c.do(http.MethodGet, "/v1/resources", nil, nil)
	var limited *RateLimitedError
	if !errors.As(err, &limited) {
		t.Fatalf("got %v, want a *RateLimitedError", err)
	}
	if want := maxRateLimitRetries + 1; limited.Attempts != want {
		t.Fatalf("made %d attempts, want %d", limited.Attempts, want)
	}
	if got := hits.Load(); got != int32(maxRateLimitRetries+1) {
		t.Fatalf("server saw %d requests, want %d", got, maxRateLimitRetries+1)
	}
	if limited.NextRetryAt.IsZero() {
		t.Fatal("NextRetryAt is unset; callers cannot schedule a retry")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("typed error lost errors.Is(err, ErrRateLimited)")
	}
}

// TestSendRecoversWhenTheLimitClears is the case the retry exists for: a burst
// trips the limiter, the wait is observed, and the command completes.
func TestSendRecoversWhenTheLimitClears(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resources":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.cooldown.after = func(time.Duration) <-chan time.Time { return closedTimeChan() }

	if err := c.do(http.MethodGet, "/v1/resources", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

// TestRateLimitCooldownIsSharedAcrossConcurrentRequests is the property the issue
// asks for: after one request is throttled, the others do not each independently
// wake and re-burst — they observe the same gate.
func TestRateLimitCooldownIsSharedAcrossConcurrentRequests(t *testing.T) {
	var limited atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limited.CompareAndSwap(false, true) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resources":[]}`))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	clk := newFakeClock()
	c.cooldown.now = clk.Now
	c.cooldown.after = clk.After
	c.cooldown.jitter = func(time.Duration) time.Duration { return 0 }

	// Trip the limiter, which parks this request on a 30s cooldown.
	throttled := make(chan error, 1)
	go func() { throttled <- c.do(http.MethodGet, "/v1/resources", nil, nil) }()
	waitFor(t, func() bool { return len(clk.recorded()) == 1 })

	// A request starting now must observe that cooldown before it sends at all.
	second := make(chan error, 1)
	go func() { second <- c.do(http.MethodGet, "/v1/resources", nil, nil) }()
	waitFor(t, func() bool { return len(clk.recorded()) == 2 })

	for i, d := range clk.recorded() {
		if d != 30*time.Second {
			t.Errorf("request %d slept %s, want the shared 30s cooldown", i, d)
		}
	}

	clk.advance(30 * time.Second)
	clk.releaseAll(8)
	if err := <-throttled; err != nil {
		t.Fatalf("throttled request: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second request: %v", err)
	}
}

// TestNonReplayableBodyIsNotRetried pins the safety rule: a request whose body
// cannot be rewound is never sent twice, however the server answers.
func TestNonReplayableBodyIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	c.cooldown.after = func(time.Duration) <-chan time.Time { return closedTimeChan() }

	// A bare io.Reader (not a *bytes.Reader) leaves GetBody nil, so the body is
	// consumed and unreplayable.
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/v1/resources", struct{ io.Reader }{strings.NewReader("x")})
	if err != nil {
		t.Fatal(err)
	}
	if req.GetBody != nil {
		t.Fatal("test setup: expected an unreplayable body")
	}
	if _, _, err := c.send(req, "/v1/resources"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v, want a rate-limit error", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want exactly 1", got)
	}
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := New(baseURL, "tok")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func closedTimeChan() <-chan time.Time {
	ch := make(chan time.Time, 1)
	ch <- time.Now()
	return ch
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
