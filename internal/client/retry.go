package client

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

// Rate-limit retry budget. The server's Retry-After is authoritative for how long
// to wait; these bound how often and for how long in total, so a server answering
// 429 indefinitely fails the command instead of hanging it.
const (
	// maxRateLimitRetries bounds how many 429s one request rides out.
	maxRateLimitRetries = 3
	// maxRetryAfter caps a single advertised wait. A hostile or misconfigured
	// server must not be able to park a client for an arbitrary length of time.
	maxRetryAfter = 30 * time.Second
	// minRetryAfter floors it, so a client always backs off measurably even if the
	// server advertises zero.
	minRetryAfter = time.Second
	// maxRetryTotal caps the summed waits across one request's retries, so three
	// maximal waits cannot silently turn a command into a two-minute hang.
	maxRetryTotal = 60 * time.Second
	// retryJitter bounds the extra delay each waiter adds above the shared
	// deadline. Concurrent requests share one cooldown floor, so without jitter
	// they would all wake on the same instant and re-trip the limiter together.
	retryJitter = 750 * time.Millisecond
)

// RateLimitedError is the typed outcome of a request that spent its whole 429
// budget. It carries what a caller needs to schedule a later attempt without
// re-parsing anything: how many tries it made, the last wait it was told to
// observe, and the earliest time a retry is safe.
type RateLimitedError struct {
	Attempts    int
	LastDelay   time.Duration
	NextRetryAt time.Time
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("server rate limit exceeded after %d attempts; retry after %s (waited up to %s)",
		e.Attempts, e.NextRetryAt.Format(time.RFC3339), e.LastDelay)
}

// Is lets errors.Is(err, ErrRateLimited) match any RateLimitedError, so callers
// written against the sentinel keep working.
func (e *RateLimitedError) Is(target error) bool { return target == ErrRateLimited }

// cooldown is the client-wide "do not send before" gate. A sync fires many chunk,
// pack, and object requests concurrently against one limiter bucket; without a
// shared floor each would ride out its own Retry-After and they would all wake
// independently, producing exactly the burst that tripped the limit. Any 429
// publishes its deadline here and every other in-flight request observes it.
type cooldown struct {
	mu    sync.Mutex
	until time.Time

	// Injectable so tests drive the gate deterministically instead of sleeping.
	now    func() time.Time
	after  func(time.Duration) <-chan time.Time
	jitter func(time.Duration) time.Duration
}

func newCooldown() *cooldown {
	return &cooldown{
		now:   time.Now,
		after: time.After,
		// Positive and bounded: never below the advertised minimum, never more
		// than retryJitter above it.
		jitter: func(d time.Duration) time.Duration { return rand.N(d + 1) },
	}
}

// enter publishes a wait, returning the resulting shared deadline. A later
// deadline always wins: an overlapping 429 that advertises a shorter wait must
// not shorten a cooldown another request already established.
func (c *cooldown) enter(wait time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := c.now().Add(wait)
	if deadline.After(c.until) {
		c.until = deadline
	}
	return c.until
}

// deadline reports the current shared floor.
func (c *cooldown) deadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.until
}

// wait blocks until the shared cooldown has elapsed, plus this waiter's own
// jitter. The deadline is re-read after every sleep: a concurrent request can
// extend it while this one is parked, and waking on the stale deadline would send
// into the burst the shared cooldown exists to prevent. alive, when set, is
// called on each wake so a deliberate park is not mistaken for a stalled
// transfer. It returns the context's error if the caller is cancelled first, so a
// ^C during a rate-limit wait aborts immediately.
func (c *cooldown) wait(ctx context.Context, alive func()) error {
	jitter := c.jitter(retryJitter)
	for {
		remaining := c.deadline().Sub(c.now())
		if remaining <= 0 {
			return nil
		}
		if err := c.sleep(ctx, remaining+jitter); err != nil {
			return err
		}
		if alive != nil {
			alive()
		}
	}
}

func (c *cooldown) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-c.after(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryAfterFrom reports how long to wait after a 429. The Retry-After header is
// authoritative whenever it survives and parses; the structured body value is the
// fallback for an intermediary that strips unknown headers. Neither present (or
// both unusable) falls back to the floor rather than hammering immediately.
func retryAfterFrom(resp *http.Response, body []byte, now time.Time) time.Duration {
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), now); ok {
		return d
	}
	if secs := decodedRetryAfterSeconds(body); secs > 0 {
		return retryAfterSeconds(secs)
	}
	return minRetryAfter
}

// decodedRetryAfterSeconds pulls the body's fallback value, or 0 when the body is
// absent, not JSON, or carries none.
func decodedRetryAfterSeconds(body []byte) int {
	var e api.ErrorResponse
	if json.Unmarshal(body, &e) != nil {
		return 0
	}
	return e.RetryAfterSeconds
}

// parseRetryAfter accepts both forms RFC 9110 defines: delay-seconds, and an
// HTTP-date. A malformed, negative, or already-past value is rejected so the
// caller can fall back; an excessive one is clamped rather than honored.
func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs < 0 {
			return 0, false
		}
		return retryAfterSeconds(secs), true
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0, false
	}
	// A date in the past means "retry now"; the floor still applies, so a server
	// with a skewed clock cannot turn the gate off entirely.
	return clampRetryAfter(when.Sub(now)), true
}

// retryAfterSeconds converts an advertised delay-seconds count. The cap is applied
// before the multiplication because a large count overflows time.Duration and wraps
// to an arbitrary value — a negative wrap would then floor to one second, the exact
// opposite of the cap it should have hit.
func retryAfterSeconds(secs int) time.Duration {
	if secs > int(maxRetryAfter/time.Second) {
		return maxRetryAfter
	}
	return clampRetryAfter(time.Duration(secs) * time.Second)
}

func clampRetryAfter(d time.Duration) time.Duration {
	return min(max(d, minRetryAfter), maxRetryAfter)
}
