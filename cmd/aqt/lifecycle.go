package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

// errNoLifecycle is returned when the caller asked for a lifecycle policy but the
// server did not echo it back, meaning it does not enforce one. The client fails
// closed rather than mint a link that never actually expires.
var errNoLifecycle = errors.New(
	"server does not enforce link lifecycle policies; upgrade the server or drop --expire/--max-reads/--burn")

// linkPolicy is a parsed, validated lifecycle request: a TTL in seconds and a read
// cap, either of which may be zero (no limit).
type linkPolicy struct {
	expireSeconds int64
	maxReads      int64
}

func (p linkPolicy) requested() bool { return p.expireSeconds > 0 || p.maxReads > 0 }

// resolveLinkPolicy turns the raw push/share flags into a linkPolicy. --burn is sugar
// for --max-reads 1 and conflicts with an explicit --max-reads.
func resolveLinkPolicy(expire string, maxReads int64, burn bool) (linkPolicy, error) {
	var p linkPolicy
	if burn && maxReads != 0 {
		return p, errors.New("--burn is shorthand for --max-reads 1; do not pass both")
	}
	if maxReads < 0 {
		return p, errors.New("--max-reads must be zero or positive")
	}
	if burn {
		p.maxReads = 1
	} else {
		p.maxReads = maxReads
	}
	if expire != "" {
		d, err := parseDuration(expire)
		if err != nil {
			return p, err
		}
		if d <= 0 {
			return p, errors.New("--expire must be a positive duration")
		}
		p.expireSeconds = int64(d / time.Second)
		if p.expireSeconds <= 0 {
			return p, errors.New("--expire must be at least one second")
		}
	}
	return p, nil
}

// parseDuration extends time.ParseDuration with a `d` (days) suffix it lacks, so a
// share can be given a natural "7d" instead of "168h".
func parseDuration(s string) (time.Duration, error) {
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(rest, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// echoTolerance bounds how far the server's echoed expiry may sit from the client's
// own now+TTL before the sanity check rejects it. It is generous because it only needs
// to absorb request latency and modest clock skew; the fail-closed check that actually
// matters is the presence of a non-zero echo.
const echoTolerance = time.Hour

// verifyPolicyEcho fails closed unless the server echoed back the lifecycle policy the
// caller requested. An old server ignores the request fields and echoes zeros, so a
// missing echo means the link would never be enforced.
func verifyPolicyEcho(p linkPolicy, resp api.PutResourceResponse) error {
	if !p.requested() {
		return nil
	}
	if p.expireSeconds > 0 {
		if resp.ExpiresAt == 0 {
			return errNoLifecycle
		}
		want := time.Now().Unix() + p.expireSeconds
		slack := int64(echoTolerance / time.Second)
		if resp.ExpiresAt < want-slack || resp.ExpiresAt > want+slack {
			return fmt.Errorf("server echoed an unexpected expiry (got %d, expected near %d)", resp.ExpiresAt, want)
		}
	}
	if p.maxReads > 0 {
		if resp.MaxReads == 0 {
			return errNoLifecycle
		}
		if resp.MaxReads != p.maxReads {
			return fmt.Errorf("server echoed max-reads %d, requested %d", resp.MaxReads, p.maxReads)
		}
	}
	return nil
}
