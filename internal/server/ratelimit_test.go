package server

import (
	"fmt"
	"testing"
	"time"
)

func TestRateLimiterBurstThenRefill(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	l := newIPRateLimiter(1, 3) // burst 3, 1 token/sec
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !l.allow("ip") {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if l.allow("ip") {
		t.Fatal("request beyond the burst should be denied")
	}

	now = now.Add(time.Second) // one token refills
	if !l.allow("ip") {
		t.Fatal("a refilled token should be allowed")
	}
	if l.allow("ip") {
		t.Fatal("only one token should have refilled")
	}

	if !l.allow("other") {
		t.Fatal("a different client must have its own bucket")
	}
}

func TestRateLimiterPrunesIdleBuckets(t *testing.T) {
	t.Parallel()
	now := time.Unix(0, 0)
	l := newIPRateLimiter(1, 1)
	l.now = func() time.Time { return now }

	for i := 0; i < maxBuckets+10; i++ {
		l.allow(fmt.Sprintf("ip-%d", i))
	}
	now = now.Add(time.Hour) // every bucket fully refills
	l.allow("trigger")       // crosses maxBuckets, so it sweeps the idle ones
	if n := len(l.buckets); n > 2 {
		t.Fatalf("idle buckets not pruned: %d remain", n)
	}
}
