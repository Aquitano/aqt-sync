// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"testing"
)

// A standing conflict must not retry a full failing sync at the base interval
// forever: a deferred or failed attempt over an unchanged tree lets the poll
// interval back off, while resolving the conflict (a tree change) snaps it back
// (issue #183).
func TestWatcherFailingSyncBacksOff(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	w.sync = func() error { f.syncs++; return errors.New("conflicts changed on both sides") }
	var st watchState

	w.step(&st) // prime
	w.step(&st) // quiet -> first (failing) sync attempt
	if f.syncs != 1 {
		t.Fatalf("syncs=%d, want 1", f.syncs)
	}
	if st.idle != 1 {
		t.Fatalf("idle=%d after a failed attempt, want 1 (backoff engaged)", st.idle)
	}
	w.step(&st)
	w.step(&st)
	if st.idle != 3 {
		t.Fatalf("idle=%d after repeated failures, want a growing streak", st.idle)
	}
	if !st.pending {
		t.Fatal("a failed sync must stay pending so the retry still happens")
	}

	// Resolving the conflict shows up as a tree change: streak resets, sync retries.
	f.sig = "b"
	w.step(&st)
	if st.idle != 0 {
		t.Fatalf("idle=%d after a change, want 0", st.idle)
	}
	w.sync = func() error { f.syncs++; return nil }
	w.step(&st)
	if st.idle != 0 || f.syncs < 3 {
		t.Fatalf("recovered sync: idle=%d syncs=%d", st.idle, f.syncs)
	}
}

// The pack LRU must be O(1) per operation and byte-bounded: recency updates on get,
// least-recently-used eviction, and the single-oversize-entry guarantee.
func TestPackCacheLRU(t *testing.T) {
	c := newPackCache(10)
	c.put("a", make([]byte, 4))
	c.put("b", make([]byte, 4))
	if _, ok := c.get("a"); !ok {
		t.Fatal("a missing")
	}
	// a was just used; adding c must evict b, the least recently used.
	c.put("c", make([]byte, 4))
	if _, ok := c.get("b"); ok {
		t.Fatal("b survived eviction over the more recently used a")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("a evicted despite being recently used")
	}

	// A single entry over the whole budget is still kept, so it can be served.
	c.put("big", make([]byte, 64))
	if _, ok := c.get("big"); !ok {
		t.Fatal("oversize entry not kept")
	}
	if c.order.Len() != 1 {
		t.Fatalf("order len = %d, want 1", c.order.Len())
	}

	// Replacing an entry adjusts the byte accounting.
	c.put("big", make([]byte, 4))
	c.put("d", make([]byte, 4))
	if _, ok := c.get("big"); !ok {
		t.Fatal("replaced entry lost")
	}
	if _, ok := c.get("d"); !ok {
		t.Fatal("d lost despite fitting the budget")
	}
}
