// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import "testing"

// The pack LRU must be O(1) per operation and byte-bounded: recency updates on get,
// least-recently-used eviction, and the single-oversize-entry guarantee.
func TestCacheLRU(t *testing.T) {
	c := NewCache(10)
	c.Put("a", make([]byte, 4))
	c.Put("b", make([]byte, 4))
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a missing")
	}
	// a was just used; adding c must evict b, the least recently used.
	c.Put("c", make([]byte, 4))
	if _, ok := c.Get("b"); ok {
		t.Fatal("b survived eviction over the more recently used a")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a evicted despite being recently used")
	}

	// A single entry over the whole budget is still kept, so it can be served.
	c.Put("big", make([]byte, 64))
	if _, ok := c.Get("big"); !ok {
		t.Fatal("oversize entry not kept")
	}
	if c.order.Len() != 1 {
		t.Fatalf("order len = %d, want 1", c.order.Len())
	}

	// Replacing an entry adjusts the byte accounting.
	c.Put("big", make([]byte, 4))
	c.Put("d", make([]byte, 4))
	if _, ok := c.Get("big"); !ok {
		t.Fatal("replaced entry lost")
	}
	if _, ok := c.Get("d"); !ok {
		t.Fatal("d lost despite fitting the budget")
	}
}
