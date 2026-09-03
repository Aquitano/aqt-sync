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
