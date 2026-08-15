// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A file deleted independently on both devices converged; the second device's sync
// must apply cleanly (no exit-4 conflict wedge) and drop the path from its base so
// it stops reading as forever-pending (issue #183).
func TestBothSidesDeletedSyncsClean(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "doomed.txt", "x")
	writeTree(t, origin, "keep.txt", "y")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	removeTree(t, origin, "doomed.txt")
	h.sync(origin)
	removeTree(t, replica, "doomed.txt")

	// Pre-fix this returned errConflictsRemain (exit 4) forever.
	if err := runSync(replica, syncOptions{}); err != nil {
		t.Fatalf("both-sides delete conflicted: %v", err)
	}
	assertAbsent(t, replica, "doomed.txt")

	// The base converged too: the next syncs on both sides are no-ops and the
	// deletion does not resurrect or re-plan.
	h.sync(replica)
	h.sync(origin)
	assertAbsent(t, origin, "doomed.txt")
	if got := readTree(t, origin, "keep.txt"); got != "y" {
		t.Fatalf("keep.txt = %q", got)
	}
}

// A crash leftover from an interrupted materialize must not be pushed as content:
// the scanner ignores .aqt-tmp-* and the sync leaves it local-only.
func TestCrashLeftoverTmpFileNotPushed(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "x")
	if err := os.WriteFile(filepath.Join(origin, ".aqt-tmp-9999"), []byte("torn write"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	assertAbsent(t, replica, ".aqt-tmp-9999")
	if got := readTree(t, replica, "a.txt"); got != "x" {
		t.Fatalf("a.txt = %q", got)
	}
}
