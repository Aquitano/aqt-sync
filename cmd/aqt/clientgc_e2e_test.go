// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/folderstate"
)

// usageObjects reports the account's stored-object count, for asserting what a
// prune reclaimed.
func (h *e2eHarness) usageObjects() int64 {
	h.t.Helper()
	cl, _, err := authedClient()
	if err != nil {
		h.t.Fatalf("authed client: %v", err)
	}
	u, err := cl.Usage()
	if err != nil {
		h.t.Fatalf("usage: %v", err)
	}
	return u.Objects
}

// The client-GC round trip: private pushes carry no refs (the stored ref rows
// stay empty while the object store grows), and after a delete an aged prune
// reclaims exactly the unreachable chunks — what survives still clones intact.
func TestClientGCSyncAndPrune(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)

	st, err := folderstate.LoadState(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}

	keep := strings.Repeat("keep this content ", 4096)
	drop := strings.Repeat("drop this content ", 4096)
	writeTree(t, dir, "keep.txt", keep)
	writeTree(t, dir, "sub/drop.txt", drop)
	h.sync(dir)

	rows, err := h.store.ResourceChunkRowsForTest(st.ID)
	if err != nil {
		t.Fatalf("count refs: %v", err)
	}
	if rows != 0 {
		t.Fatalf("refs rows after private sync = %d, want 0", rows)
	}
	objectsBefore := h.usageObjects()
	if objectsBefore <= 1 {
		t.Fatalf("objects after sync = %d, want the synced tree's objects", objectsBefore)
	}

	if err := os.Remove(filepath.Join(dir, "sub", "drop.txt")); err != nil {
		t.Fatal(err)
	}
	h.sync(dir)

	if err := h.store.BackdatePacksForTest(st.Account, 2*time.Hour); err != nil {
		t.Fatalf("backdate packs: %v", err)
	}
	if err := runPrune(false, false); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if after := h.usageObjects(); after >= objectsBefore {
		t.Fatalf("objects after prune = %d, want fewer than %d", after, objectsBefore)
	}

	clone := t.TempDir()
	h.clone(st.ID, clone)
	got, err := os.ReadFile(filepath.Join(clone, "keep.txt"))
	if err != nil || string(got) != keep {
		t.Fatalf("surviving file after prune: err=%v, content match=%v", err, string(got) == keep)
	}
	if _, err := os.Stat(filepath.Join(clone, "sub", "drop.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file present in clone (stat err %v)", err)
	}
}

// The stale-view guard: a root that appeared or moved between the reachability
// walk and the delete aborts the prune, while removals stay safe to ignore.
func TestPruneRootsDrifted(t *testing.T) {
	t.Parallel()
	items := []api.ResourceListItem{{ID: "a", Version: 3}, {ID: "b", Version: 1}}
	snaps := []api.SnapshotInfo{{ID: "s1"}}

	if rootsDrifted(items, items, snaps, snaps) {
		t.Fatal("identical listings must not drift")
	}
	if rootsDrifted(items, items[:1], snaps, nil) {
		t.Fatal("removed roots must not drift (the walked view is conservative)")
	}
	if !rootsDrifted(items, []api.ResourceListItem{{ID: "a", Version: 4}, {ID: "b", Version: 1}}, snaps, snaps) {
		t.Fatal("a version bump must drift")
	}
	if !rootsDrifted(items, append(items, api.ResourceListItem{ID: "c", Version: 1}), snaps, snaps) {
		t.Fatal("a new resource must drift")
	}
	if !rootsDrifted(items, items, snaps, append(snaps, api.SnapshotInfo{ID: "s2"})) {
		t.Fatal("a new snapshot must drift")
	}
}
