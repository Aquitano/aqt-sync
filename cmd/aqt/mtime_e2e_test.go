// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// A tree that arrived from the remote must stat-fast-path on the very next scan.
// Entries reassembled from the DAG carry no mtime — the format does not store one —
// so unless clone and pull record the mtime each file actually landed with, every
// later `aqt status` and TUI refresh re-reads and re-hashes the whole tree, forever.
func TestPulledTreeStatFastPaths(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	writeTree(t, origin, "big.dat", bigContent())
	h.sync(origin)
	id := h.folderID(origin)

	replica := t.TempDir()
	h.clone(id, replica)
	assertScanReadsNothing(t, replica)

	// The same has to hold for files a sync pulls, not just a clone's initial write.
	writeTree(t, origin, "notes/todo.txt", "buy milk and eggs")
	writeTree(t, origin, "later.txt", "new file")
	h.sync(origin)
	h.sync(replica)
	assertScanReadsNothing(t, replica)
}

// assertScanReadsNothing rescans root against its recorded base with every hash
// replaced by a sentinel: any file the scan opens comes back with its real hash
// instead, which names exactly the entries that failed the stat fast-path.
func assertScanReadsNothing(t *testing.T, root string) {
	t.Helper()
	if err := bindTrackedRoot(root); err != nil {
		t.Fatal(err)
	}
	base, err := folderstate.LoadBase(root, flagProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Entries) == 0 {
		t.Fatal("base manifest is empty; the test proves nothing")
	}
	const sentinel = "sentinel-not-a-real-hash"
	for i := range base.Entries {
		if base.Entries[i].IsSymlink() {
			continue // symlinks are hashed from the target, never read
		}
		if base.Entries[i].MTime == 0 {
			t.Fatalf("%s has no mtime in the base manifest", base.Entries[i].Path)
		}
		base.Entries[i].Hash = sentinel
	}
	got, err := syncengine.ScanReusing(root, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got.Entries {
		if !e.IsSymlink() && e.Hash != sentinel {
			t.Errorf("%s was re-read and re-hashed", e.Path)
		}
	}
}
