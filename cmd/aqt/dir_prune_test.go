// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// Deleting the last file in a tracked directory must not delete the directory:
// the parent-pruning in RemoveFile is blind to the tracked set, so without the
// healing pass the emptied directory vanished locally and the next sync pushed
// that as a fleet-wide directory delete (issue #175).
func TestPullEmptyingTrackedDirKeepsIt(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "docs/only.txt", "content")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Origin deletes the file but keeps the (now empty) directory tracked.
	removeTree(t, origin, "docs/only.txt")
	h.sync(origin)

	// The replica's pull applies the delete; the tracked directory must survive.
	h.sync(replica)
	assertAbsent(t, replica, "docs/only.txt")
	if fi, err := os.Stat(filepath.Join(replica, "docs")); err != nil || !fi.IsDir() {
		t.Fatalf("tracked dir gone after pull emptied it: %v", err)
	}

	// And the replica must have nothing to push: a full round trip leaves the
	// directory alive on the origin too.
	h.sync(replica)
	h.sync(origin)
	if fi, err := os.Stat(filepath.Join(origin, "docs")); err != nil || !fi.IsDir() {
		t.Fatalf("tracked dir deleted fleet-wide: %v", err)
	}
}

// The pack-and-seal pull prunes with the same blind parent-pruning; its healing
// pass must keep an emptied tracked directory alive as well.
func TestPackPullEmptyingTrackedDirKeepsIt(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "docs/only.txt", "content")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	removeTree(t, origin, "docs/only.txt")
	h.sync(origin)

	h.sync(replica)
	assertAbsent(t, replica, "docs/only.txt")
	if fi, err := os.Stat(filepath.Join(replica, "docs")); err != nil || !fi.IsDir() {
		t.Fatalf("tracked dir gone after pack pull emptied it: %v", err)
	}
}

// EnsureDirs recreates only what is missing: an existing directory keeps its
// on-disk mode, a missing one is created with its recorded mode.
func TestEnsureDirsRecreatesOnlyMissing(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "kept"), 0o755); err != nil {
		t.Fatal(err)
	}
	dirs := []syncengine.DirEntry{
		{Path: "kept", Mode: 0o700},
		{Path: "pruned/nested", Mode: 0o750},
	}
	if err := syncengine.EnsureDirs(root, dirs); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(root, "kept")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("existing dir touched: %v %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(filepath.Join(root, "pruned", "nested")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("missing dir not recreated with recorded mode: %v %v", fi, err)
	}
}
