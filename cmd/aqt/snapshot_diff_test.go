// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestDiffTrees(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()
	// same in both
	writeTree(t, oldDir, "keep.txt", "same")
	writeTree(t, newDir, "keep.txt", "same")
	// modified
	writeTree(t, oldDir, "sub/mod.txt", "before")
	writeTree(t, newDir, "sub/mod.txt", "after")
	// removed (old only)
	writeTree(t, oldDir, "gone.txt", "x")
	// added (new only)
	writeTree(t, newDir, "sub/new.txt", "y")

	d, err := diffTrees(oldDir, newDir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"sub/new.txt"}; !reflect.DeepEqual(d.Paths(syncengine.ChangeAdded), want) {
		t.Errorf("added = %v, want %v", d.Paths(syncengine.ChangeAdded), want)
	}
	if want := []string{"gone.txt"}; !reflect.DeepEqual(d.Paths(syncengine.ChangeRemoved), want) {
		t.Errorf("removed = %v, want %v", d.Paths(syncengine.ChangeRemoved), want)
	}
	if want := []string{"sub/mod.txt"}; !reflect.DeepEqual(d.Paths(syncengine.ChangeContent), want) {
		t.Errorf("modified = %v, want %v", d.Paths(syncengine.ChangeContent), want)
	}
}

func TestDiffTreesIdentical(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	writeTree(t, a, "x.txt", "hi")
	writeTree(t, b, "x.txt", "hi")
	d, err := diffTrees(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() {
		t.Fatalf("identical trees diffed non-empty: %+v", d.Changes)
	}
}

// diffTrees must ignore the .aqt control dir, which a live tracked tree carries but a
// reconstructed snapshot does not.
func TestDiffTreesIgnoresControlDir(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	writeTree(t, a, "x.txt", "hi")
	writeTree(t, b, "x.txt", "hi")
	writeTree(t, b, ".aqt/state.json", "{}")
	d, err := diffTrees(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() {
		t.Fatalf("control dir leaked into diff: %+v", d.Changes)
	}
}

// A snapshot diffed against the live resource reports exactly the files that changed
// after the snapshot was taken, decrypting both sides on the client.
func TestSnapshotDiffAgainstLive(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "original A")
	writeTree(t, src, "sub/b.txt", "original B")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Change a.txt, remove sub/b.txt, add c.txt, then re-sync so the live state moves on.
	writeTree(t, src, "a.txt", "CHANGED A")
	removeTree(t, src, "sub/b.txt")
	writeTree(t, src, "c.txt", "new C")
	h.sync(src)

	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	got, err := computeSnapshotDiff(cl, mk, snap.ID, "")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	assertStrings(t, "added", got.Added, []string{"c.txt"})
	assertStrings(t, "removed", got.Removed, []string{"sub/b.txt"})
	assertStrings(t, "modified", got.Modified, []string{"a.txt"})
	if got.Right.Label != "live" {
		t.Errorf("right label = %q, want live", got.Right.Label)
	}
}

// Diffing two snapshots reports the delta between the versions they captured.
func TestSnapshotDiffSnapshotToSnapshot(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "v1")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	first, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatal(err)
	}

	writeTree(t, src, "a.txt", "v2")
	writeTree(t, src, "d.txt", "added later")
	h.sync(src)
	second, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatal(err)
	}

	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	got, err := computeSnapshotDiff(cl, mk, first.ID, second.ID)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	assertStrings(t, "added", got.Added, []string{"d.txt"})
	assertStrings(t, "removed", got.Removed, nil)
	assertStrings(t, "modified", got.Modified, []string{"a.txt"})
}

func assertStrings(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}
