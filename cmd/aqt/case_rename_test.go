// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// A case-only rename plans as an add+delete pair. On a case-folding filesystem the
// delete and the survivor are one physical file, so the pair must become a rename
// and leave the delete lists; unrelated deletes must be untouched (issue #174).
func TestPlanCaseOnlyRenames(t *testing.T) {
	newBase := map[string]syncengine.Entry{
		"file.txt":      {Path: "file.txt"},
		"dir/child.txt": {Path: "dir/child.txt"},
		"same.txt":      {Path: "same.txt"},
	}
	newBaseDirs := map[string]syncengine.DirEntry{
		"dir": {Path: "dir"},
	}
	deletes := []string{"File.txt", "Dir/Child.txt", "gone.txt"}
	dirRemovals := []string{"Dir", "emptied"}

	renames, keptDeletes, keptDirRemovals := planCaseOnlyRenames(deletes, dirRemovals, newBase, newBaseDirs)

	wantRenames := []caseRename{
		{from: "Dir", to: "dir"},
		{from: "Dir/Child.txt", to: "dir/child.txt"},
		{from: "File.txt", to: "file.txt"},
	}
	if !reflect.DeepEqual(renames, wantRenames) {
		t.Errorf("renames = %v, want %v", renames, wantRenames)
	}
	if !reflect.DeepEqual(keptDeletes, []string{"gone.txt"}) {
		t.Errorf("kept deletes = %v", keptDeletes)
	}
	if !reflect.DeepEqual(keptDirRemovals, []string{"emptied"}) {
		t.Errorf("kept dir removals = %v", keptDirRemovals)
	}
}

// A delete whose path equals a survivor exactly is not a rename (the download
// replaces it in place); only a case-differing survivor converts.
func TestPlanCaseOnlyRenamesLeavesExactMatches(t *testing.T) {
	newBase := map[string]syncengine.Entry{"a.txt": {Path: "a.txt"}}
	renames, kept, _ := planCaseOnlyRenames([]string{"a.txt"}, nil, newBase, nil)
	if len(renames) != 0 {
		t.Errorf("exact-path delete converted to rename: %v", renames)
	}
	if !reflect.DeepEqual(kept, []string{"a.txt"}) {
		t.Errorf("kept = %v", kept)
	}
}

// On a case-folding filesystem the early/late classification must compare
// case-insensitively: a deleted file whose remote replacement is a directory of a
// different case still occupies the download's path (issue #174).
func TestPartitionDeletesByDownloadFoldsCase(t *testing.T) {
	downloads := []syncengine.Entry{{Path: "foo/inner.txt"}, {Path: "bar"}}
	deletes := []string{"Foo", "Bar/x", "other"}

	early, late := partitionDeletesByDownload(deletes, downloads, true)
	if !reflect.DeepEqual(early, []string{"Foo", "Bar/x"}) {
		t.Errorf("fold early = %v", early)
	}
	if !reflect.DeepEqual(late, []string{"other"}) {
		t.Errorf("fold late = %v", late)
	}

	early, _ = partitionDeletesByDownload(deletes, downloads, false)
	if len(early) != 0 {
		t.Errorf("case-sensitive early = %v, want none", early)
	}
}

// The rename executor must move the old-cased entry onto its survivor path instead
// of the apply loop deleting it, including a child whose parent directory was
// already renamed by an earlier (shallower) pair.
func TestRenameCaseOnlyMovesInsteadOfDeleting(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Dir", "Child.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "File.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Shallowest first, the order applyPlan executes.
	for _, r := range []caseRename{
		{from: "Dir", to: "dir"},
		{from: "Dir/Child.txt", to: "dir/child.txt"},
		{from: "File.txt", to: "file.txt"},
	} {
		if err := syncengine.RenameCaseOnly(root, r.from, r.to); err != nil {
			t.Fatalf("rename %s -> %s: %v", r.from, r.to, err)
		}
	}

	for path, want := range map[string]string{
		"dir/child.txt": "v1",
		"file.txt":      "x",
	} {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if syncengine.CaseInsensitiveDir(root) {
		return // old and new names are the same entries here; nothing more to assert
	}
	for _, gone := range []string{"File.txt", "Dir"} {
		if _, err := os.Lstat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still present: %v", gone, err)
		}
	}
}

// A missing source (never existed, or already carried along by a parent rename with
// no leaf case change) is not an error.
func TestRenameCaseOnlyToleratesMissingSource(t *testing.T) {
	root := t.TempDir()
	if err := syncengine.RenameCaseOnly(root, "Ghost.txt", "ghost.txt"); err != nil {
		t.Fatalf("missing source: %v", err)
	}
}

// End-to-end wiring: a case-only file and directory rename pushed from one device
// applies cleanly on a case-folding replica — the old names convert to renames, the
// content survives, and the replica has nothing new to push afterwards.
func TestSyncAppliesCaseOnlyRenameOnFoldingFS(t *testing.T) {
	t.Setenv("AQT_TEST_CASE_INSENSITIVE", "1")
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "File.txt", "x")
	writeTree(t, dir, "Dir/Child.txt", "v1")
	h.sync(dir)

	replica := t.TempDir()
	h.clone(h.folderID(dir), replica)

	if err := os.Rename(filepath.Join(dir, "File.txt"), filepath.Join(dir, "file.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "Dir"), filepath.Join(dir, "dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "dir", "Child.txt"), filepath.Join(dir, "dir", "child.txt")); err != nil {
		t.Fatal(err)
	}
	h.sync(dir)

	h.sync(replica)
	if got := readTree(t, replica, "file.txt"); got != "x" {
		t.Fatalf("file.txt = %q after case rename", got)
	}
	if got := readTree(t, replica, "dir/child.txt"); got != "v1" {
		t.Fatalf("dir/child.txt = %q after case rename", got)
	}

	// The replica converged: its next sync must not push a delete or re-add that
	// would ping-pong the rename back to the other device.
	h.sync(replica)
	h.sync(dir)
	if got := readTree(t, dir, "file.txt"); got != "x" {
		t.Fatalf("origin file.txt = %q after replica round-trip", got)
	}
	if got := readTree(t, dir, "dir/child.txt"); got != "v1" {
		t.Fatalf("origin dir/child.txt = %q after replica round-trip", got)
	}
}
