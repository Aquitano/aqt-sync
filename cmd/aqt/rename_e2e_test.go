package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestStatusLocalRename covers the offline local-changes view: a file renamed on
// disk since the last sync is reported as one `renamed old -> new` line, not as a
// new-and-deleted pair.
func TestStatusLocalRename(t *testing.T) {
	h := newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "content")
	h.sync(src)

	renameOnDisk(t, src, "a.txt", "b.txt")

	out := captureStdout(t, func() { mustStatusOpts(t, src, statusOptions{offline: true}) })
	if !strings.Contains(out, "renamed") || !strings.Contains(out, "a.txt -> b.txt") {
		t.Fatalf("status did not report the rename:\n%s", out)
	}
	if strings.Contains(out, "new") || strings.Contains(out, "deleted") {
		t.Errorf("rename leaked as new/deleted:\n%s", out)
	}
}

// TestSyncDryRunLocalRename covers the dry-run plan: a local file rename coalesces
// into one `renamed old -> new` line instead of the upload+delete-remote pair.
func TestSyncDryRunLocalRename(t *testing.T) {
	h := newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "content")
	h.sync(src)

	renameOnDisk(t, src, "a.txt", "b.txt")

	out := captureStdout(t, func() { h.syncOpts(src, syncOptions{dryRun: true}) })
	if !strings.Contains(out, "renamed") || !strings.Contains(out, "a.txt -> b.txt") {
		t.Fatalf("dry-run plan missing the rename:\n%s", out)
	}
	if strings.Contains(out, "upload") || strings.Contains(out, "delete") {
		t.Errorf("dry-run plan still lists upload/delete for the renamed paths:\n%s", out)
	}
}

// TestSyncDryRunDirRename covers the whole-directory move: renaming a directory of
// two files plus a nested subdir collapses to a single `renamed olddir/ -> newdir/`
// line, with no per-file upload/delete lines and no directory action lines.
func TestSyncDryRunDirRename(t *testing.T) {
	h := newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "d/a.txt", "one")
	writeTree(t, src, "d/b.txt", "two")
	if err := os.MkdirAll(filepath.Join(src, "d", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sync(src)

	if err := os.Rename(filepath.Join(src, "d"), filepath.Join(src, "d2")); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { h.syncOpts(src, syncOptions{dryRun: true}) })
	if !strings.Contains(out, "d/ -> d2/") {
		t.Fatalf("dry-run plan missing the directory rename:\n%s", out)
	}
	if n := strings.Count(out, "renamed"); n != 1 {
		t.Errorf("expected exactly one rename line, got %d:\n%s", n, out)
	}
	if strings.Contains(out, "upload") || strings.Contains(out, "delete") {
		t.Errorf("dir rename left per-file or per-dir action lines:\n%s", out)
	}
}

// TestSnapshotDiffRename covers the content-addressed snapshot diff: a file renamed
// after the snapshot is reported as a rename pair, not as an add plus a remove.
func TestSnapshotDiffRename(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "moved content")
	writeTree(t, src, "keep.txt", "stays")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	renameOnDisk(t, src, "a.txt", "b.txt")
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
	if len(got.Renamed) != 1 || got.Renamed[0].From != "a.txt" || got.Renamed[0].To != "b.txt" {
		t.Fatalf("renamed = %v, want [a.txt -> b.txt]", got.Renamed)
	}
	assertStrings(t, "added", got.Added, nil)
	assertStrings(t, "removed", got.Removed, nil)
	assertStrings(t, "modified", got.Modified, nil)
}

// TestDiffIncomingRename covers the incoming (remote) view: a path whose content
// moved on the server since the last sync is one rename, not an add plus a delete.
func TestDiffIncomingRename(t *testing.T) {
	base := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "a.txt", Hash: "H", Mode: 0o644},
	}}
	remote := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "b.txt", Hash: "H", Mode: 0o644},
	}}

	got := diffIncoming(base, remote)
	if len(got.renamed) != 1 || got.renamed[0].From != "a.txt" || got.renamed[0].To != "b.txt" {
		t.Fatalf("renamed = %v, want [a.txt -> b.txt]", got.renamed)
	}
	if len(got.added) != 0 || len(got.deleted) != 0 || len(got.modified) != 0 {
		t.Errorf("rename leaked into added/deleted/modified: +%v -%v ~%v", got.added, got.deleted, got.modified)
	}
	if got.total() != 1 {
		t.Errorf("total = %d, want 1", got.total())
	}
}

// TestSyncRenameThenClean confirms rename reporting is display-only and does not
// break the apply path: a real sync after a rename leaves both the local tree and
// the server clean.
func TestSyncRenameThenClean(t *testing.T) {
	h := newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "content")
	h.sync(src)

	renameOnDisk(t, src, "a.txt", "b.txt")
	h.sync(src)

	out := captureStdout(t, func() { mustStatus(t, src) })
	if !strings.Contains(out, "clean (no local changes since last sync)") {
		t.Errorf("post-rename sync left local changes:\n%s", out)
	}
	if !strings.Contains(out, "up to date with the server") {
		t.Errorf("post-rename sync did not level with the server:\n%s", out)
	}
}

func renameOnDisk(t *testing.T, root, from, to string) {
	t.Helper()
	if err := os.Rename(filepath.Join(root, filepath.FromSlash(from)), filepath.Join(root, filepath.FromSlash(to))); err != nil {
		t.Fatal(err)
	}
}
