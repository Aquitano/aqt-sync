package main

import (
	"errors"
	"os"
	"testing"
)

// TestAdoptReusesLocalFiles covers the happy path: a directory that already holds a
// byte-identical copy of a tracked folder is bound to the remote without any upload.
// The reconcile matches every file by hash, writes the base, and a plain sync is then
// a no-op.
func TestAdoptReusesLocalFiles(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	writeTree(t, origin, "big.dat", bigContent())
	h.sync(origin)
	id := h.folderID(origin)

	// A fresh directory that already contains the same content, but no tracking.
	adoptee := t.TempDir()
	copyTreeExclAqt(t, origin, adoptee)

	before := h.countPacks()
	if err := runClone(id, adoptee, true); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if got := h.countPacks(); got != before {
		t.Fatalf("adopt re-uploaded content: pack count %d -> %d", before, got)
	}
	if _, err := os.Stat(controlPath(adoptee, baseFile)); err != nil {
		t.Fatalf("adopt did not write base.json: %v", err)
	}
	if got := h.folderID(adoptee); got != id {
		t.Fatalf("adopted folder id = %q, want %q", got, id)
	}

	// A plain sync now has nothing to do and still uploads nothing.
	h.sync(adoptee)
	if got := h.countPacks(); got != before {
		t.Fatalf("post-adopt sync changed pack count: %d -> %d", before, got)
	}
	assertTreeEqual(t, origin, adoptee)
}

// TestAdoptDivergenceConflicts covers the reconcile branch: a modified file, a
// local-only file, and a remote-only file each surface as a conflict, so adopt aborts
// with errConflictsRemain. Tracking is still written, so --force resolves it and a
// later plain sync works.
func TestAdoptDivergenceConflicts(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "same")
	writeTree(t, origin, "edit.txt", "remote value")
	writeTree(t, origin, "remote-only.txt", "only on remote")
	h.sync(origin)
	id := h.folderID(origin)

	adoptee := t.TempDir()
	copyTreeExclAqt(t, origin, adoptee)
	writeTree(t, adoptee, "edit.txt", "local value")     // modified
	writeTree(t, adoptee, "local-only.txt", "only here") // extra local file
	removeTree(t, adoptee, "remote-only.txt")            // missing locally

	if err := runClone(id, adoptee, true); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("adopt of a diverging tree: want errConflictsRemain, got %v", err)
	}
	// Tracking must survive the conflict abort so the user can resolve and re-run.
	if st, err := loadState(adoptee); err != nil || st.ID != id {
		t.Fatalf("adopt did not leave state.json (id=%q err=%v)", st.ID, err)
	}
	if _, err := os.Stat(controlPath(adoptee, baseFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("adopt wrote base.json despite conflicts: %v", err)
	}

	// Local-wins resolves the conflicts and rebuilds the base; a plain sync then works.
	h.syncOpts(adoptee, syncOptions{reconcile: true, force: true})
	h.sync(adoptee)
	h.sync(origin)
	if got := readTree(t, origin, "edit.txt"); got != "local value" {
		t.Fatalf("force reconcile did not push local value: %q", got)
	}
	assertAbsent(t, origin, "remote-only.txt")
	if got := readTree(t, origin, "local-only.txt"); got != "only here" {
		t.Fatalf("local-only file did not propagate: %q", got)
	}
	assertTreeEqual(t, origin, adoptee)
}

// TestAdoptGuards covers the refusals: adopting an already-tracked directory, a plain
// (non-adopt) clone into a non-empty directory, and adopting a pack-and-seal folder.
func TestAdoptGuards(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "data")
	h.sync(origin)
	id := h.folderID(origin)

	// Adopting a directory that is already tracked is refused.
	if err := runClone(id, origin, true); err == nil {
		t.Fatal("adopt of an already-tracked folder did not error")
	}

	// A plain clone into a non-empty directory still refuses.
	nonEmpty := t.TempDir()
	writeTree(t, nonEmpty, "stray.txt", "in the way")
	if err := runClone(id, nonEmpty, false); err == nil {
		t.Fatal("plain clone into a non-empty directory did not error")
	}

	// Adopting a pack-and-seal folder is refused: hash reconcile does not apply.
	packOrigin := t.TempDir()
	writePackConfig(t, packOrigin)
	h.init(packOrigin)
	writeTree(t, packOrigin, "p.txt", "packed")
	h.sync(packOrigin)
	packID := h.folderID(packOrigin)

	adoptee := t.TempDir()
	writeTree(t, adoptee, "p.txt", "packed")
	if err := runClone(packID, adoptee, true); err == nil {
		t.Fatal("adopt of a pack-and-seal folder did not error")
	}

	// A local .aqtconfig selecting pack against a chunked remote is refused up front,
	// before any tracking is written.
	mismatched := t.TempDir()
	writePackConfig(t, mismatched)
	writeTree(t, mismatched, "a.txt", "data")
	if err := runClone(id, mismatched, true); err == nil {
		t.Fatal("adopt with a pack .aqtconfig against a chunked remote did not error")
	}
	if _, err := os.Stat(controlPath(mismatched, stateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused adopt still wrote tracking: %v", err)
	}
}

// copyTreeExclAqt recreates every tracked file under src into dst, skipping the .aqt
// control directory, so the copy holds the same content but no tracking.
func copyTreeExclAqt(t *testing.T, src, dst string) {
	t.Helper()
	for rel, content := range collectTree(t, src) {
		writeTree(t, dst, rel, content)
	}
}
