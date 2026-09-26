// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConflictsCopyConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"conflicts": "copy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An in-place restore of a tree whose own .aqtconfig selects conflicts=copy used to
// wedge after the swap: the internal propagation sync runs with force, which the
// config's copy mode contradicts — a flag conflict the user never caused. The
// propagation sync pins conflicts=block instead (issue #183).
func TestInPlaceRestoreWithConflictsCopyConfig(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeConflictsCopyConfig(t, src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, "a.txt", "changed")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	if c := readTree(t, src, "a.txt"); c != "original" {
		t.Fatalf("a.txt = %q after restore", c)
	}
	// A completed restore leaves no marker behind.
	if _, err := os.Stat(controlPath(src, restoreMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("restore marker left behind: %v", err)
	}
}

// An in-place restore replaces what syncs and nothing else. A .git directory and a
// file .aqtignore keeps local are in no snapshot, so swapping the whole old tree out
// and deleting it would destroy the only copy of them.
func TestInPlaceRestoreKeepsUntrackedFiles(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, ".aqtignore", "local.env\n")
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, "a.txt", "changed")
	writeTree(t, src, "local.env", "TOKEN=only-here")
	writeTree(t, src, ".git/HEAD", "ref: refs/heads/main\n")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	for path, want := range map[string]string{
		"a.txt":     "original",
		"local.env": "TOKEN=only-here",
		".git/HEAD": "ref: refs/heads/main\n",
	} {
		if got := readTree(t, src, path); got != want {
			t.Fatalf("%s = %q after restore, want %q", path, got, want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*")); len(left) != 0 {
		t.Fatalf("restore left a backup behind: %v", left)
	}
}

// A snapshot taken before a file was ignored restores an .aqtignore that tracks it.
// Moving that file back would let the restore's propagation sync publish it, so it
// stays in the backup.
func TestInPlaceRestoreKeepsUntrackedFromRestoredRules(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, ".aqtignore", "local.env\n")
	writeTree(t, src, "local.env", "TOKEN=only-here")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	assertAbsent(t, src, "local.env")
	other := filepath.Join(t.TempDir(), "other")
	h.clone(h.folderID(src), other)
	assertAbsent(t, other, "local.env")
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
	if len(left) != 1 || readTree(t, left[0], "local.env") != "TOKEN=only-here" {
		t.Fatalf("local.env was not kept in the backup: %v", left)
	}
}

// A snapshot can hold a symlink where the live tree has a directory. An ignored file
// in that directory stays in the backup instead of following the link out of the folder.
func TestInPlaceRestoreKeepsUntrackedOutOfSymlinks(t *testing.T) {
	parent, outside := t.TempDir(), t.TempDir()
	root, staging := filepath.Join(parent, "work"), filepath.Join(parent, "staging")
	writeTree(t, root, ".aqtignore", "*.env\n")
	writeTree(t, root, "a/local.env", "TOKEN=only-here")
	writeTree(t, staging, ".aqtignore", "*.env\n")
	if err := os.Symlink(outside, filepath.Join(staging, "a")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	if err := swapTree(root, staging); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "local.env")); !os.IsNotExist(err) {
		t.Fatalf("local.env followed the restored symlink out of the folder: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(parent, ".aqt-backup-*"))
	if len(left) != 1 || readTree(t, left[0], "a/local.env") != "TOKEN=only-here" {
		t.Fatalf("local.env was not kept in the backup: %v", left)
	}
}

// Adopting a clone whose synced .aqtconfig selects conflicts=copy used to wedge the
// internal reconcile the same way (copy contradicts --reconcile); it pins block too.
func TestAdoptWithConflictsCopyConfig(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeConflictsCopyConfig(t, origin)
	writeTree(t, origin, "a.txt", "same content")
	h.sync(origin)
	id := h.folderID(origin)

	adoptee := t.TempDir()
	copyTreeExclAqt(t, origin, adoptee)
	if err := app.runClone(id, adoptee, true, ""); err != nil {
		t.Fatalf("adopt with conflicts=copy config: %v", err)
	}
	if got := h.folderID(adoptee); got != id {
		t.Fatalf("adoptee tracks %s, want %s", got, id)
	}
}

// A kill mid-swap leaves a half-emptied root; the marker written before the swap
// must make the next sync refuse with recovery guidance instead of scanning the
// carnage as local deletions and pushing them fleet-wide.
func TestSyncRefusesAfterInterruptedRestoreSwap(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "x")
	h.sync(src)

	if err := writeMarker(src, restoreMarkerFile, interruptedRestore{SnapshotID: "snapXYZ"}); err != nil {
		t.Fatal(err)
	}
	err := app.runSync(src, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "restore") || !strings.Contains(err.Error(), "snapXYZ") {
		t.Fatalf("sync with restore marker: %v", err)
	}

	if err := clearMarker(src, restoreMarkerFile); err != nil {
		t.Fatal(err)
	}
	h.sync(src)
}
