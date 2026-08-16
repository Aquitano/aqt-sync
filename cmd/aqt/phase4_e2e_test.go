// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestSyncEmptyDirsAndModes covers first-class-directory behavior: an
// explicitly empty directory round-trips through clone and pull, a directory mode
// propagates, and removing an empty directory propagates as a removal.
func TestSyncEmptyDirsAndModes(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)

	if err := os.MkdirAll(filepath.Join(origin, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "data/f.txt", "hi")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(origin, "data"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if fi, err := os.Stat(filepath.Join(replica, "empty")); err != nil || !fi.IsDir() {
		t.Fatalf("empty directory did not clone: isDir=%v err=%v", err == nil && fi != nil && fi.IsDir(), err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(replica, "data"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode did not propagate through clone: got %o want 700", fi.Mode().Perm())
		}
	}

	// A new empty directory on origin propagates to replica via push then pull.
	if err := os.MkdirAll(filepath.Join(origin, "later"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	h.sync(replica)
	if fi, err := os.Stat(filepath.Join(replica, "later")); err != nil || !fi.IsDir() {
		t.Fatalf("new empty directory did not propagate: err=%v", err)
	}

	// Removing the empty directory on origin removes it on replica.
	if err := os.Remove(filepath.Join(origin, "later")); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	h.sync(replica)
	assertAbsent(t, replica, "later")
}

// TestSyncDirModeConflictSurfaces verifies that a directory whose
// mode diverged on both sides since the last sync is surfaced as a conflict (like a file
// conflict) rather than silently resolving local-wins, so a plain sync aborts and --force
// is required to take local.
func TestSyncDirModeConflictSurfaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits are not meaningful on Windows")
	}
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	if err := os.MkdirAll(filepath.Join(origin, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "d/f.txt", "hi")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Both sides change d's mode away from the cloned base, to different values.
	if err := os.Chmod(filepath.Join(origin, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.sync(origin) // remote d is now 0700
	if err := os.Chmod(filepath.Join(replica, "d"), 0o750); err != nil {
		t.Fatal(err)
	}

	// A plain sync must refuse: d changed on both sides since base.
	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected a directory-mode conflict to abort the sync, got %v", err)
	}

	// --force resolves it local-wins (0750) and completes.
	if err := runSync(replica, syncOptions{force: true}); err != nil {
		t.Fatalf("--force should resolve the dir conflict local-wins: %v", err)
	}
	fi, err := os.Stat(filepath.Join(replica, "d"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Fatalf("--force should have kept local dir mode 750, got %o", fi.Mode().Perm())
	}
}

// TestSyncSubtreeDedupOnMove checks that moving a whole directory
// re-uploads no file-content packs, because the file chunks and the subtree's
// directory node are content-addressed and already on the server. Only the new root
// node (its child was renamed) is uploaded, so the pack count grows by at most one.
func TestSyncSubtreeDedupOnMove(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "lib/util.dat", bigContent())
	writeTree(t, origin, "lib/math.dat", bigContent()+"\ntrailing variation\n")
	h.sync(origin)
	before := h.countPacks()
	if before == 0 {
		t.Fatal("expected chunked files to have uploaded packs")
	}

	// Rename the directory. lib's node (its children unchanged) seals to the same id,
	// so it and its file chunks dedup; only the new root node is new.
	if err := os.Rename(filepath.Join(origin, "lib"), filepath.Join(origin, "vendor")); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	after := h.countPacks()
	if after > before+1 {
		t.Fatalf("moving a directory uploaded %d new packs; subtree dedup did not hold (%d -> %d)", after-before, before, after)
	}

	// And the move still round-trips byte-for-byte through a fresh clone.
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	assertTreeEqual(t, origin, replica)
	if got := readTree(t, replica, "vendor/util.dat"); got != bigContent() {
		t.Fatal("moved chunked file did not reconstruct from packs")
	}
	if strings.Contains(readTree(t, replica, "vendor/math.dat"), "trailing variation") == false {
		t.Fatal("moved second file did not reconstruct")
	}
}
