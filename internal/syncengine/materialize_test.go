// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A materialized file reports the mtime it landed with, and recording that on the
// base entry is what lets the next scan stat-fast-path it. Entries coming from the
// remote carry no mtime at all, so without this every command after a clone or a pull
// re-reads and re-hashes the whole tree. The sentinel hash proves nothing was read:
// only the fast path can produce it.
func TestMaterializedEntryStatFastPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	entry := Entry{Path: "pulled.txt", Mode: 0o644, Size: 5, Hash: "sentinel-not-a-real-hash"}
	mtime, err := WriteFile(root, entry, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if mtime == 0 {
		t.Fatal("materialize must report the file's mtime")
	}
	fi, err := os.Stat(filepath.Join(root, "pulled.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if mtime != fi.ModTime().UnixNano() {
		t.Fatalf("reported mtime %d, on-disk %d", mtime, fi.ModTime().UnixNano())
	}

	entry.MTime = mtime
	// The stat check covers mode too, and Windows carries only the write bit, so a
	// requested 0644 reads back as 0666 there. Take the mode from disk: what is under
	// test is the mtime, not whether a Unix mode survives a Windows filesystem.
	entry.Mode = uint32(fi.Mode().Perm())
	base := Manifest{Entries: []Entry{entry}}
	got, err := ScanReusing(root, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	if h := scanEntry(t, got, "pulled.txt").Hash; h != entry.Hash {
		t.Fatalf("a freshly materialized file was re-hashed: hash = %q", h)
	}
}

// TestMaterializeDirsAppliesModesLast pins the ordering a restrictive directory mode
// forces: applying it on sight would leave nothing able to create the directories
// underneath it, so every directory is created first and the modes come after.
func TestMaterializeDirsAppliesModesLast(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows Chmod carries only the write bit, so a non-writable directory is not representable")
	}
	root := t.TempDir()
	dirs := []DirEntry{{Path: "locked", Mode: 0o500}, {Path: "locked/inner", Mode: 0o500}}
	// RemoveAll cannot unlink out of a directory it cannot write, so restore the modes
	// before the temp dir is torn down.
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(root, "locked", "inner"), 0o700)
		_ = os.Chmod(filepath.Join(root, "locked"), 0o700)
	})

	if err := MaterializeDirs(root, dirs); err != nil {
		t.Fatalf("MaterializeDirs: %v", err)
	}

	for _, d := range dirs {
		fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(d.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if got := uint32(fi.Mode().Perm()); got != d.Mode {
			t.Errorf("%s mode = %#o, want %#o", d.Path, got, d.Mode)
		}
	}
}

// TestRemoveDirPathBecameFile covers the dir->file type change: when a tracked directory
// was replaced on disk by a regular file earlier in the same apply (a remote type change),
// RemoveDir must be a no-op that leaves the replacement file intact rather than failing on
// the ENOTDIR that os.ReadDir returns for a non-directory.
func TestRemoveDirPathBecameFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	file := filepath.Join(root, "x")
	if err := os.WriteFile(file, []byte("now a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDir(root, "x"); err != nil {
		t.Fatalf("RemoveDir on a path that became a file must not error: %v", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the replacement file must survive RemoveDir: %v", err)
	}
}

// TestRemoveDirEmptyAndNonEmpty covers the ordinary cases: an empty tracked directory is
// removed and its now-empty parents pruned up to the root, while a directory still holding
// entries is left in place.
func TestRemoveDirEmptyAndNonEmpty(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	// Empty nested directory: removed, and the empty parent pruned (but not the root).
	empty := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDir(root, "a/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		t.Fatalf("emptied parent should have been pruned, err=%v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("the tracked root must never be pruned: %v", err)
	}

	// Non-empty directory: left untouched.
	full := filepath.Join(root, "c")
	if err := os.MkdirAll(full, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDir(root, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("a non-empty directory must not be removed: %v", err)
	}
}
