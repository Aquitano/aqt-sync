// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

// A tree can list the same name as a symlink and as a directory. The directory's
// mode must not be applied through the link to whatever it points at.
func TestMaterializeDirsRefusesASymlinkAtTheDirectoryPath(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows Chmod carries only the write bit")
	}
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Chmod(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteSymlink(root, Entry{Path: "d", Link: outside}); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := MaterializeDirs(root, []DirEntry{{Path: "d", Mode: 0o755}}); err == nil {
		t.Error("MaterializeDirs accepted a directory path that is a symlink")
	}
	fi, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("symlink target mode = %#o, want it left at 0700", got)
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

// FuzzMaterializeStaysInRoot materializes an arbitrary tree shape in the order a
// clone does (files, then symlinks, then directories) and checks that nothing outside
// the root changed. A remote tree's names are chosen by whoever holds its key, which
// for a share link or a grant is another account. Each spec line is "f <path>",
// "l <path> <target selector>" or "d <path> <octal mode>"; link targets stay inside a
// per-run sandbox, so a failure is contained.
func FuzzMaterializeStaysInRoot(f *testing.F) {
	f.Add("l d 0\nd d 55") // a directory's mode once reached through a symlink at its path
	f.Add("l . 0\nl y 1")  // an entry at the root's own path once replaced the root
	f.Add("f a/x\nl a 0\nd a/b 7")
	f.Fuzz(func(t *testing.T, spec string) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation needs a privilege Windows leaves off")
		}
		sandbox := t.TempDir()
		root, outside := filepath.Join(sandbox, "root"), filepath.Join(sandbox, "outside")
		for _, d := range []string{sandbox, root, outside} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		targets := []string{outside, sandbox}
		var files, links []Entry
		var dirs []DirEntry
		for _, line := range strings.Split(spec, "\n") {
			kind, rest, _ := strings.Cut(line, " ")
			path, arg, _ := strings.Cut(rest, " ")
			switch kind {
			case "f":
				files = append(files, Entry{Path: path, Mode: 0o600, Inline: []byte("x")})
			case "l":
				links = append(links, Entry{Path: path, Link: targets[len(arg)%len(targets)]})
			case "d":
				mode, _ := strconv.ParseUint(arg, 8, 32)
				// Owner rwx always, so the sandbox stays removable; the fuzzed group
				// and other bits are what a chmod through a link would reveal.
				dirs = append(dirs, DirEntry{Path: path, Mode: 0o700 | uint32(mode)&0o077})
			}
		}
		for _, e := range files {
			_, _ = WriteFile(root, e, e.Inline)
		}
		for _, e := range links {
			_ = WriteSymlink(root, e)
		}
		_ = MaterializeDirs(root, dirs)

		if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
			t.Fatalf("the root is no longer a directory (err %v)", err)
		}
		for _, d := range []string{sandbox, outside} {
			if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
				t.Fatalf("%s changed mode or vanished (err %v)", d, err)
			}
		}
		if got, _ := os.ReadDir(outside); len(got) > 0 {
			t.Fatalf("%d entries landed outside the root", len(got))
		}
		if got, _ := os.ReadDir(sandbox); len(got) != 2 {
			t.Fatalf("the sandbox holds %d entries, want only root and outside", len(got))
		}
	})
}
