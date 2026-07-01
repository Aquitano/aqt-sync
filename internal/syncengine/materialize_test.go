package syncengine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRemoveDirPathBecameFile covers the dir->file type change: when a tracked directory
// was replaced on disk by a regular file earlier in the same apply (a remote type change),
// RemoveDir must be a no-op that leaves the replacement file intact rather than failing on
// the ENOTDIR that os.ReadDir returns for a non-directory.
func TestRemoveDirPathBecameFile(t *testing.T) {
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
