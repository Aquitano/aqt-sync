// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unicode/utf8"
)

func TestInPlaceRestoreKeepsNonUTF8SpecialFiles(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	bad := "pipe-\xff"
	if err := syscall.Mkfifo(filepath.Join(src, bad), 0o600); err != nil {
		t.Skipf("filesystem rejects a FIFO with a non-UTF-8 name: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, e := range entries {
		stored = stored || !utf8.ValidString(e.Name())
	}
	if !stored {
		t.Skip("filesystem normalized the non-UTF-8 name")
	}
	if err := syscall.Mkfifo(filepath.Join(src, "local.pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTree(t, src, "a.txt", "changed")
	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	left, err := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
	if err != nil || len(left) != 1 {
		t.Fatalf("expected retained backup: %v, %v", left, err)
	}
	for _, path := range []string{filepath.Join(left[0], bad), filepath.Join(src, "local.pipe")} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("FIFO was not preserved at %q: %v, %v", path, info, err)
		}
	}
	h.sync(src)
	replica := t.TempDir()
	h.clone(h.folderID(src), replica)
	if got := readTree(t, replica, "a.txt"); got != "original" {
		t.Fatalf("restored replica = %q, want original", got)
	}
}

func TestRestoreCarriesParentPermissions(t *testing.T) {
	restoreUmask := setUmask(t, 0o022)
	defer restoreUmask()
	parent := t.TempDir()
	root, staging := filepath.Join(parent, "work"), filepath.Join(parent, "staging")
	writeTree(t, root, ".aqtignore", "*.env\n")
	writeTree(t, root, "shared/local.env", "only copy")
	if err := os.Chmod(filepath.Join(root, "shared"), 0o775); err != nil {
		t.Fatal(err)
	}
	writeTree(t, staging, ".aqtignore", "*.env\n")
	if err := swapTree(root, staging); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o775 {
		t.Fatalf("carried parent permissions = %04o, want 0775", got)
	}
	if got := readTree(t, root, "shared/local.env"); got != "only copy" {
		t.Fatalf("carried file = %q", got)
	}
}

func TestRestoreCarriesIgnoredFilesUnderReadOnlyParents(t *testing.T) {
	restoreUmask := setUmask(t, 0o022)
	defer restoreUmask()
	for _, tc := range []struct {
		name         string
		stagedParent bool
		ignored      string
	}{
		{"new parent", false, "dir/shared/local.env"},
		{"new nested parents", false, "dir/shared/sub/local.env"},
		{"existing restored parent", true, "dir/shared/local.env"},
		{"ignored directory", true, "dir/shared/local/cache.env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			t.Cleanup(func() {
				_ = filepath.WalkDir(parent, func(path string, d os.DirEntry, err error) error {
					if err == nil && d.IsDir() {
						_ = os.Chmod(path, 0o700)
					}
					return nil
				})
			})
			root, staging := filepath.Join(parent, "work"), filepath.Join(parent, "staging")
			rules := "*.env\n"
			if tc.name == "ignored directory" {
				rules = "dir/shared/local/\n"
			}
			writeTree(t, root, ".aqtignore", rules)
			writeTree(t, root, tc.ignored, "only copy")
			writeTree(t, staging, ".aqtignore", rules)
			writeTree(t, staging, "dir/tracked.txt", "restored")
			if err := os.Chmod(filepath.Join(root, "dir/shared"), 0o555); err != nil {
				t.Fatal(err)
			}
			wantMode := os.FileMode(0o555)
			if tc.stagedParent {
				writeTree(t, staging, "dir/shared/tracked.txt", "restored nested")
				wantMode = 0o500
				if err := os.Chmod(filepath.Join(staging, "dir/shared"), wantMode); err != nil {
					t.Fatal(err)
				}
			}
			if err := swapTree(root, staging); err != nil {
				t.Fatal(err)
			}
			if got := readTree(t, root, tc.ignored); got != "only copy" {
				t.Fatalf("ignored contents = %q", got)
			}
			info, err := os.Stat(filepath.Join(root, "dir/shared"))
			if err != nil || info.Mode().Perm() != wantMode {
				t.Fatalf("parent permissions: %v, %v; want %04o", info, err, wantMode)
			}
			if got := readTree(t, root, "dir/tracked.txt"); got != "restored" {
				t.Fatalf("tracked contents = %q", got)
			}
			left, err := filepath.Glob(filepath.Join(parent, ".aqt-backup-*"))
			if err != nil || len(left) != 0 {
				t.Fatalf("restore retained a backup: %v, %v", left, err)
			}
		})
	}
}

func TestRestoreCarryRestoresPermissionsAfterCollision(t *testing.T) {
	parent := t.TempDir()
	backup, root := filepath.Join(parent, "backup"), filepath.Join(parent, "restored")
	t.Cleanup(func() {
		for _, tree := range []string{backup, root} {
			_ = os.Chmod(filepath.Join(tree, "dir"), 0o700)
		}
	})
	writeTree(t, backup, "dir/first.env", "carried")
	writeTree(t, backup, "dir/collision.env", "kept in backup")
	writeTree(t, root, ".aqtignore", "*.env\n")
	writeTree(t, root, "dir/collision.env", "restored")
	for tree, mode := range map[string]os.FileMode{backup: os.ModeSticky | 0o555, root: os.ModeSticky | 0o500} {
		if err := os.Chmod(filepath.Join(tree, "dir"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := carryUntracked(backup, root, []string{"dir/first.env", "dir/collision.env"}); err == nil {
		t.Fatal("collision was accepted")
	}
	if got := readTree(t, root, "dir/first.env"); got != "carried" {
		t.Fatalf("carried contents = %q", got)
	}
	if got := readTree(t, backup, "dir/collision.env"); got != "kept in backup" {
		t.Fatalf("backup contents = %q", got)
	}
	if got := readTree(t, root, "dir/collision.env"); got != "restored" {
		t.Fatalf("restored contents = %q", got)
	}
	for tree, mode := range map[string]os.FileMode{backup: os.ModeSticky | 0o555, root: os.ModeSticky | 0o500} {
		info, err := os.Stat(filepath.Join(tree, "dir"))
		if err != nil || info.Mode()&(os.ModePerm|os.ModeSticky) != mode {
			t.Fatalf("%s permissions: %v, %v; want %04o", tree, info, err, mode)
		}
	}
}
