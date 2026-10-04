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
