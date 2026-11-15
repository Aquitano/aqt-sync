// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package syncengine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Windows synthesizes permission bits (0666/0777), so a scan must carry the
// base's recorded mode instead of pushing the synthetic one to every POSIX
// device — and a path with no base entry gets the conventional default.
func TestWindowsScanCarriesBaseModes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "new.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the folder was authored on a POSIX host — an executable script and a
	// non-default directory mode — and that bin/new.txt is new since the last sync.
	entries := base.Entries[:0]
	for _, e := range base.Entries {
		if e.Path == "run.sh" {
			e.Mode = 0o755
		}
		if e.Path != "bin/new.txt" {
			entries = append(entries, e)
		}
	}
	base.Entries = entries
	for i := range base.Dirs {
		base.Dirs[i].Mode = 0o750
	}

	m, err := ScanReusing(dir, &base, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		switch e.Path {
		case "run.sh":
			if e.Mode != 0o755 {
				t.Errorf("run.sh mode = %o, want the base's 755 carried forward", e.Mode)
			}
		case "bin/new.txt":
			if e.Mode != 0o644 {
				t.Errorf("new file mode = %o, want the 644 default", e.Mode)
			}
		}
	}
	for _, d := range m.Dirs {
		if d.Mode != 0o750 {
			t.Errorf("dir %s mode = %o, want the base's 750 carried forward", d.Path, d.Mode)
		}
	}
}

// A junction inside the tracked tree points outside it. The scan must keep base
// content under it instead of reading it as deleted, and a pull must refuse to
// write through it.
func TestJunctionIsNeitherFollowedNorDeleted(t *testing.T) {
	t.Parallel()
	dir, outside := t.TempDir(), t.TempDir()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(dir, "j"), outside).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}

	base := Manifest{Entries: []Entry{{Path: "j/x", Hash: "h"}}}
	got, err := ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Path != "j" || !errors.Is(got.Skipped[0].Err, errReparsePoint) {
		t.Fatalf("skipped = %v, want just the junction", got.Skipped)
	}
	if _, ok := got.ByPath()["j/x"]; !ok {
		t.Fatal("base content under a junction must not read as deleted")
	}

	if _, err := WriteFile(dir, Entry{Path: "j/y"}, []byte("y")); err == nil {
		t.Fatal("a write through a junction must be refused")
	}
	if err := MaterializeDirs(dir, []DirEntry{{Path: "j/sub"}}); err == nil {
		t.Fatal("a directory through a junction must be refused")
	}
	if _, err := os.Lstat(filepath.Join(outside, "y")); !os.IsNotExist(err) {
		t.Fatalf("file landed outside the tracked root: %v", err)
	}
}

// A backslash is a separator on Windows: a\b must be refused, not written as b
// inside a new directory a.
func TestSafeJoinRefusesBackslash(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := WriteFile(dir, Entry{Path: `a\b`}, []byte("x")); err == nil {
		t.Fatal("a backslash name must be refused")
	}
	if _, err := os.Lstat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatalf("a backslash name was split into a path: %v", err)
	}
}
