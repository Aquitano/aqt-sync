//go:build windows

package syncengine

import (
	"os"
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
