package syncengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// A non-UTF-8 filename must fail the scan rather than be coerced to U+FFFD by
// json.Marshal when the manifest is sealed (which would restore the file under a
// corrupted name and collapse siblings differing only in invalid bytes). Filesystems
// that normalize or reject such names (APFS, NTFS) can't reproduce it, so the test
// confirms the byte sequence survived on disk before asserting.
func TestScanRejectsInvalidUTF8Path(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "caf\xe9.txt") // latin-1 'é' (0xe9), not valid UTF-8
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Skipf("filesystem rejects non-UTF-8 names: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, e := range entries {
		if !utf8.ValidString(e.Name()) {
			stored = true
		}
	}
	if !stored {
		t.Skip("filesystem normalized the non-UTF-8 name; cannot reproduce")
	}

	if _, err := Scan(dir); err == nil {
		t.Fatal("Scan must reject a tree with a non-UTF-8 filename")
	} else if !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("Scan error = %v, want it to name the UTF-8 problem", err)
	}
}

// An ignored non-UTF-8 path is never sealed into the manifest, so it must not wedge
// the scan. The UTF-8 guard runs after the ignore filter precisely so a non-UTF-8 name
// in an ignored cache or build dir does not break every sync of the folder.
func TestScanSkipsIgnoredInvalidUTF8Path(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".aqtignore"), []byte("*.tmp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "caf\xe9.tmp") // non-UTF-8, but ignored by *.tmp
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Skipf("filesystem rejects non-UTF-8 names: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, e := range entries {
		if !utf8.ValidString(e.Name()) {
			stored = true
		}
	}
	if !stored {
		t.Skip("filesystem normalized the non-UTF-8 name; cannot reproduce")
	}

	if _, err := Scan(dir); err != nil {
		t.Fatalf("Scan must skip an ignored non-UTF-8 path, got: %v", err)
	}
}
