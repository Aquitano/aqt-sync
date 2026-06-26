package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestSafeOutputName(t *testing.T) {
	cases := map[string]string{
		"..":           "aqt-download",
		".":            "aqt-download",
		"/":            "aqt-download",
		"":             "aqt-download",
		"stdin":        "aqt-download",
		"../../evil":   "evil",
		"/etc/passwd":  "passwd",
		"sub/dir/file": "file",
		"report.txt":   "report.txt",
	}
	for in, want := range cases {
		if got := safeOutputName(in); got != want {
			t.Errorf("safeOutputName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestWriteOutputConfinesToCWD verifies that a default destination derived from
// attacker-controlled metadata cannot escape the working directory.
func TestWriteOutputConfinesToCWD(t *testing.T) {
	tmp := t.TempDir()
	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCWD) })

	// Resolve symlinks so the containment check holds where TempDir lives under a
	// symlinked path (e.g. /tmp -> /private/tmp).
	tmpReal, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}

	names := []string{"../../evil", "/etc/passwd", "sub/dir/file", "report.txt"}
	for _, name := range names {
		if err := writeOutput([]byte("x"), "", api.Metadata{Name: name}, false, false); err != nil {
			t.Fatalf("writeOutput(%q): %v", name, err)
		}
		base := filepath.Base(name)
		written := filepath.Join(tmp, base)
		if _, err := os.Stat(written); err != nil {
			t.Fatalf("expected %s to exist for name %q: %v", written, name, err)
		}
		absReal, err := filepath.EvalSymlinks(written)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(absReal) != tmpReal {
			t.Fatalf("name %q wrote outside CWD: %s", name, absReal)
		}
	}
}
