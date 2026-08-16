// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
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
		// A link author's name is hostile input: the control bytes that would let it
		// rewrite the terminal (via "wrote %s") or land in the on-disk filename are
		// stripped, leaving the now-inert printable remainder.
		"x\x1b[1A\x1b[2K\rwrote report.pdf (12 B)": "x[1A[2Kwrote report.pdf (12 B)",
		"a\nb.txt":   "ab.txt",
		"\x1b\r\x07": "aqt-download",
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

// TestWriteStreamAtomicLeavesOriginalOnFailure covers the H1 fix: a mid-stream
// failure must not truncate or remove an existing destination. The original
// bytes survive and no temp file is left behind.
func TestWriteStreamAtomicLeavesOriginalOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.bin")
	original := []byte("original bytes, do not destroy")
	if err := os.WriteFile(dest, original, 0o600); err != nil {
		t.Fatal(err)
	}

	streamErr := errors.New("simulated mid-write network failure")
	err := fsatomic.WriteStream(dest, 0o600, func(f *os.File) error {
		if _, err := f.Write([]byte("partial")); err != nil {
			return err
		}
		return streamErr
	})
	if !errors.Is(err, streamErr) {
		t.Fatalf("fsatomic.WriteStream err = %v, want streamErr", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination missing after failed write: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("destination corrupted: %q, want %q", got, original)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only dest in dir, found %d entries", len(entries))
	}
}

// TestWriteStreamAtomicRenamesOnSuccess confirms a successful stream replaces
// the destination atomically with the new bytes.
func TestWriteStreamAtomicRenamesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	want := []byte("brand new contents")
	if err := fsatomic.WriteStream(dest, 0o600, func(f *os.File) error {
		_, err := f.Write(want)
		return err
	}); err != nil {
		t.Fatalf("fsatomic.WriteStream: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}
