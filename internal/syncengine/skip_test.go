// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// requireUnprivileged skips a test whose point is that a path cannot be read: root
// reads everything, and Windows does not gate reads on the permission bits.
func requireUnprivileged(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not gate reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
}

// The walk skips churn and unreadable paths but must not swallow anything else —
// an upload failure reaches the same callback, and an error about a different path
// says nothing about the entry being walked.
func TestTolerateClassifiesReadFailures(t *testing.T) {
	t.Parallel()
	const path = "/tree/f.txt"
	cases := []struct {
		name     string
		err      error
		fatal    bool
		recorded bool
	}{
		{"vanished mid-walk", &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}, false, false},
		{"parent became a file", &fs.PathError{Op: "lstat", Path: path, Err: syscall.ENOTDIR}, false, false},
		{"unreadable", &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}, false, true},
		{"other filesystem error", &fs.PathError{Op: "read", Path: path, Err: errors.New("input/output error")}, true, false},
		{"about another path", &fs.PathError{Op: "open", Path: "/tree/other", Err: fs.ErrNotExist}, true, false},
		{"not a filesystem error", errors.New("pack upload failed"), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var skips skipList
			err := skips.tolerate("f.txt", path, tc.err)
			if (err != nil) != tc.fatal {
				t.Fatalf("err = %v, want fatal = %v", err, tc.fatal)
			}
			if recorded := len(skips.paths) == 1; recorded != tc.recorded {
				t.Fatalf("recorded = %v, want %v", recorded, tc.recorded)
			}
		})
	}
}

// One unreadable file must not fail the scan, and must not read as deleted either:
// its base entry is carried over, so nothing plans a remote delete for content that
// is still on disk.
func TestScanKeepsUnreadableFileAsLastSynced(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	for _, name := range []string{"keep.txt", "secret.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "secret.txt"), 0); err != nil {
		t.Fatal(err)
	}

	got, err := ScanReusing(dir, &base, true) // rehash, so the stat fast-path cannot hide the read
	if err != nil {
		t.Fatalf("an unreadable file must not fail the scan: %v", err)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Path != "secret.txt" {
		t.Fatalf("skipped = %v, want just secret.txt", got.Skipped)
	}
	if !errors.Is(got.Skipped[0].Err, fs.ErrPermission) {
		t.Fatalf("skip reason = %v, want a permission error", got.Skipped[0].Err)
	}
	if d := Diff(base, got); !d.Empty() {
		t.Fatalf("an unreadable file must read as unchanged, got %+v", d.Changes)
	}
}

// A directory the walk cannot enter takes its whole subtree with it, so the carry-over
// has to cover every base entry beneath it — otherwise one chmod would delete a whole
// subtree from the remote.
func TestScanKeepsUnreadableDirSubtree(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "nested", "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "top.txt"), []byte("top"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) }) // or TempDir cleanup cannot remove it

	got, err := ScanReusing(dir, &base, false)
	if err != nil {
		t.Fatalf("an unreadable directory must not fail the scan: %v", err)
	}
	if len(got.Skipped) != 1 || got.Skipped[0].Path != "locked" {
		t.Fatalf("skipped = %v, want just locked", got.Skipped)
	}
	// The chmod itself is a real mode change and does propagate; what must not happen
	// is the subtree behind it reading as deleted.
	for _, c := range Diff(base, got).Changes {
		if c.Kind == ChangeRemoved {
			t.Fatalf("an unreadable subtree must not read as deleted: %+v", c)
		}
	}
	if e, ok := got.ByPath()["locked/nested/deep.txt"]; !ok || e.Hash != scanEntry(t, base, "locked/nested/deep.txt").Hash {
		t.Fatalf("entry under an unreadable directory must keep its base record, got %+v (present=%v)", e, ok)
	}
	if _, ok := got.DirsByPath()["locked/nested"]; !ok {
		t.Fatal("a tracked directory under an unreadable parent must keep its base record")
	}
}

// Pack-and-seal ships the whole tree as one archive, so a file it cannot read would
// be a file deleted from the remote copy. That one has to fail loudly, naming the path.
func TestTarAndSealRefusesUnreadableFile(t *testing.T) {
	requireUnprivileged(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "secret.txt"), 0); err != nil {
		t.Fatal(err)
	}
	var ck crypto.ContentKey
	_, _, err := TarAndSeal(dir, ck, nil, nil)
	if err == nil {
		t.Fatal("TarAndSeal must refuse to ship a tree it cannot read whole")
	}
	if !strings.Contains(err.Error(), "secret.txt") {
		t.Fatalf("error must name the unreadable file, got %v", err)
	}
}
