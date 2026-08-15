// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedTar returns a small well-formed archive plus a couple of adversarial ones, so
// the fuzzer starts from valid tar framing and from the traversal shapes the extractor
// is meant to refuse.
func seedTar(f *testing.F) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "a/b.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3, ModTime: time.Unix(0, 0)})
	_, _ = tw.Write([]byte("hey"))
	_ = tw.WriteHeader(&tar.Header{Name: "a/link", Typeflag: tar.TypeSymlink, Linkname: "b.txt", Mode: 0o777, ModTime: time.Unix(0, 0)})
	_ = tw.Close()
	f.Add(buf.Bytes())

	var esc bytes.Buffer
	ew := tar.NewWriter(&esc)
	_ = ew.WriteHeader(&tar.Header{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, ModTime: time.Unix(0, 0)})
	_, _ = ew.Write([]byte("x"))
	_ = ew.Close()
	f.Add(esc.Bytes())

	var sl bytes.Buffer
	sw := tar.NewWriter(&sl)
	_ = sw.WriteHeader(&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: "/etc", Mode: 0o777, ModTime: time.Unix(0, 0)})
	_ = sw.WriteHeader(&tar.Header{Name: "evil/passwd", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, ModTime: time.Unix(0, 0)})
	_, _ = sw.Write([]byte("y"))
	_ = sw.Close()
	f.Add(sl.Bytes())

	// A relative symlink escape targets a sibling of dest, so a write that slips
	// through the symlink-parent guard lands inside the scratch dir where the
	// containment walk can actually observe it (an absolute target like /etc fails
	// silently on permissions instead).
	var rel bytes.Buffer
	rw := tar.NewWriter(&rel)
	_ = rw.WriteHeader(&tar.Header{Name: "up", Typeflag: tar.TypeSymlink, Linkname: "../outside", Mode: 0o777, ModTime: time.Unix(0, 0)})
	_ = rw.WriteHeader(&tar.Header{Name: "up/leak.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, ModTime: time.Unix(0, 0)})
	_, _ = rw.Write([]byte("z"))
	_ = rw.Close()
	f.Add(rel.Bytes())

	f.Add([]byte{})
}

// FuzzExtractTar materializes an arbitrary archive into a destination directory the
// way the pull path does (newTreeWriter, nil safe callback) and asserts the containment
// property the whole pack-and-seal extractor exists to guarantee: a hostile server's
// tarball can never write, symlink, or mkdir anything outside the destination root. The
// dest is a subdir of a scratch dir; any file the extractor lands in the scratch dir but
// outside dest is an escape and fails the fuzz.
func FuzzExtractTar(f *testing.F) {
	seedTar(f)
	f.Fuzz(func(t *testing.T, archive []byte) {
		scratch := t.TempDir()
		dest := filepath.Join(scratch, "dest")
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}

		// nil safe mirrors a clone (no local edits to protect): every entry is written,
		// the most aggressive case for the containment guard.
		_, _ = extractTar(newTreeWriter(dest), bytes.NewReader(archive), nil)

		walkAndAssertContained(t, scratch, dest)
	})
}

// FuzzHashTar drives the read-only manifest builder over arbitrary bytes; it writes
// nothing, so the only invariant is that no archive shape panics it.
func FuzzHashTar(f *testing.F) {
	seedTar(f)
	f.Fuzz(func(t *testing.T, archive []byte) {
		_, _ = hashTar(bytes.NewReader(archive))
	})
}

// walkAndAssertContained fails if any path under scratch lands outside dest. It uses
// Lstat semantics (WalkDir does not follow symlinks) so a symlink is checked by its own
// location, not its target.
func walkAndAssertContained(t *testing.T, scratch, dest string) {
	t.Helper()
	err := filepath.WalkDir(scratch, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == scratch || p == dest {
			return nil
		}
		rel, rerr := filepath.Rel(dest, p)
		if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("extractTar wrote %q outside the destination %q", p, dest)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk scratch: %v", err)
	}
}
