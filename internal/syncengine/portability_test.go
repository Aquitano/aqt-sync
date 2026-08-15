// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseCollisions(t *testing.T) {
	entries := []Entry{
		{Path: "Notes.md"}, {Path: "notes.md"},
		{Path: "docs/readme"}, {Path: "unique.txt"},
	}
	dirs := []DirEntry{{Path: "Docs"}, {Path: "docs"}}
	groups := CaseCollisions(entries, dirs)
	if len(groups) != 2 {
		t.Fatalf("groups = %v, want 2", groups)
	}
	if got := strings.Join(groups[0], "/"); got != "Docs/docs" {
		t.Errorf("first group = %q", got)
	}
	if got := strings.Join(groups[1], "/"); got != "Notes.md/notes.md" {
		t.Errorf("second group = %q", got)
	}
	if got := CaseCollisions(entries[2:], nil); len(got) != 0 {
		t.Errorf("clean set reported %v", got)
	}
}

// A tar carrying case-twins must be refused before the second write on a
// case-folding destination, naming both paths — extracting it would collapse the
// pair into one file with whichever content streamed last.
func TestExtractRefusesCaseTwinsOnFoldingFS(t *testing.T) {
	// The twins must first exist on disk to be archived, which needs a real
	// case-sensitive filesystem; only the destination's folding is simulated.
	if CaseInsensitiveDir(t.TempDir()) {
		t.Skip("filesystem folds case; twins cannot be created here")
	}
	t.Setenv("AQT_TEST_CASE_INSENSITIVE", "1")
	src := t.TempDir()
	// Legal on the case-sensitive filesystem this test builds the archive on.
	if err := os.WriteFile(filepath.Join(src, "Notes.md"), []byte("upper"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "notes.md"), []byte("lower"), 0o644); err != nil {
		t.Fatal(err)
	}
	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ExtractToTree(t.TempDir(), root, ck, store.get, nil)
	if err == nil || !strings.Contains(err.Error(), "case-colliding") {
		t.Fatalf("extract of case twins: %v", err)
	}
}

// A base symlink the walk cannot see is kept only when the filesystem cannot
// create links at all; on one that can, its absence is an ordinary delete.
func TestKeepUnsupportedLinks(t *testing.T) {
	base := &Manifest{Entries: []Entry{
		{Path: "link", Link: "target", Hash: linkHash("target")},
		{Path: "file.txt", Hash: "abc"},
	}}
	dir := t.TempDir()

	t.Setenv("AQT_TEST_NO_SYMLINKS", "1")
	m := Manifest{Entries: []Entry{{Path: "file.txt", Hash: "abc"}}}
	keepUnsupportedLinks(&m, base, dir)
	if len(m.Entries) != 2 {
		t.Fatalf("link not kept on a linkless filesystem: %v", m.Entries)
	}

	t.Setenv("AQT_TEST_NO_SYMLINKS", "")
	m = Manifest{Entries: []Entry{{Path: "file.txt", Hash: "abc"}}}
	keepUnsupportedLinks(&m, base, dir)
	if len(m.Entries) != 1 {
		t.Fatalf("deleted link resurrected on a capable filesystem: %v", m.Entries)
	}
}

// The extract records a link it cannot write as skipped-but-present, so the
// caller's base keeps it and the next scan does not read absence as a delete.
func TestExtractSkipsLinksWithoutSupport(t *testing.T) {
	t.Setenv("AQT_TEST_NO_SYMLINKS", "1")
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(src, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	ck := testContentKey(t)
	store := memObjects{}
	root, _, err := TarAndSeal(src, ck, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	m, err := ExtractToTree(dst, root, ck, store.get, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "link")); !os.IsNotExist(err) {
		t.Fatalf("link written despite unsupported filesystem: %v", err)
	}
	var linkRecorded bool
	for _, e := range m.Entries {
		if e.Path == "link" {
			linkRecorded = true
		}
	}
	if !linkRecorded {
		t.Fatal("skipped link missing from the manifest; the next scan would push its deletion")
	}
	if len(m.Skipped) != 1 || m.Skipped[0].Path != "link" {
		t.Fatalf("skip not reported: %+v", m.Skipped)
	}
}
