// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
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
