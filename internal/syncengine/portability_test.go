// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"io/fs"
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
	if got := CaseCollisions([]Entry{{Path: "caf\u00e9"}, {Path: "cafe\u0301"}}, nil); len(got) != 1 {
		t.Errorf("normalization twins reported %v, want one group", got)
	}
	if got := CaseCollisions([]Entry{{Path: "notes"}, {Path: "Notes. "}, {Path: "d./x"}}, []DirEntry{{Path: "d"}}); len(got) != 1 || len(got[0]) != 2 {
		t.Errorf("trailing dot and space twins reported %v, want one pair", got)
	}
	if got := CaseCollisions([]Entry{{Path: "d./x"}, {Path: "d/x"}}, nil); len(got) != 1 {
		t.Errorf("twins under a trailing-dot directory reported %v, want one group", got)
	}
}

func TestBackslashPaths(t *testing.T) {
	got := BackslashPaths([]Entry{{Path: `z\b`}, {Path: "plain"}}, []DirEntry{{Path: `a\dir`}})
	if strings.Join(got, ",") != `a\dir,z\b` {
		t.Errorf("BackslashPaths = %q", got)
	}
}

// Go reports a Windows junction as ModeIrregular without ModeDir; the symlink
// guards must treat it as a link. A cloud-placeholder directory carries ModeDir too
// and stays an ordinary directory.
func TestLinkLike(t *testing.T) {
	cases := []struct {
		mode fs.FileMode
		want bool
	}{
		{fs.ModeSymlink, true},
		{fs.ModeIrregular, true},
		{fs.ModeDir | fs.ModeIrregular, false},
		{fs.ModeDir, false},
		{0, false},
		{fs.ModeNamedPipe, false},
	}
	for _, c := range cases {
		if got := linkLike(c.mode); got != c.want {
			t.Errorf("linkLike(%v) = %v, want %v", c.mode, got, c.want)
		}
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
