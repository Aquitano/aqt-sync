package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestSplitRefPath(t *testing.T) {
	cases := []struct {
		ref, base, sub string
	}{
		{"aqt://abc123", "aqt://abc123", ""},
		{"aqt://abc123/", "aqt://abc123", ""},
		{"aqt://abc123/docs/notes.txt", "aqt://abc123", "docs/notes.txt"},
		{"abc123", "abc123", ""},
		{"https://host/x/abc123#key", "https://host/x/abc123#key", ""},
		{"aqt://abc123/docs#frag", "aqt://abc123#frag", "docs"},
	}
	for _, c := range cases {
		base, sub := splitRefPath(c.ref)
		if base != c.base || sub != c.sub {
			t.Errorf("splitRefPath(%q) = %q, %q; want %q, %q", c.ref, base, sub, c.base, c.sub)
		}
	}
}

// subpathFixture syncs a folder with a nested tree and returns its resource id.
func subpathFixture(t *testing.T, h *e2eHarness) (src, id string) {
	t.Helper()
	src = filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "docs/notes.txt", "hello subpath")
	writeTree(t, src, "docs/deep/more.txt", "deeper content")
	writeTree(t, src, "big.bin", strings.Repeat("chunky data ", 20000)) // large enough to chunk
	writeTree(t, src, "top.txt", "at the root")
	h.sync(src)
	return src, h.folderID(src)
}

func TestPullSubpathSingleFile(t *testing.T) {
	h := newE2E(t)
	_, id := subpathFixture(t, h)

	dest := filepath.Join(t.TempDir(), "out.txt")
	if err := runPull("aqt://"+id+"/docs/notes.txt", dest, "", false, false); err != nil {
		t.Fatalf("pull subpath: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "hello subpath" {
		t.Fatalf("pulled %q, %v; want %q", got, err, "hello subpath")
	}

	// A chunked file streams from its packs the same way.
	destBig := filepath.Join(t.TempDir(), "big.bin")
	if err := runPull("aqt://"+id+"/big.bin", destBig, "", false, false); err != nil {
		t.Fatalf("pull chunked subpath: %v", err)
	}
	if got, err := os.ReadFile(destBig); err != nil || string(got) != strings.Repeat("chunky data ", 20000) {
		t.Fatalf("chunked pull corrupt (len %d, err %v)", len(got), err)
	}

	if err := runPull("aqt://"+id+"/docs/missing.txt", filepath.Join(t.TempDir(), "x"), "", false, false); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing subpath err = %v, want path-not-found", err)
	}
}

func TestPullSubpathDirectory(t *testing.T) {
	h := newE2E(t)
	_, id := subpathFixture(t, h)

	dest := filepath.Join(t.TempDir(), "docs-copy")
	if err := runPull("aqt://"+id+"/docs", dest, "", false, false); err != nil {
		t.Fatalf("pull subtree: %v", err)
	}
	if got := readTree(t, dest, "notes.txt"); got != "hello subpath" {
		t.Errorf("notes.txt = %q", got)
	}
	if got := readTree(t, dest, "deep/more.txt"); got != "deeper content" {
		t.Errorf("deep/more.txt = %q", got)
	}
	// Only the subtree lands: siblings of /docs must not appear.
	if _, err := os.Stat(filepath.Join(dest, "top.txt")); !os.IsNotExist(err) {
		t.Error("pulling /docs materialized a sibling from the folder root")
	}

	// cat of a directory is refused with guidance rather than dumping bytes.
	if err := runPull("aqt://"+id+"/docs", "", "", true, false); err == nil ||
		!strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("cat of a directory err = %v, want refusal", err)
	}
}

func TestPullFolderWithoutSubpathIsGuided(t *testing.T) {
	h := newE2E(t)
	_, id := subpathFixture(t, h)
	err := runPull("aqt://"+id, "", "", true, false)
	if err == nil || !strings.Contains(err.Error(), "is a folder") {
		t.Fatalf("pull of a folder err = %v, want folder guidance", err)
	}
}

func TestLsFolderSubpath(t *testing.T) {
	h := newE2E(t)
	_, id := subpathFixture(t, h)
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	rows, err := collectFolderRows(cl, mk, "aqt://"+id, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{".aqtignore": "file", "big.bin": "file", "docs": "dir", "top.txt": "file"}
	if len(rows) != len(want) {
		t.Fatalf("root rows = %+v, want %d entries", rows, len(want))
	}
	for _, r := range rows {
		if want[r.Name] != r.Type {
			t.Errorf("row %s type = %s, want %s", r.Name, r.Type, want[r.Name])
		}
	}

	// The same path can ride in the ref or the extra arg.
	sub, err := collectFolderRows(cl, mk, "aqt://"+id+"/docs", "")
	if err != nil {
		t.Fatal(err)
	}
	viaArg, err := collectFolderRows(cl, mk, "aqt://"+id, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if len(sub) != 2 || len(viaArg) != 2 {
		t.Fatalf("docs rows = %+v / %+v, want 2 entries each", sub, viaArg)
	}

	// A file path lists the single entry.
	one, err := collectFolderRows(cl, mk, "aqt://"+id+"/docs/notes.txt", "")
	if err != nil || len(one) != 1 || one[0].Type != string(syncengine.ChildFile) {
		t.Fatalf("file row = %+v, %v; want one file entry", one, err)
	}

	if _, err := collectFolderRows(cl, mk, "aqt://"+id+"/nope", ""); err == nil ||
		!strings.Contains(err.Error(), "not found") {
		t.Fatalf("ls of missing path err = %v, want path-not-found", err)
	}
}
