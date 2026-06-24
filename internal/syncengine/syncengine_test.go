package syncengine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func testConv(t *testing.T) crypto.ConvergenceKey {
	t.Helper()
	p, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := crypto.DeriveMasterKey("folder passphrase", p)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.DeriveConvergenceKey(mk)
}

func writeFile(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTakeInlinesSmallAndChunksLarge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "small.txt", []byte("just a little config"))
	big := bytes.Repeat([]byte("0123456789abcdef"), 8<<10) // 128 KiB
	writeFile(t, dir, "nested/big.bin", big)

	snap, err := Take(dir, testConv(t), DefaultChunker(), nil)
	if err != nil {
		t.Fatal(err)
	}

	byPath := snap.Manifest.byPath()
	small, ok := byPath["small.txt"]
	if !ok || small.Inline == nil || len(small.Chunks) != 0 {
		t.Fatalf("small file should be inline, got %+v", small)
	}
	bigEntry, ok := byPath["nested/big.bin"]
	if !ok || len(bigEntry.Chunks) < 2 || bigEntry.Inline != nil {
		t.Fatalf("big file should be chunked, got %d chunks", len(bigEntry.Chunks))
	}
	if len(snap.NewChunks) == 0 {
		t.Fatal("expected sealed chunks for the big file")
	}
}

func TestTakeReusesUnchangedEntries(t *testing.T) {
	dir := t.TempDir()
	big := bytes.Repeat([]byte("reuse-me"), 32<<10)
	writeFile(t, dir, "a.bin", big)

	conv := testConv(t)
	first, err := Take(dir, conv, DefaultChunker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// A second snapshot against the first as base must re-seal nothing.
	second, err := Take(dir, conv, DefaultChunker(), &first.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.NewChunks) != 0 {
		t.Fatalf("unchanged file re-sealed %d chunks", len(second.NewChunks))
	}
}

func TestManifestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x", bytes.Repeat([]byte("y"), 40<<10))
	snap, err := Take(dir, testConv(t), DefaultChunker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := crypto.GenerateContentKey()
	blob, err := SealManifest(snap.Manifest, ck)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenManifest(blob, ck)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Path != "x" {
		t.Fatalf("manifest round trip lost entries: %+v", got.Entries)
	}
}

func TestIgnoreMatching(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".aqtignore", []byte("*.log\n/build/\nnode_modules\n!keep.log\n"))
	ig, err := LoadIgnore(dir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path  string
		isDir bool
		want  bool
	}{
		{"app.log", false, true},
		{"sub/dir/app.log", false, true},
		{"keep.log", false, false}, // re-included by negation
		{"build", true, true},
		{"src/build", true, false}, // /build/ is anchored to root
		{"node_modules", true, true},
		{"src/node_modules", true, true},
		{"main.go", false, false},
		{".aqt", true, true}, // control dir always ignored
	}
	for _, c := range cases {
		if got := ig.Match(c.path, c.isDir); got != c.want {
			t.Errorf("Match(%q, dir=%v) = %v, want %v", c.path, c.isDir, got, c.want)
		}
	}
}

// .git is ignored by default, but a root `!.git/` re-includes the directory and
// everything under it — the override the init prompt writes when the user opts to
// sync their git history.
func TestIgnoreGitNegation(t *testing.T) {
	def := t.TempDir()
	igDef, err := LoadIgnore(def)
	if err != nil {
		t.Fatal(err)
	}
	if !igDef.Match(".git", true) {
		t.Fatal(".git must be ignored by default")
	}

	tracked := t.TempDir()
	writeFile(t, tracked, ".aqtignore", []byte("!.git/\n"))
	ig, err := LoadIgnore(tracked)
	if err != nil {
		t.Fatal(err)
	}
	if ig.Match(".git", true) {
		t.Fatal("!.git/ must re-include the .git directory")
	}
	if ig.Match(".git/config", false) {
		t.Fatal("!.git/ must re-include files under .git")
	}
}

func TestPlanThreeWay(t *testing.T) {
	mk := func(entries ...Entry) Manifest { return Manifest{Entries: entries} }
	e := func(path, hash string) Entry { return Entry{Path: path, Hash: hash} }

	base := mk(e("keep", "1"), e("edit-local", "1"), e("edit-remote", "1"), e("del-local", "1"), e("del-remote", "1"), e("both", "1"))
	local := mk(e("keep", "1"), e("edit-local", "2"), e("edit-remote", "1"), e("del-remote", "1"), e("both", "2"), e("new-local", "9"))
	remote := mk(e("keep", "1"), e("edit-local", "1"), e("edit-remote", "2"), e("del-local", "1"), e("both", "3"), e("new-remote", "8"))

	got := map[string]ActionKind{}
	for _, a := range Plan(local, base, remote) {
		got[a.Path] = a.Kind
	}
	want := map[string]ActionKind{
		"edit-local":  Upload,       // changed locally, untouched remote
		"edit-remote": Download,     // changed remotely, untouched local
		"del-local":   DeleteRemote, // deleted locally, untouched remote
		"del-remote":  DeleteLocal,  // deleted remotely, untouched local
		"new-local":   Upload,
		"new-remote":  Download,
		"both":        Conflict, // changed both sides to different content
	}
	if len(got) != len(want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Errorf("%s: got %v, want %v", path, got[path], kind)
		}
	}
}

func TestSymlinkSnapshotAndMaterialize(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "real.txt", []byte("hello"))
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}

	snap, err := Take(dir, testConv(t), DefaultChunker(), nil)
	if err != nil {
		t.Fatal(err)
	}
	link, ok := snap.Manifest.Lookup("link.txt")
	if !ok || !link.IsSymlink() || link.Link != "real.txt" {
		t.Fatalf("symlink not captured as a target: %+v", link)
	}
	if len(link.Chunks) != 0 || link.Inline != nil {
		t.Fatal("a symlink must not be sealed as content")
	}

	// Materialize into a fresh tree and confirm the link is recreated, not followed.
	out := t.TempDir()
	for _, e := range snap.Manifest.Entries {
		if e.IsSymlink() {
			if err := WriteSymlink(out, e); err != nil {
				t.Fatal(err)
			}
			continue
		}
		data, err := FileBytes(e, func(string) ([]byte, error) { return nil, fmt.Errorf("unexpected chunk fetch") })
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(out, e, data); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.Readlink(filepath.Join(out, "link.txt"))
	if err != nil || got != "real.txt" {
		t.Fatalf("materialized link target = %q err=%v, want real.txt", got, err)
	}
}

func TestWriteFileRejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, Entry{Path: "../escape.txt", Mode: 0o600}, []byte("x")); err == nil {
		t.Fatal("a path escaping the tracked root must be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.txt")); err == nil {
		t.Fatal("escape file should not have been written")
	}
}

func TestWriteFileReplacesStaleSymlinkInsteadOfFollowing(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim.txt")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stale local symlink points out of the tree. A peer flipping this path from
	// a symlink to a regular file must not let the write land on the link target.
	link := filepath.Join(root, "entry")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}
	if err := WriteFile(root, Entry{Path: "entry", Mode: 0o600}, []byte("new content")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "do not touch" {
		t.Fatalf("write followed the stale symlink to its target: victim = %q", got)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink; the stale link was not replaced")
	}
	if got, _ := os.ReadFile(link); string(got) != "new content" {
		t.Fatalf("entry content = %q, want new content", got)
	}
}

func TestWriteFileLeavesNoTempBehind(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFile(dir, Entry{Path: "nested/file.txt", Mode: 0o640}, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "nested/file.txt"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("content = %q err=%v, want payload", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "nested"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("destination dir has %d entries, want 1 (a staged temp leaked)", len(entries))
	}
}

func TestNestedAqtignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".aqtignore", []byte("*.log\n"))
	writeFile(t, dir, "app.log", []byte("x"))  // ignored by root
	writeFile(t, dir, "keep.txt", []byte("x")) // kept
	// A nested .aqtignore adds rules for its subtree, and can re-include a path
	// the root excluded.
	writeFile(t, dir, "sub/.aqtignore", []byte("secret.*\n!important.log\n"))
	writeFile(t, dir, "sub/secret.key", []byte("x"))    // ignored by the nested file
	writeFile(t, dir, "sub/important.log", []byte("x")) // re-included despite root *.log
	writeFile(t, dir, "sub/notes.txt", []byte("x"))     // kept

	m, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range m.Entries {
		got[e.Path] = true
	}
	for _, p := range []string{"keep.txt", "sub/important.log", "sub/notes.txt"} {
		if !got[p] {
			t.Errorf("expected %q to be tracked", p)
		}
	}
	for _, p := range []string{"app.log", "sub/secret.key"} {
		if got[p] {
			t.Errorf("expected %q to be ignored", p)
		}
	}
}
