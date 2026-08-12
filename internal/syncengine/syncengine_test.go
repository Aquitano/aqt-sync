package syncengine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
)

// captureSink records the chunks a snapshot seals so a test can assert what was
// (re)sealed without the snapshot holding ciphertext itself.
type captureSink struct {
	ids   []string
	bytes map[string][]byte
}

func newCaptureSink() *captureSink { return &captureSink{bytes: map[string][]byte{}} }

func (s *captureSink) Add(ch crypto.Chunk, ct []byte) error {
	s.ids = append(s.ids, ch.ID)
	s.bytes[ch.ID] = append([]byte(nil), ct...)
	return nil
}

func testConv(t *testing.T) crypto.ConvergenceKey {
	t.Helper()
	p := cryptotest.KdfParams(t)
	mk, err := crypto.DeriveMasterKey("folder passphrase", p)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.DeriveConvergenceKey(mk)
}

func TestEntryFromBytesRoundTrip(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	defer conv.Wipe()
	data := bytes.Repeat([]byte("merged line with enough content\n"), 500)
	sink := newCaptureSink()
	e, err := EntryFromBytes("notes.md", data, 0o640, conv, DefaultChunkSelector(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if e.Path != "notes.md" || e.Mode != 0o640 || e.Size != int64(len(data)) || len(e.Chunks) == 0 {
		t.Fatalf("entry metadata = %+v", e)
	}
	got, err := FileBytes(e, func(id string) ([]byte, error) { return sink.bytes[id], nil })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("derived entry did not round-trip")
	}
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
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "small.txt", []byte("just a little config"))
	big := bytes.Repeat([]byte("0123456789abcdef"), 8<<10) // 128 KiB
	writeFile(t, dir, "nested/big.bin", big)

	sink := newCaptureSink()
	m, err := Take(dir, testConv(t), DefaultChunker(), nil, sink, false)
	if err != nil {
		t.Fatal(err)
	}

	byPath := m.byPath()
	small, ok := byPath["small.txt"]
	if !ok || small.Inline == nil || len(small.Chunks) != 0 {
		t.Fatalf("small file should be inline, got %+v", small)
	}
	bigEntry, ok := byPath["nested/big.bin"]
	if !ok || len(bigEntry.Chunks) < 2 || bigEntry.Inline != nil {
		t.Fatalf("big file should be chunked, got %d chunks", len(bigEntry.Chunks))
	}
	if len(sink.ids) == 0 {
		t.Fatal("expected sealed chunks for the big file")
	}
}

func TestTakeReusesUnchangedEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := bytes.Repeat([]byte("reuse-me"), 32<<10)
	writeFile(t, dir, "a.bin", big)

	conv := testConv(t)
	first, err := Take(dir, conv, DefaultChunker(), nil, newCaptureSink(), false)
	if err != nil {
		t.Fatal(err)
	}
	// A second snapshot against the first as base must re-seal nothing.
	sink := newCaptureSink()
	second, err := Take(dir, conv, DefaultChunker(), &first, sink, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.ids) != 0 {
		t.Fatalf("unchanged file re-sealed %d chunks", len(sink.ids))
	}
	if len(second.Entries) != 1 {
		t.Fatalf("second snapshot lost entries: %d", len(second.Entries))
	}
}

// The stat fast-path reuses the base entry when size+mode+mtime are unchanged,
// without reading the file — so a content change that preserves all three is not
// seen by default, and --rehash forces the authoritative content read that catches it.
func TestTakeStatFastPathTrustsMtimeUnlessRehash(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	writeFile(t, dir, "a.bin", bytes.Repeat([]byte("fastpath"), 32<<10))
	conv := testConv(t)
	base, err := Take(dir, conv, DefaultChunker(), nil, newCaptureSink(), false)
	if err != nil {
		t.Fatal(err)
	}
	baseEntry, _ := base.Lookup("a.bin")

	// Overwrite with different bytes of the same length, then restore the mtime so
	// size+mode+mtime match the base entry.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "a.bin", bytes.Repeat([]byte("CHANGED!"), 32<<10))
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}

	// Default: trust the stat, reuse the stale entry, read nothing.
	sink := newCaptureSink()
	fast, err := Take(dir, conv, DefaultChunker(), &base, sink, false)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := fast.Lookup("a.bin"); e.Hash != baseEntry.Hash {
		t.Fatalf("fast path hash = %s, want the reused base hash %s", e.Hash, baseEntry.Hash)
	}
	if len(sink.ids) != 0 {
		t.Fatalf("fast path re-sealed %d chunks; it must not read the file", len(sink.ids))
	}

	// --rehash forces the content read, catching the change.
	sink2 := newCaptureSink()
	full, err := Take(dir, conv, DefaultChunker(), &base, sink2, true)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := full.Lookup("a.bin"); e.Hash == baseEntry.Hash {
		t.Fatal("rehash must detect the changed content")
	}
	if len(sink2.ids) == 0 {
		t.Fatal("rehash must re-seal the changed file")
	}
}

// The manifest round-trips through the object store: chunk+seal it, seal the root
// pointer under the content key, then reassemble it from the captured objects.
// A permission-only change (chmod) on otherwise-identical content is a tracked edit:
// the snapshot reuse path must carry the new mode through even though it skips the
// content re-read, and the planner must surface it as an Upload despite an unchanged
// content hash.
func TestModeOnlyChangeSnapshottedAndPlanned(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		// Windows file modes carry no exec/group permission bits, so chmod cannot
		// move a file's recorded mode here; mode propagation is a Unix-only concern.
		t.Skip("file mode bits are not represented on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	writeFile(t, dir, "a.bin", bytes.Repeat([]byte("chmodme"), 32<<10)) // large -> chunked

	conv := testConv(t)
	base, err := Take(dir, conv, DefaultChunker(), nil, newCaptureSink(), false)
	if err != nil {
		t.Fatal(err)
	}
	baseEntry, _ := base.Lookup("a.bin")
	if os.FileMode(baseEntry.Mode).Perm() != 0o644 {
		t.Fatalf("base mode = %o, want 0644", baseEntry.Mode)
	}

	// chmod without touching content, then restore the mtime so the snapshot takes the
	// reuse path (hash matches, no re-seal) rather than re-sealing the file.
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(0, baseEntry.MTime)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}

	sink := newCaptureSink()
	next, err := Take(dir, conv, DefaultChunker(), &base, sink, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.ids) != 0 {
		t.Fatalf("mode-only change re-sealed %d chunks; the reuse path must not re-read", len(sink.ids))
	}
	nextEntry, _ := next.Lookup("a.bin")
	if os.FileMode(nextEntry.Mode).Perm() != 0o755 {
		t.Fatalf("snapshot dropped the new mode: got %o, want 0755", nextEntry.Mode)
	}
	if nextEntry.Hash != baseEntry.Hash {
		t.Fatalf("content hash changed on a mode-only edit: %s -> %s", baseEntry.Hash, nextEntry.Hash)
	}

	var got ActionKind
	for _, a := range Plan(next, base, base) {
		if a.Path == "a.bin" {
			got = a.Kind
		}
	}
	if got != Upload {
		t.Fatalf("mode-only change planned as %q, want %q", got, Upload)
	}
}

func TestIgnoreMatching(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "real.txt", []byte("hello"))
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}

	m, err := Take(dir, testConv(t), DefaultChunker(), nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	link, ok := m.Lookup("link.txt")
	if !ok || !link.IsSymlink() || link.Link != "real.txt" {
		t.Fatalf("symlink not captured as a target: %+v", link)
	}
	if len(link.Chunks) != 0 || link.Inline != nil {
		t.Fatal("a symlink must not be sealed as content")
	}

	// Materialize into a fresh tree and confirm the link is recreated, not followed.
	out := t.TempDir()
	for _, e := range m.Entries {
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
	t.Parallel()
	dir := t.TempDir()
	if err := WriteFile(dir, Entry{Path: "../escape.txt", Mode: 0o600}, []byte("x")); err == nil {
		t.Fatal("a path escaping the tracked root must be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.txt")); err == nil {
		t.Fatal("escape file should not have been written")
	}
}

func TestWriteFileReplacesStaleSymlinkInsteadOfFollowing(t *testing.T) {
	t.Parallel()
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

func TestWriteFileReplacesEmptyDirectoryWithFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// The remote turned a directory into a regular file at the same path; once its
	// children are deleted an empty directory remains, and Rename cannot replace it.
	if err := os.MkdirAll(filepath.Join(root, "foo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(root, Entry{Path: "foo", Mode: 0o600}, []byte("now a file")); err != nil {
		t.Fatalf("write over empty dir: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, "foo"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("foo is %v, want a regular file", fi.Mode())
	}
	if got, _ := os.ReadFile(filepath.Join(root, "foo")); string(got) != "now a file" {
		t.Fatalf("foo content = %q, want now a file", got)
	}
}

func TestWriteFileLeavesNoTempBehind(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
