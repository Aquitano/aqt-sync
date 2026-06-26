package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestApplySyncReplacesDirectoryWithFile pulls a remote change that swaps a
// directory foo/ (holding foo/a, foo/b) for a regular file at foo. Plan emits
// Download{foo} plus DeleteLocal of the two children, which are descendants of the
// download target. They must run before foo is materialized, or the download
// renames onto the still-populated directory and fails (EISDIR/ENOTEMPTY), wedging
// the sync. The whole pull must complete and leave foo a regular file.
func TestApplySyncReplacesDirectoryWithFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, syncengine.ControlDir), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, "foo/a", "a")
	writeTree(t, root, "foo/b", "b")

	child := func(p string) syncengine.Entry {
		return syncengine.Entry{Path: p, Hash: p, Inline: []byte(p)}
	}
	base := syncengine.Manifest{Entries: []syncengine.Entry{child("foo/a"), child("foo/b")}}
	const fileContent = "foo is a regular file now"
	remote := syncengine.Manifest{Entries: []syncengine.Entry{{Path: "foo", Hash: "foo-file", Inline: []byte(fileContent)}}}

	actions := syncengine.Plan(base, base, remote)
	apply := applyCtx{root: root, opts: syncOptions{pullOnly: true}, base: base, local: base, remote: remote}
	if err := applySync(apply, actions); err != nil {
		t.Fatalf("applySync: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(root, "foo"))
	if err != nil {
		t.Fatalf("stat foo: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("foo is %v, want a regular file", fi.Mode())
	}
	if got := readTree(t, root, "foo"); got != fileContent {
		t.Fatalf("foo content = %q, want %q", got, fileContent)
	}
	for _, child := range []string{"foo/a", "foo/b"} {
		if _, err := os.Stat(filepath.Join(root, child)); err == nil {
			t.Fatalf("%s still present after sync", child)
		}
	}
}
