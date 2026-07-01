package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// contentHash mirrors how the sync engine hashes a regular file's bytes, so a test
// manifest entry can carry the same hash applySync re-verifies against disk.
func contentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

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

	// Base hashes must match the on-disk bytes: applySync re-verifies a delete target
	// against disk before removing it, so a stale hash would (correctly) be read as a
	// window edit and the delete skipped.
	child := func(p, content string) syncengine.Entry {
		return syncengine.Entry{Path: p, Hash: contentHash(content), Inline: []byte(content)}
	}
	base := syncengine.Manifest{Entries: []syncengine.Entry{child("foo/a", "a"), child("foo/b", "b")}}
	const fileContent = "foo is a regular file now"
	remote := syncengine.Manifest{Entries: []syncengine.Entry{{Path: "foo", Hash: "foo-file", Inline: []byte(fileContent)}}}

	actions := syncengine.Plan(base, base, remote)
	apply := applyCtx{root: root, opts: syncOptions{pullOnly: true}, base: base, local: base, remote: remote}
	if err := applySync(apply, actions, nil); err != nil {
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

// applyTestCtx builds the apply context plus the actions for a pull-only reconcile,
// creating the control dir saveBase needs.
func applyTestCtx(t *testing.T, root string, base, local, remote syncengine.Manifest) (applyCtx, []syncengine.Action) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, syncengine.ControlDir), 0o700); err != nil {
		t.Fatal(err)
	}
	actions := syncengine.Plan(local, base, remote)
	return applyCtx{root: root, opts: syncOptions{pullOnly: true}, base: base, local: local, remote: remote}, actions
}

// A file edited in the snapshot->apply window must not be deleted by a remote delete:
// the on-disk bytes no longer match what the snapshot saw, so the delete is downgraded
// to a conflict and the local edit survives.
func TestApplySyncSkipsDeleteOfWindowEditedFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "f", "edited in the window") // what is actually on disk now

	// The snapshot (and base) recorded the pre-edit content; the remote dropped the file.
	orig := syncengine.Entry{Path: "f", Hash: contentHash("orig"), Inline: []byte("orig")}
	base := syncengine.Manifest{Entries: []syncengine.Entry{orig}}
	apply, actions := applyTestCtx(t, root, base, base, syncengine.Manifest{})

	if err := applySync(apply, actions, nil); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("applySync = %v, want errConflictsRemain", err)
	}
	if got := readTree(t, root, "f"); got != "edited in the window" {
		t.Fatalf("window-edited file was clobbered by the delete: %q", got)
	}
}

// A file edited in the window must not be overwritten by a remote download either.
func TestApplySyncSkipsOverwriteOfWindowEditedFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "g", "edited in the window")

	orig := syncengine.Entry{Path: "g", Hash: contentHash("orig"), Inline: []byte("orig")}
	base := syncengine.Manifest{Entries: []syncengine.Entry{orig}}
	remote := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "g", Hash: contentHash("from remote"), Inline: []byte("from remote")},
	}}
	apply, actions := applyTestCtx(t, root, base, base, remote)

	if err := applySync(apply, actions, nil); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("applySync = %v, want errConflictsRemain", err)
	}
	if got := readTree(t, root, "g"); got != "edited in the window" {
		t.Fatalf("window-edited file was overwritten by the download: %q", got)
	}
}

// The guard must not over-fire: a download whose target still holds the bytes the
// snapshot saw is applied normally.
func TestApplySyncOverwritesUnchangedFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, "g", "orig") // on disk == snapshot

	orig := syncengine.Entry{Path: "g", Hash: contentHash("orig"), Inline: []byte("orig")}
	base := syncengine.Manifest{Entries: []syncengine.Entry{orig}}
	remote := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "g", Hash: contentHash("from remote"), Inline: []byte("from remote")},
	}}
	apply, actions := applyTestCtx(t, root, base, base, remote)

	if err := applySync(apply, actions, nil); err != nil {
		t.Fatalf("applySync = %v, want nil", err)
	}
	if got := readTree(t, root, "g"); got != "from remote" {
		t.Fatalf("unchanged file = %q, want the remote content", got)
	}
}
