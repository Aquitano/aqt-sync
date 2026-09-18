// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// requireCaseSensitiveFS skips a test that must author case-twin paths, which a
// case-insensitive filesystem cannot hold in the first place.
func requireCaseSensitiveFS(t *testing.T) {
	t.Helper()
	if syncengine.CaseInsensitiveDir(t.TempDir()) {
		t.Skip("filesystem folds case; twins cannot be created here")
	}
}

// Two paths differing only by case are legal here but collapse into one file on a
// case-insensitive clone, whose next sync then uploads the survivor's bytes under
// both names. The push is where the trap is armed, so the push is what refuses.
func TestSyncRefusesCaseCollidingPush(t *testing.T) {
	app := &application{ctx: context.Background()}
	requireCaseSensitiveFS(t)
	h := app.newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "Notes.md", "upper")
	writeTree(t, dir, "notes.md", "lower")

	err := app.runSync(dir, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "case-colliding") {
		t.Fatalf("push of case twins: %v", err)
	}

	// Nothing was committed; resolving the twin lets the folder sync clean.
	removeTree(t, dir, "notes.md")
	h.sync(dir)
	replica := t.TempDir()
	h.clone(h.folderID(dir), replica)
	if got := readTree(t, replica, "Notes.md"); got != "upper" {
		t.Fatalf("Notes.md = %q after resolution", got)
	}
	assertAbsent(t, replica, "notes.md")
}

func TestDownloadsRefuseCaseTwinsOnFoldingFS(t *testing.T) {
	t.Setenv("AQT_TEST_CASE_INSENSITIVE", "1")
	entries := []syncengine.Entry{{Path: "A.txt"}, {Path: "a.txt"}}
	_, err := runDownloadsFrom(func(string) ([]byte, error) { return nil, nil }, t.TempDir(), entries, nil)
	if err == nil || !strings.Contains(err.Error(), "case-colliding") {
		t.Fatalf("materializing case twins on a folding filesystem: %v", err)
	}
}

// A filesystem that cannot create symlinks (Windows without Developer Mode) gets
// the rest of the folder, skips the links with a warning, and — critically — does
// not read their absence as a local delete to push: a capable device must still
// see them.
func TestSymlinksDegradeWithoutSupport(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "v1")
	if err := os.Symlink("a.txt", filepath.Join(origin, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	h.sync(origin)

	t.Setenv("AQT_TEST_NO_SYMLINKS", "1")
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if _, err := os.Lstat(filepath.Join(replica, "link")); !os.IsNotExist(err) {
		t.Fatalf("link materialized despite unsupported filesystem: %v", err)
	}
	if got := readTree(t, replica, "a.txt"); got != "v1" {
		t.Fatalf("clone dropped regular files along with the link: %q", got)
	}
	// A round-trip sync from the linkless device must not delete the link remotely.
	writeTree(t, replica, "b.txt", "from replica")
	h.sync(replica)

	t.Setenv("AQT_TEST_NO_SYMLINKS", "")
	other := t.TempDir()
	h.clone(h.folderID(origin), other)
	target, err := os.Readlink(filepath.Join(other, "link"))
	if err != nil || target != "a.txt" {
		t.Fatalf("link lost from the server after a linkless device synced: %v %q", err, target)
	}
	if got := readTree(t, other, "b.txt"); got != "from replica" {
		t.Fatalf("replica's edit did not propagate: %q", got)
	}
}

// Shared clones and subtree pulls must check directory names across the whole
// manifest, including empty directories that never enter a file download batch.
func TestFolderDownloadsRefuseCaseCollidingDirectories(t *testing.T) {
	app := &application{ctx: context.Background()}
	app.newE2E(t)
	cl, prof, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Wipe()
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()
	// Build a remote tree directly, independent of the test machine's filesystem.
	m := syncengine.Manifest{Version: syncengine.TreeManifestVersion, Dirs: []syncengine.DirEntry{
		{Path: "parent", Mode: 0o755}, {Path: "parent/A", Mode: 0o755}, {Path: "parent/a", Mode: 0o755},
	}}
	res, err := app.createFolder(cl, conv, m, ck, mk, "case-twins")
	if err != nil {
		t.Fatal(err)
	}
	link := app.shareFolder(t, res.ID, "", linkPolicy{})
	t.Setenv("AQT_TEST_CASE_INSENSITIVE", "1")
	for _, tc := range []struct {
		name, ref string
		subtree   bool
	}{
		{"owner clone", res.ID, false}, {"shared clone", link, false},
		{"owner subtree", "aqt://" + res.ID + "/parent", true}, {"shared subtree", link + "/parent", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "download")
			var err error
			if tc.subtree {
				err = app.runPull(tc.ref, dest, "", false, false)
			} else {
				err = app.runClone(tc.ref, dest, false, "")
			}
			if err == nil || !strings.Contains(err.Error(), "case-colliding") {
				t.Fatalf("download: %v", err)
			}
			if _, err := os.Lstat(dest); !os.IsNotExist(err) {
				t.Fatalf("failed download left a destination: %v", err)
			}
		})
	}
}
