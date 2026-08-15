package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	requireCaseSensitiveFS(t)
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "Notes.md", "upper")
	writeTree(t, dir, "notes.md", "lower")

	err := runSync(dir, syncOptions{})
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

func TestPackSyncRefusesCaseCollidingPush(t *testing.T) {
	requireCaseSensitiveFS(t)
	h := newE2E(t)
	dir := t.TempDir()
	writePackConfig(t, dir)
	h.init(dir)
	writeTree(t, dir, "Notes.md", "upper")
	writeTree(t, dir, "notes.md", "lower")

	if err := runSync(dir, syncOptions{}); err == nil || !strings.Contains(err.Error(), "case-colliding") {
		t.Fatalf("pack push of case twins: %v", err)
	}
}

// The pull-side guard: a remote tree holding case twins (written by a pre-guard
// client) must be refused before the first byte lands on a case-folding
// filesystem, not materialized last-writer-wins.
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
	h := newE2E(t)
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

// The same round trip for a pack-and-seal folder: the archive is the whole
// folder, so a push from a linkless device must carry the base's links into the
// tar rather than shipping a tree without them.
func TestPackSymlinksSurviveLinklessDevice(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
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
	writeTree(t, replica, "a.txt", "v2")
	h.sync(replica) // whole-folder push from the linkless device

	t.Setenv("AQT_TEST_NO_SYMLINKS", "")
	other := t.TempDir()
	h.clone(h.folderID(origin), other)
	target, err := os.Readlink(filepath.Join(other, "link"))
	if err != nil || target != "a.txt" {
		t.Fatalf("pack push from a linkless device dropped the link: %v %q", err, target)
	}
	if got := readTree(t, other, "a.txt"); got != "v2" {
		t.Fatalf("edit did not ship: %q", got)
	}
}
