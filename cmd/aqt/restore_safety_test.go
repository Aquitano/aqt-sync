// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func writeConflictsCopyConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"conflicts": "copy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An in-place restore of a tree whose own .aqtconfig selects conflicts=copy used to
// wedge after the swap: the internal propagation sync runs with force, which the
// config's copy mode contradicts — a flag conflict the user never caused. The
// propagation sync pins conflicts=block instead (issue #183).
func TestInPlaceRestoreWithConflictsCopyConfig(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeConflictsCopyConfig(t, src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, "a.txt", "changed")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	if c := readTree(t, src, "a.txt"); c != "original" {
		t.Fatalf("a.txt = %q after restore", c)
	}
	// A completed restore leaves no marker behind.
	if _, err := os.Stat(controlPath(src, restoreMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("restore marker left behind: %v", err)
	}
}

// An in-place restore replaces what syncs and nothing else. A .git directory and a
// file .aqtignore keeps local are in no snapshot, so swapping the whole old tree out
// and deleting it would destroy the only copy of them.
func TestInPlaceRestoreKeepsUntrackedFiles(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, ".aqtignore", "local.env\n")
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, "a.txt", "changed")
	writeTree(t, src, "local.env", "TOKEN=only-here")
	writeTree(t, src, ".git/HEAD", "ref: refs/heads/main\n")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	for path, want := range map[string]string{
		"a.txt":     "original",
		"local.env": "TOKEN=only-here",
		".git/HEAD": "ref: refs/heads/main\n",
	} {
		if got := readTree(t, src, path); got != want {
			t.Fatalf("%s = %q after restore, want %q", path, got, want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*")); len(left) != 0 {
		t.Fatalf("restore left a backup behind: %v", left)
	}
}

func TestInPlaceRestoreThroughRootSymlinkKeepsLocalPaths(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	parent := t.TempDir()
	src, alias := filepath.Join(parent, "root"), filepath.Join(parent, "alias")
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, ".aqtignore", "local.env\n")
	writeTree(t, src, "a.txt", "checkpoint contents")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)
	writeTree(t, src, "a.txt", "changed")
	writeTree(t, src, "local.env", "only copy of secret")
	writeTree(t, src, ".git/HEAD", "only git metadata")
	if err := os.Symlink(src, alias); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	runCmd(t, app.restoreCmd(), "pin", alias, "--in-place", "-y")
	for rel, want := range map[string]string{"local.env": "only copy of secret", ".git/HEAD": "only git metadata"} {
		if got := readTree(t, src, rel); got != want {
			t.Fatalf("local %s = %q, want %q", rel, got, want)
		}
	}
	left, err := filepath.Glob(filepath.Join(parent, ".aqt-backup-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("unexpected retained backup: %v, %v", left, err)
	}
	replica := t.TempDir()
	h.clone(h.folderID(src), replica)
	if got := readTree(t, replica, "a.txt"); got != "checkpoint contents" {
		t.Fatalf("restored replica = %q, want checkpoint contents", got)
	}
	assertAbsent(t, replica, "local.env")
	assertAbsent(t, replica, ".git")
}

// A snapshot taken before a file was ignored restores an .aqtignore that tracks it.
// Moving that file back would let the restore's propagation sync publish it, so it
// stays in the backup.
func TestInPlaceRestoreKeepsUntrackedFromRestoredRules(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	writeTree(t, src, ".aqtignore", "local.env\n")
	writeTree(t, src, "local.env", "TOKEN=only-here")
	h.sync(src)

	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	assertAbsent(t, src, "local.env")
	other := filepath.Join(t.TempDir(), "other")
	h.clone(h.folderID(src), other)
	assertAbsent(t, other, "local.env")
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
	if len(left) != 1 || readTree(t, left[0], "local.env") != "TOKEN=only-here" {
		t.Fatalf("local.env was not kept in the backup: %v", left)
	}
}

func TestInPlaceRestoreKeepsIgnoredRulesOutOfRestoredTree(t *testing.T) {
	for _, name := range []string{".aqtignore", ".AQTIGNORE"} {
		t.Run(name, func(t *testing.T) {
			app := &application{ctx: context.Background()}
			h := app.newE2E(t)
			src := t.TempDir()
			h.init(src)
			rules := "nested/" + name
			writeTree(t, src, ".aqtignore", rules+"\n")
			writeTree(t, src, "nested/data.txt", "checkpoint contents")
			h.sync(src)
			runCmd(t, app.checkpointCmd(), "pin", src)

			writeTree(t, src, rules, "*.txt\n")
			h.sync(src)
			runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
			assertAbsent(t, src, rules)
			left, err := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
			if err != nil || len(left) != 1 {
				t.Fatalf("expected retained backup: %v, %v", left, err)
			}
			if got := readTree(t, left[0], rules); got != "*.txt\n" {
				t.Fatalf("retained local ignore rules = %q", got)
			}
			replica := t.TempDir()
			h.clone(h.folderID(src), replica)
			if got := readTree(t, replica, "nested/data.txt"); got != "checkpoint contents" {
				t.Fatalf("restored replica = %q, want checkpoint contents", got)
			}
		})
	}
}

func TestInPlaceRestoreKeepsUntrackedFromOriginalSymlinkRules(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, ".aqtignore", "# initial rules\n")
	writeTree(t, src, "a.txt", "checkpoint contents")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	if err := os.Remove(filepath.Join(src, ".aqtignore")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(src, "rules"), filepath.Join(src, ".aqtignore")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	writeTree(t, src, "rules", "local.env\n")
	writeTree(t, src, "local.env", "only copy of secret")
	h.sync(src)
	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	assertAbsent(t, src, "local.env")
	left, err := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
	if err != nil || len(left) != 1 {
		t.Fatalf("expected retained backup: %v, %v", left, err)
	}
	if got := readTree(t, left[0], "local.env"); got != "only copy of secret" {
		t.Fatalf("retained local.env = %q", got)
	}
	replica := t.TempDir()
	h.clone(h.folderID(src), replica)
	assertAbsent(t, replica, "local.env")
	if got := readTree(t, replica, "a.txt"); got != "checkpoint contents" {
		t.Fatalf("restored replica = %q, want checkpoint contents", got)
	}
}

func TestInPlaceRestoreKeepsLinkedIgnoreTargetsInBackup(t *testing.T) {
	for _, target := range []string{"local.rules", "local/rules"} {
		t.Run(target, func(t *testing.T) {
			app := &application{ctx: context.Background()}
			h := app.newE2E(t)
			src := t.TempDir()
			h.init(src)
			writeTree(t, src, ".aqtignore", "nested/local*\n")
			writeTree(t, src, "nested/data.txt", "checkpoint contents")
			if err := os.Symlink(filepath.FromSlash(target), filepath.Join(src, "nested/.aqtignore")); err != nil {
				t.Skipf("symlinks unsupported: %v", err)
			}
			h.sync(src)
			runCmd(t, app.checkpointCmd(), "pin", src)

			rules := "nested/" + target
			writeTree(t, src, rules, "*.txt\n")
			h.sync(src)
			runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
			assertAbsent(t, src, rules)
			left, err := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
			if err != nil || len(left) != 1 {
				t.Fatalf("expected retained backup: %v, %v", left, err)
			}
			if got := readTree(t, left[0], rules); got != "*.txt\n" {
				t.Fatalf("retained symlink target = %q", got)
			}
			replica := t.TempDir()
			h.clone(h.folderID(src), replica)
			if got := readTree(t, replica, "nested/data.txt"); got != "checkpoint contents" {
				t.Fatalf("restored replica = %q, want checkpoint contents", got)
			}
		})
	}
}

func TestInPlaceRestoreKeepsNonUTF8Paths(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, app.checkpointCmd(), "pin", src)

	badFile, badDir := "local-\xff", "dir-\xfe"
	if err := os.WriteFile(filepath.Join(src, badFile), []byte("only copy"), 0o600); err != nil {
		t.Skipf("filesystem rejects non-UTF-8 names: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	stored := false
	for _, e := range entries {
		stored = stored || !utf8.ValidString(e.Name())
	}
	if !stored {
		t.Skip("filesystem normalized the non-UTF-8 name")
	}
	writeTree(t, src, badDir+"/nested.txt", "another only copy")
	writeTree(t, src, "a.txt", "changed")
	runCmd(t, app.restoreCmd(), "pin", src, "--in-place", "-y")
	left, err := filepath.Glob(filepath.Join(filepath.Dir(src), ".aqt-backup-*"))
	if err != nil || len(left) != 1 {
		t.Fatalf("expected retained backup: %v, %v", left, err)
	}
	for rel, want := range map[string]string{badFile: "only copy", badDir + "/nested.txt": "another only copy"} {
		if got := readTree(t, left[0], rel); got != want {
			t.Fatalf("backup %q = %q, want %q", rel, got, want)
		}
	}
	h.sync(src)
	replica := t.TempDir()
	h.clone(h.folderID(src), replica)
	if got := readTree(t, replica, "a.txt"); got != "original" {
		t.Fatalf("restored replica = %q, want original", got)
	}
}

func TestRestoreStagingStaysOutOfParentScan(t *testing.T) {
	parent := t.TempDir()
	writeTree(t, parent, ".aqtignore", "work/\n")
	dest := filepath.Join(parent, ".aqt-restore-test")
	if err := materializeStaged(dest, func(staging string) error {
		writeTree(t, staging, "past-secret.txt", "restored snapshot contents")
		manifest, err := syncengine.Scan(parent)
		if err != nil {
			return err
		}
		for _, entry := range manifest.Entries {
			if entry.Path != ".aqtignore" {
				t.Fatalf("parent scan includes inner restore staging at %s", entry.Path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manifest, err := syncengine.Scan(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		if entry.Path != ".aqtignore" {
			t.Fatalf("parent scan includes outer restore staging at %s", entry.Path)
		}
	}
}

func TestRetainedRestoreBackupStaysOutOfParentScan(t *testing.T) {
	parent := t.TempDir()
	root, staging := filepath.Join(parent, "work"), filepath.Join(parent, ".aqt-restore-test")
	writeTree(t, root, ".aqtignore", "local.env\n")
	writeTree(t, root, "local.env", "TOKEN=only-here")
	writeTree(t, root, "tracked.txt", "old")
	writeTree(t, staging, "tracked.txt", "restored")
	if err := swapTree(root, staging); err != nil {
		t.Fatal(err)
	}
	left, err := filepath.Glob(filepath.Join(parent, ".aqt-backup-*"))
	if err != nil || len(left) != 1 {
		t.Fatalf("expected retained backup: %v, %v", left, err)
	}
	manifest, err := syncengine.Scan(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range manifest.Entries {
		if strings.HasPrefix(entry.Path, filepath.Base(left[0])+"/") {
			t.Fatalf("parent scan includes retained backup at %s", entry.Path)
		}
	}
	if got := readTree(t, left[0], "local.env"); got != "TOKEN=only-here" {
		t.Fatalf("retained local.env = %q", got)
	}
}

// A snapshot can hold a symlink where the live tree has a directory. An ignored file
// in that directory stays in the backup instead of following the link out of the folder.
func TestInPlaceRestoreKeepsUntrackedOutOfSymlinks(t *testing.T) {
	parent, outside := t.TempDir(), t.TempDir()
	root, staging := filepath.Join(parent, "work"), filepath.Join(parent, "staging")
	writeTree(t, root, ".aqtignore", "*.env\n")
	writeTree(t, root, "a/local.env", "TOKEN=only-here")
	writeTree(t, staging, ".aqtignore", "*.env\n")
	if err := os.Symlink(outside, filepath.Join(staging, "a")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	if err := swapTree(root, staging); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "local.env")); !os.IsNotExist(err) {
		t.Fatalf("local.env followed the restored symlink out of the folder: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(parent, ".aqt-backup-*"))
	if len(left) != 1 || readTree(t, left[0], "a/local.env") != "TOKEN=only-here" {
		t.Fatalf("local.env was not kept in the backup: %v", left)
	}
}

// Adopting a clone whose synced .aqtconfig selects conflicts=copy used to wedge the
// internal reconcile the same way (copy contradicts --reconcile); it pins block too.
func TestAdoptWithConflictsCopyConfig(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeConflictsCopyConfig(t, origin)
	writeTree(t, origin, "a.txt", "same content")
	h.sync(origin)
	id := h.folderID(origin)

	adoptee := t.TempDir()
	copyTreeExclAqt(t, origin, adoptee)
	if err := app.runClone(id, adoptee, true, ""); err != nil {
		t.Fatalf("adopt with conflicts=copy config: %v", err)
	}
	if got := h.folderID(adoptee); got != id {
		t.Fatalf("adoptee tracks %s, want %s", got, id)
	}
}

// A kill mid-swap leaves a half-emptied root; the marker written before the swap
// must make the next sync refuse with recovery guidance instead of scanning the
// carnage as local deletions and pushing them fleet-wide.
func TestSyncRefusesAfterInterruptedRestoreSwap(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "x")
	h.sync(src)

	if err := writeMarker(src, restoreMarkerFile, interruptedRestore{SnapshotID: "snapXYZ"}); err != nil {
		t.Fatal(err)
	}
	err := app.runSync(src, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "restore") || !strings.Contains(err.Error(), "snapXYZ") {
		t.Fatalf("sync with restore marker: %v", err)
	}

	if err := clearMarker(src, restoreMarkerFile); err != nil {
		t.Fatal(err)
	}
	h.sync(src)
}
