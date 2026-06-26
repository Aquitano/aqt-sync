package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestPackSyncE2E drives a pack-and-seal folder (.aqtconfig pack=true) through the
// real CLI and server: init+push, clone, edit and delete propagation, and a
// both-sides conflict. Unlike the chunked path, reconciliation is whole-folder
// last-writer-wins, so even edits to different files collide.
func TestPackSyncE2E(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha")
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	big := make([]byte, (4<<20)+512) // spans more than one segment
	for i := range big {
		big[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(origin, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)

	// A no-op resync of a pack folder uploads nothing (no change to re-ship).
	packsAfterPush := h.countPacks()
	h.sync(origin)
	if got := h.countPacks(); got != packsAfterPush {
		t.Fatalf("no-op pack resync changed pack count: %d -> %d", packsAfterPush, got)
	}

	// Clone reconstructs the tree (including the multi-segment file) byte-for-byte.
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	assertTreeEqual(t, origin, replica)
	if got, _ := os.ReadFile(filepath.Join(replica, "big.bin")); string(got) != string(big) {
		t.Fatal("multi-segment file did not round-trip through clone")
	}

	// An edit on origin propagates to replica through a push then a pull.
	writeTree(t, origin, "notes/todo.txt", "buy milk and eggs")
	h.sync(origin)
	h.sync(replica)
	if got := readTree(t, replica, "notes/todo.txt"); got != "buy milk and eggs" {
		t.Fatalf("edit did not propagate: %q", got)
	}

	// A delete propagates as a delete (the pull prunes it), not a resurrection.
	removeTree(t, origin, "big.bin")
	h.sync(origin)
	h.sync(replica)
	assertAbsent(t, replica, "big.bin")

	// Independent edits to different files still conflict: pack-and-seal reconciles
	// the whole folder at once, so there is no per-file merge.
	writeTree(t, origin, "x.txt", "from origin")
	h.sync(origin)
	writeTree(t, replica, "y.txt", "from replica")
	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected folder-level conflict, got %v", err)
	}

	// --force resolves local-wins: replica's whole tree supersedes origin's, so
	// origin's x.txt is dropped when origin pulls.
	h.syncOpts(replica, syncOptions{force: true})
	h.sync(origin)
	assertAbsent(t, origin, "x.txt")
	if got := readTree(t, origin, "y.txt"); got != "from replica" {
		t.Fatalf("force resolution did not win: %q", got)
	}
	assertTreeEqual(t, origin, replica)
}

// TestPackSyncRefusesMissingBase mirrors the chunked guard for pack folders: a sync
// with no base refuses, and --reconcile rebuilds it when local and remote match.
func TestPackSyncRefusesMissingBase(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "keep.txt", "data")
	h.sync(origin)

	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
		t.Fatal(err)
	}
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errSyncNoBase) {
		t.Fatalf("expected errSyncNoBase, got %v", err)
	}
	h.syncOpts(origin, syncOptions{reconcile: true}) // identical trees: rebuild base
	h.sync(origin)                                   // base restored, plain sync works
}

// TestPackDirectionalFlagsConflict verifies a directional flag does not silently
// discard the other side. When both sides changed since the last sync, --pull-only
// must conflict instead of overwriting and pruning the local working copy, and
// --push-only must conflict instead of clobbering the remote; --force then makes the
// chosen direction an explicit, opted-in resolution.
func TestPackDirectionalFlagsConflict(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "shared.txt", "v0")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Diverge both sides from the cloned base.
	writeTree(t, origin, "shared.txt", "origin edit")
	h.sync(origin)
	writeTree(t, replica, "keep-local.txt", "only on replica")

	// --pull-only would extract origin's tree over the replica and prune the
	// local-only file; it must conflict, and the local work must survive untouched.
	if err := runSync(replica, syncOptions{pullOnly: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("--pull-only with both sides changed: want errConflictsRemain, got %v", err)
	}
	if got := readTree(t, replica, "keep-local.txt"); got != "only on replica" {
		t.Fatalf("--pull-only destroyed local work: %q", got)
	}
	// --push-only would clobber origin's edit; it must conflict too.
	if err := runSync(replica, syncOptions{pushOnly: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("--push-only with both sides changed: want errConflictsRemain, got %v", err)
	}

	// --force --pull-only is the explicit opt-in: the replica takes origin's tree,
	// dropping its own unsynced file.
	h.syncOpts(replica, syncOptions{pullOnly: true, force: true})
	if got := readTree(t, replica, "shared.txt"); got != "origin edit" {
		t.Fatalf("--force --pull-only did not take remote: %q", got)
	}
	assertAbsent(t, replica, "keep-local.txt")
}

// TestPackReconcileNoBaseDiffers covers the baseless --reconcile branch the existing
// missing-base test skips: when local and remote actually differ with no base to
// judge add-vs-delete, it must conflict, and --force resolves local-wins and rebuilds
// a base the next plain sync accepts.
func TestPackReconcileNoBaseDiffers(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "remote value")
	h.sync(origin)

	// Drop the base and change the file so local != remote with nothing to reconcile
	// against.
	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "a.txt", "local value")
	if err := runSync(origin, syncOptions{reconcile: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("baseless reconcile of differing trees: want errConflictsRemain, got %v", err)
	}

	// --force pushes local-wins and rebuilds the base; a fresh clone proves the remote
	// now holds the local value.
	h.syncOpts(origin, syncOptions{reconcile: true, force: true})
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if got := readTree(t, replica, "a.txt"); got != "local value" {
		t.Fatalf("force reconcile did not push local value: %q", got)
	}
}

// TestChunkedSyncRefusesPackedFolder guards the silent tree-wipe: a pack-and-seal
// folder whose local .aqtconfig no longer carries pack=true is routed through the
// chunked sync path. That path must refuse it (the resource metadata says packed),
// not read an empty manifest and delete every local file.
func TestChunkedSyncRefusesPackedFolder(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	writePackConfig(t, dir)
	h.init(dir)
	writeTree(t, dir, "keep.txt", "data")
	writeTree(t, dir, "nested/also.txt", "more")
	h.sync(dir)

	// Drop pack=true so runSync routes this packed folder through the chunked path.
	if err := os.Remove(filepath.Join(dir, ".aqtconfig")); err != nil {
		t.Fatal(err)
	}
	if err := runSync(dir, syncOptions{}); err == nil {
		t.Fatal("chunked sync of a packed folder did not error")
	}
	if got := readTree(t, dir, "keep.txt"); got != "data" {
		t.Fatalf("keep.txt was damaged by the refused sync: %q", got)
	}
	if got := readTree(t, dir, "nested/also.txt"); got != "more" {
		t.Fatalf("nested/also.txt was damaged by the refused sync: %q", got)
	}
}

func TestDecidePack(t *testing.T) {
	cases := []struct {
		name          string
		local, remote bool
		opts          syncOptions
		want          packDecision
	}{
		{"clean", false, false, syncOptions{}, packNoop},
		{"local only", true, false, syncOptions{}, packPush},
		{"remote only", false, true, syncOptions{}, packPull},
		{"both", true, true, syncOptions{}, packConflict},
		{"both forced", true, true, syncOptions{force: true}, packPush},
		// A directional flag must not silently discard the other side: when it also
		// changed, the restricted action is a conflict until --force makes it explicit.
		{"both push-only", true, true, syncOptions{pushOnly: true}, packConflict},
		{"both pull-only", true, true, syncOptions{pullOnly: true}, packConflict},
		{"both push-only forced", true, true, syncOptions{pushOnly: true, force: true}, packPush},
		{"both pull-only forced", true, true, syncOptions{pullOnly: true, force: true}, packPull},
		{"push-only no local", false, true, syncOptions{pushOnly: true}, packNoop},
		{"pull-only no remote", true, false, syncOptions{pullOnly: true}, packNoop},
		{"push-only local only", true, false, syncOptions{pushOnly: true}, packPush},
		{"pull-only remote only", false, true, syncOptions{pullOnly: true}, packPull},
	}
	for _, c := range cases {
		if got := decidePack(c.local, c.remote, c.opts); got != c.want {
			t.Errorf("%s: decidePack(%v,%v) = %d, want %d", c.name, c.local, c.remote, got, c.want)
		}
	}
}

func TestPartitionDeletesByDownload(t *testing.T) {
	downloads := []syncengine.Entry{{Path: "link/inner.txt"}, {Path: "a/b/c.txt"}, {Path: "top.txt"}}
	deletes := []string{"link", "a/b", "top.txt", "unrelated"}

	early, late := partitionDeletesByDownload(deletes, downloads)

	// "link" and "a/b" are ancestors of a download path (a file/symlink became a dir),
	// so they run first. "top.txt" equals a download path but is not an ancestor (a file
	// replaced by a file, handled by rename), and "unrelated" matches nothing.
	wantEarly := map[string]bool{"link": true, "a/b": true}
	for _, p := range early {
		if !wantEarly[p] {
			t.Errorf("unexpected early delete %q", p)
		}
		delete(wantEarly, p)
	}
	if len(wantEarly) != 0 {
		t.Errorf("missing early deletes: %v", wantEarly)
	}
	wantLate := map[string]bool{"top.txt": true, "unrelated": true}
	for _, p := range late {
		if !wantLate[p] {
			t.Errorf("unexpected late delete %q", p)
		}
	}
}

func writePackConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"pack": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
}
