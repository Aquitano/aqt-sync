package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
		{"both push-only", true, true, syncOptions{pushOnly: true}, packPush},
		{"both pull-only", true, true, syncOptions{pullOnly: true}, packPull},
		{"push-only no local", false, true, syncOptions{pushOnly: true}, packNoop},
		{"pull-only no remote", true, false, syncOptions{pullOnly: true}, packNoop},
	}
	for _, c := range cases {
		if got := decidePack(c.local, c.remote, c.opts); got != c.want {
			t.Errorf("%s: decidePack(%v,%v) = %d, want %d", c.name, c.local, c.remote, got, c.want)
		}
	}
}

func writePackConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"pack": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
}
