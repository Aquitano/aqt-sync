package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A snapshot taken before a mutation must reconstruct the pre-mutation tree, even
// after the live folder has been rewritten and re-synced. This exercises the full
// path: CreateSnapshot over the wire, the live state moving on (which supersedes the
// snapshotted version), then a client-side reconstruct of the snapshot.
func TestSnapshotRestoreRoundTrip(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "original A")
	writeTree(t, src, "sub/b.txt", "original B")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Mutate and re-sync: the live state moves on, the snapshot must not.
	writeTree(t, src, "a.txt", "CHANGED A")
	removeTree(t, src, "sub/b.txt")
	writeTree(t, src, "c.txt", "new C")
	h.sync(src)

	// The snapshot is listed (account-global browse) at the version it captured.
	snaps, err := cl.ListSnapshots(h.folderID(src))
	if err != nil || len(snaps) != 1 {
		t.Fatalf("list snapshots = %d err=%v, want 1", len(snaps), err)
	}

	// Restore side-by-side into a fresh dir; it must match the pre-mutation tree.
	got, err := cl.GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	if _, err := reconstructSnapshot(cl, prof, got, dest); err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if c := readTree(t, dest, "a.txt"); c != "original A" {
		t.Fatalf("a.txt = %q, want 'original A'", c)
	}
	if c := readTree(t, dest, "sub/b.txt"); c != "original B" {
		t.Fatalf("sub/b.txt = %q, want 'original B'", c)
	}
	assertAbsent(t, dest, "c.txt")
}

// A label set on create is sealed client-side and reads back decrypted on browse,
// without the server ever seeing the plaintext.
func TestSnapshotLabelEndToEnd(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "hi")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	rid := h.folderID(src)
	runCmd(t, snapshotCreateCmd(), src, "milestone-1")

	snaps, err := cl.ListSnapshots(rid)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("list = %d err=%v, want 1", len(snaps), err)
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	if _, label := snapshotNameLabel(snaps[0], mk); label != "milestone-1" {
		t.Fatalf("label = %q, want 'milestone-1'", label)
	}
}

// Pruning a snapshot deletes it; a subsequent fetch is a not-found.
func TestSnapshotPrune(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "hello")
	h.sync(src)

	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := cl.CreateSnapshot(h.folderID(src), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.DeleteSnapshot(snap.ID); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if snaps, err := cl.ListSnapshots(""); err != nil || len(snaps) != 0 {
		t.Fatalf("after prune list = %d err=%v, want 0", len(snaps), err)
	}
}
