package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// supersede replaces a resource's manifest with one referencing a different object
// set, bumping its version and dropping its old chunk roots — what a sync that
// rewrote the folder does. Without a snapshot, the old objects become reclaimable.
func (s *Store) supersede(t *testing.T, owner, id string, refs []string) {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("new manifest"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"folder","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	if _, _, err := s.PutResource(owner, api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, ChunkRefs: refs,
	}); err != nil {
		t.Fatalf("supersede resource: %v", err)
	}
}

// A snapshot must keep its objects alive through both a GC sweep and a repack after
// the resource that referenced them has moved on. This is the core safety property:
// the GC root queries union snapshot_chunks, so a chunk only a snapshot needs is
// neither swept nor dropped during compaction.
func TestSnapshotPinsChunksThroughGCAndRepack(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "snap@example.com")

	// packA holds the snapshotted object plus a large dead sibling, so the pack is
	// >50% dead and RepackOwner rewrites it. packC is the object the resource moves to.
	packA, dataA, idsA := packOf("snapshot target", strings.Repeat("x", 8192))
	packC, dataC, idsC := packOf("post-supersede object")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(owner, packC, dataC, 0); err != nil {
		t.Fatal(err)
	}

	rid := s.rootResource(t, owner, []string{idsA[0]})
	snap, err := s.CreateSnapshot(owner, rid, nil)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// The resource now references a different object; idsA[0] is rooted only by the
	// snapshot.
	s.supersede(t, owner, rid, []string{idsC[0]})

	if _, _, err := s.GCPacks(owner, forceGC); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RepackOwner(owner, forceGC); err != nil {
		t.Fatal(err)
	}

	// The snapshot-pinned object survived sweep and repack (it may have moved packs)
	// with its ciphertext intact.
	if missing, _ := s.MissingChunks(owner, []string{idsA[0]}); len(missing) != 0 {
		t.Fatal("snapshot-pinned object was reclaimed by GC/repack")
	}
	if got := s.readLocated(t, owner, idsA[0]); string(got) != "snapshot target" {
		t.Fatalf("pinned object bytes = %q, want 'snapshot target'", got)
	}

	// The snapshot's root blob is still fetchable after the resource was rewritten.
	got, err := s.GetSnapshot(owner, snap.ID)
	if err != nil {
		t.Fatalf("get snapshot after supersede: %v", err)
	}
	if len(got.Blob.Ciphertext) == 0 {
		t.Fatal("snapshot blob empty")
	}

	// Dropping the snapshot unroots the object; the next sweep reclaims it.
	if err := s.DeleteSnapshot(owner, snap.ID); err != nil {
		t.Fatalf("delete snapshot: %v", err)
	}
	if _, _, err := s.GCPacks(owner, forceGC); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RepackOwner(owner, forceGC); err != nil {
		t.Fatal(err)
	}
	if missing, _ := s.MissingChunks(owner, []string{idsA[0]}); len(missing) != 1 {
		t.Fatal("object should be reclaimed once the snapshot pinning it is gone")
	}
}

// Deleting the source resource entirely must not take its snapshots with it: this is
// the protection against a sync-propagated delete.
func TestSnapshotSurvivesResourceDelete(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "del@example.com")
	packA, dataA, idsA := packOf("kept by snapshot")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{idsA[0]})
	snap, err := s.CreateSnapshot(owner, rid, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteResource(owner, rid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GCPacks(owner, forceGC); err != nil {
		t.Fatal(err)
	}

	if missing, _ := s.MissingChunks(owner, []string{idsA[0]}); len(missing) != 0 {
		t.Fatal("snapshot must keep a deleted resource's objects alive")
	}
	got, err := s.GetSnapshot(owner, snap.ID)
	if err != nil {
		t.Fatalf("get snapshot after resource delete: %v", err)
	}
	if len(got.Blob.Ciphertext) == 0 {
		t.Fatal("snapshot blob empty")
	}
}

// The scheduled job snapshots a resource once per version: a second run with nothing
// changed is a no-op, a new version becomes due again, and an opt-out excludes it.
func TestRunAutoSnapshotsDedupsByVersion(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "auto@example.com")
	packA, dataA, idsA := packOf("v1 object")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{idsA[0]})

	if n, err := s.RunAutoSnapshots(); err != nil || n != 1 {
		t.Fatalf("first auto run: n=%d err=%v, want 1", n, err)
	}
	if n, err := s.RunAutoSnapshots(); err != nil || n != 0 {
		t.Fatalf("second auto run: n=%d err=%v, want 0 (version unchanged)", n, err)
	}

	packB, dataB, idsB := packOf("v2 object")
	if _, err := s.PutPack(owner, packB, dataB, 0); err != nil {
		t.Fatal(err)
	}
	s.supersede(t, owner, rid, []string{idsB[0]})
	if n, err := s.RunAutoSnapshots(); err != nil || n != 1 {
		t.Fatalf("after change: n=%d err=%v, want 1", n, err)
	}

	packD, dataD, idsD := packOf("v3 object")
	if _, err := s.PutPack(owner, packD, dataD, 0); err != nil {
		t.Fatal(err)
	}
	s.supersede(t, owner, rid, []string{idsD[0]})
	if err := s.SetAutoSnapshot(owner, rid, false); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RunAutoSnapshots(); err != nil || n != 0 {
		t.Fatalf("opted-out run: n=%d err=%v, want 0", n, err)
	}

	snaps, err := s.ListSnapshots(owner, rid)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2 (v1 and v2)", len(snaps))
	}
}

// PruneAutoSnapshots is the retention cap that keeps the scheduled job's storage
// bounded: it drops scheduled snapshots beyond the newest keepLast per resource and
// never touches a manual one, so a user's explicit snapshots are safe while automatic
// ones converge.
func TestPruneAutoSnapshotsKeepsLastAndSparesManual(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "retain@example.com")
	pack, data, ids := packOf("v1 object")
	if _, err := s.PutPack(owner, pack, data, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{ids[0]})

	// A manual snapshot at v1 that retention must never touch.
	manual, err := s.CreateSnapshot(owner, rid, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Four scheduled snapshots, one per new version.
	for i := 2; i <= 5; i++ {
		p, d, id := packOf(fmt.Sprintf("v%d object", i))
		if _, err := s.PutPack(owner, p, d, 0); err != nil {
			t.Fatal(err)
		}
		s.supersede(t, owner, rid, []string{id[0]})
		if n, err := s.RunAutoSnapshots(); err != nil || n != 1 {
			t.Fatalf("scheduled snapshot v%d: n=%d err=%v, want 1", i, n, err)
		}
	}
	if all, _ := s.ListSnapshots(owner, rid); len(all) != 5 {
		t.Fatalf("setup: %d snapshots, want 5 (1 manual + 4 scheduled)", len(all))
	}

	// keepLast <= 0 disables retention.
	if n, err := s.PruneAutoSnapshots(0); err != nil || n != 0 {
		t.Fatalf("prune(0): n=%d err=%v, want 0", n, err)
	}

	// Keep the newest 2 scheduled; the other 2 scheduled go, the manual stays.
	n, err := s.PruneAutoSnapshots(2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("pruned %d, want 2 (4 scheduled minus keep-2)", n)
	}
	all, err := s.ListSnapshots(owner, rid)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("remaining %d, want 3 (2 scheduled + 1 manual)", len(all))
	}
	if _, err := s.GetSnapshot(owner, manual.ID); err != nil {
		t.Fatalf("retention deleted the manual snapshot: %v", err)
	}

	// Within the cap now, a second prune removes nothing.
	if n, err := s.PruneAutoSnapshots(2); err != nil || n != 0 {
		t.Fatalf("prune(2) again: n=%d err=%v, want 0", n, err)
	}
}

func TestSnapshotCRUDAndOwnerIsolation(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "a@example.com")
	other := s.mustAccount(t, "b@example.com")
	packA, dataA, idsA := packOf("obj")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{idsA[0]})

	if _, err := s.CreateSnapshot(owner, "nosuchid", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("snapshot of missing resource = %v, want ErrNotFound", err)
	}

	snap, err := s.CreateSnapshot(owner, rid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != 1 || snap.ResourceID != rid {
		t.Fatalf("snapshot info = %+v, want version 1 of %s", snap, rid)
	}

	// A different owner can neither list, fetch, nor delete it.
	if got, _ := s.ListSnapshots(other, ""); len(got) != 0 {
		t.Fatal("snapshot leaked to another owner")
	}
	if _, err := s.GetSnapshot(other, snap.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner get = %v, want ErrNotFound", err)
	}
	if err := s.DeleteSnapshot(other, snap.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-owner delete = %v, want ErrNotFound", err)
	}

	if got, err := s.GetSnapshot(owner, snap.ID); err != nil || got.Snapshot.ResourceID != rid {
		t.Fatalf("owner get = %+v err=%v", got.Snapshot, err)
	}
	if err := s.DeleteSnapshot(owner, snap.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSnapshot(owner, snap.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete = %v, want ErrNotFound", err)
	}
}

// A client-sealed label survives the round trip through create, list, and get as
// opaque ciphertext and decrypts back; a scheduled (keyless) snapshot carries none.
func TestSnapshotLabelRoundTrip(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "label@example.com")
	packA, dataA, idsA := packOf("obj")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{idsA[0]})

	// Seal a label under a content key, as the CLI does before upload.
	ck, _ := crypto.GenerateContentKey()
	sealedLabel, err := crypto.Seal([]byte("before refactor"), ck, crypto.AADSnapshotLabel)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.CreateSnapshot(owner, rid, &sealedLabel)
	if err != nil {
		t.Fatal(err)
	}
	if snap.EncryptedLabel == nil {
		t.Fatal("create did not echo the label")
	}

	got, err := s.GetSnapshot(owner, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Snapshot.EncryptedLabel == nil {
		t.Fatal("get returned no label")
	}
	plain, err := crypto.Open(*got.Snapshot.EncryptedLabel, ck, crypto.AADSnapshotLabel)
	if err != nil {
		t.Fatalf("open label: %v", err)
	}
	if string(plain) != "before refactor" {
		t.Fatalf("label = %q, want 'before refactor'", plain)
	}

	// A scheduled snapshot of the next version is keyless, so it has no label.
	s.supersede(t, owner, rid, []string{idsA[0]})
	if _, err := s.RunAutoSnapshots(); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListSnapshots(owner, rid)
	if err != nil || len(all) != 2 {
		t.Fatalf("list = %d err=%v, want 2", len(all), err)
	}
	labeled := 0
	for _, sn := range all {
		if sn.EncryptedLabel != nil {
			labeled++
		}
	}
	if labeled != 1 {
		t.Fatalf("labeled snapshots = %d, want 1 (manual labeled, scheduled unlabeled)", labeled)
	}
}

// ListResources surfaces each resource's scheduled-snapshot coverage so the CLI can
// show it without a per-resource fetch; SetAutoSnapshot flips it.
func TestListResourcesReflectsAutoSnapshot(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "auto-list@example.com")
	packA, dataA, idsA := packOf("obj")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, []string{idsA[0]})

	items, err := s.ListResources(owner)
	if err != nil || len(items) != 1 {
		t.Fatalf("list = %d err=%v, want 1", len(items), err)
	}
	if !items[0].AutoSnapshot {
		t.Fatal("auto_snapshot should default to true")
	}

	if err := s.SetAutoSnapshot(owner, rid, false); err != nil {
		t.Fatal(err)
	}
	items, err = s.ListResources(owner)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].AutoSnapshot {
		t.Fatal("auto_snapshot should be false after opt-out")
	}
}
