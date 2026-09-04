// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// readLocated resolves an object to its current pack and returns the bytes that pack
// holds for it, so a test can confirm a moved object's ciphertext survived intact.
func (s *Store) readLocated(t *testing.T, owner, id string) []byte {
	t.Helper()
	locs, err := s.LocateObjects(owner, []string{id})
	if err != nil || len(locs) != 1 {
		t.Fatalf("locate %s: %+v err=%v", id, locs, err)
	}
	loc := locs[0]
	data, err := os.ReadFile(s.packPath(owner, loc.PackID))
	if err != nil {
		t.Fatalf("read pack %s: %v", loc.PackID, err)
	}
	if loc.Off < 0 || loc.Off+loc.Len > int64(len(data)) {
		t.Fatalf("located slice [%d,%d) escapes pack of %d bytes", loc.Off, loc.Off+loc.Len, len(data))
	}
	return data[loc.Off : loc.Off+loc.Len]
}

// GCPacks alone keeps dead objects inside a still-live pack; RepackOwner is what
// reclaims them (see TestRepackCompactsPartiallyDeadPack). The pack file stays
// readable here because only GCPacks runs.
func TestPartiallyReferencedPackSurvives(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "partial@example.com")
	packID, data, ids := packOf("kept object", "dead object")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]}) // only the first object is live

	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (pack is partly live)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("live pack file missing: %v", err)
	}
	// The dead object is still locatable (dead space, not yet repacked).
	if locs, _ := s.LocateObjects(owner, []string{ids[1]}); len(locs) != 1 {
		t.Fatal("dead object inside a live pack should still resolve")
	}
}

// RepackOwner compacts a pack a prune left sparse: the surviving object is copied
// into a fresh pack and still decrypts, the pruned bytes are dropped, and the old
// pack file is removed.
func TestRepackCompactsPartiallyDeadPack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "repack-old@example.com")
	livePayload := "live-object-keep"
	deadPayload := strings.Repeat("dead", 64) // 256 bytes of soon-to-be-reclaimed space
	packID, data, ids := packOf(livePayload, deadPayload)
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]})
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids[1:], forceGC); err != nil || deleted != 1 {
		t.Fatalf("prune deleted %d err=%v, want 1", deleted, err)
	}

	// The sweep alone cannot reclaim the pruned bytes: the pack still holds an object.
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0", deleted, err)
	}

	repacked, reclaimed, err := s.RepackOwner(owner, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if repacked != 1 || reclaimed <= 0 {
		t.Fatalf("repack = %d packs / %d bytes, want 1 / >0", repacked, reclaimed)
	}

	// The live object survives and still decrypts to its original ciphertext, so the
	// resource that roots it still resolves.
	if got := s.readLocated(t, owner, ids[0]); string(got) != livePayload {
		t.Fatalf("live object after repack = %q, want %q", got, livePayload)
	}
	if missing, _ := s.MissingChunks(owner, []string{ids[0]}); len(missing) != 0 {
		t.Fatal("rooted object must survive repack")
	}
	// The dead object is dropped.
	if missing, _ := s.MissingChunks(owner, []string{ids[1]}); len(missing) != 1 {
		t.Fatal("dead object must be dropped by repack")
	}
	// The old sparse pack file is gone.
	if _, err := os.Stat(s.packPath(owner, packID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old pack file should be removed, stat err=%v", err)
	}
	// The compacted pack carries no dead objects, so a second pass is a no-op.
	if r2, _, err := s.RepackOwner(owner, forceGC); err != nil || r2 != 0 {
		t.Fatalf("second repack = %d err=%v, want 0 (pack is dense now)", r2, err)
	}
}

// A pack with no dead objects is never rewritten, even with the age guard disabled.
func TestRepackLeavesFullyLivePack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "dense@example.com")
	packID, data, ids := packOf("aaaa", "bbbb")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, ids) // both objects live

	if repacked, _, err := s.RepackOwner(owner, forceGC); err != nil || repacked != 0 {
		t.Fatalf("repack = %d err=%v, want 0 (no dead objects)", repacked, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("fully-live pack must remain: %v", err)
	}
}

// A compacted pack is content-addressed, so its id can land on a pack the owner
// already stores (here: a client uploaded exactly the live subset earlier). Those
// bytes are already on the owner's counter, so the swap must not add them a second
// time — the counter has no ceiling, so any drift is permanent and only inflates the
// quota the owner is charged.
func TestRepackDoesNotDoubleCountExistingPack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "collide@example.com")
	packID, data, ids := packOf("live-object-keep", strings.Repeat("dead", 64))
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]})
	if _, _, _, err := s.DeleteOwnerChunks(owner, ids[1:], forceGC); err != nil {
		t.Fatal(err)
	}

	// Store the pack the repack is about to build, so its id already has a row.
	live, _, err := s.packLiveObjects(owner, packID)
	if err != nil {
		t.Fatal(err)
	}
	newID, newPack, _ := buildLivePack(data, live)
	if _, err := s.PutPack(owner, newID, newPack, 0); err != nil {
		t.Fatal(err)
	}

	before := s.mustPackBytes(t, owner)
	repacked, reclaimed, err := s.RepackOwner(owner, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if repacked != 1 {
		t.Fatalf("repacked = %d, want 1", repacked)
	}
	after := s.mustPackBytes(t, owner)
	if want := s.mustPackRowBytes(t, owner); after != want {
		t.Fatalf("pack_bytes = %d, want %d (sum of the surviving pack rows)", after, want)
	}
	if before-after != reclaimed {
		t.Fatalf("counter dropped by %d but repack reported %d reclaimed", before-after, reclaimed)
	}
	// The live object still resolves through the surviving pack.
	if got := s.readLocated(t, owner, ids[0]); string(got) != "live-object-keep" {
		t.Fatalf("live object after repack = %q", got)
	}
}

// mustPackBytes returns the owner's maintained pack-bytes counter.
func (s *Store) mustPackBytes(t *testing.T, owner string) int64 {
	t.Helper()
	n, err := s.OwnerPackBytes(owner)
	if err != nil {
		t.Fatalf("owner pack bytes: %v", err)
	}
	return n
}

// mustPackRowBytes returns what the counter should hold: the total length of the
// owner's actual pack rows.
func (s *Store) mustPackRowBytes(t *testing.T, owner string) int64 {
	t.Helper()
	var total sql.NullInt64
	if err := s.db.QueryRow(`SELECT sum(length) FROM packs WHERE owner_handle = ?`, owner).Scan(&total); err != nil {
		t.Fatalf("sum pack lengths: %v", err)
	}
	return total.Int64
}

func TestConcurrentPackWritesDoNotError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "concurrent@example.com")

	const writers = 32
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			packID, data, _ := packOf(fmt.Sprintf("object %d", i))
			_, err := s.PutPack(owner, packID, data, 0)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed (SQLITE_BUSY without a single writer connection?): %v", err)
		}
	}
}

// Re-uploading a stored pack stores no new objects but re-arms its age guard, so a
// client that re-pushes a pack mid-sync (idempotent retry) keeps it alive.
func TestPutPackIdempotentReArm(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "idem@example.com")
	packID, data, _ := packOf("once", "twice")
	if n, err := s.PutPack(owner, packID, data, 0); err != nil || n != 2 {
		t.Fatalf("first put: n=%d err=%v, want 2", n, err)
	}
	// Age it past the guard, then re-upload: the second put adds no objects but
	// bumps created_at, so a real-age sweep then spares it.
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, packID,
	); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PutPack(owner, packID, data, 0); err != nil || n != 0 {
		t.Fatalf("re-put: n=%d err=%v, want 0 stored", n, err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (re-put must re-arm the guard)", deleted, err)
	}
}

// PutPack batches its object inserts; a pack whose object count spans several batches
// must still store and count every chunk, and RowsAffected on a multi-row INSERT must
// sum only the newly-stored rows. This crosses the objectInsertBatch boundary and then
// re-uploads to confirm dedup counts nothing.
func TestPutPackBatchesObjectInserts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "batch@example.com")

	const n = 2*objectInsertBatch + 50 // spans more than two insert batches
	payloads := make([]string, n)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("chunk-%05d", i)
	}
	packID, data, ids := packOf(payloads...)

	if stored, err := s.PutPack(owner, packID, data, 0); err != nil || stored != n {
		t.Fatalf("PutPack stored=%d err=%v, want %d", stored, err, n)
	}
	if missing, err := s.MissingChunks(owner, ids); err != nil || len(missing) != 0 {
		t.Fatalf("missing after upload = %d err=%v, want 0", len(missing), err)
	}
	// Re-uploading the identical pack stores nothing new (dedup on chunk_id).
	if stored, err := s.PutPack(owner, packID, data, 0); err != nil || stored != 0 {
		t.Fatalf("re-put stored=%d err=%v, want 0", stored, err)
	}
}

// An object slice that escapes the object region (into the index trailer) is
// rejected, so a crafted pack cannot smuggle an id that points at index bytes.
func TestPutPackRejectsSliceOutOfRange(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "bounds@example.com")
	packID, data, _ := packOf("real object")

	// Re-write the index with a length that runs past the object region, then
	// re-address the whole pack so only the bounds check (not the id check) fires.
	var index []api.PackIndexEntry
	indexLen := int(binary.BigEndian.Uint32(data[len(data)-4:]))
	objectsEnd := len(data) - 4 - indexLen
	if err := json.Unmarshal(data[objectsEnd:len(data)-4], &index); err != nil {
		t.Fatal(err)
	}
	index[0].Len = objectsEnd + 10 // runs into the index region
	tampered := bytes.Clone(data[:objectsEnd])
	ij, _ := json.Marshal(index)
	tampered = append(tampered, ij...)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(ij)))
	tampered = append(tampered, lb[:]...)
	newID := objID(tampered)

	if _, err := s.PutPack(owner, newID, tampered, 0); !errors.Is(err, ErrBadPack) {
		t.Fatalf("out-of-range slice: got %v, want ErrBadPack", err)
	}
	_ = packID
}

// A crafted pack whose index offset overflows int64 (off=MaxInt64, len=1) must be
// rejected as a bad pack, not slip past the bounds check and panic the slice.
func TestPutPackRejectsOverflowSlice(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "overflow@example.com")
	obj := []byte("real object bytes")
	var buf bytes.Buffer
	buf.Write(obj)
	index := []api.PackIndexEntry{{ID: objID(obj), Off: math.MaxInt64, Len: 1}}
	ij, _ := json.Marshal(index)
	buf.Write(ij)
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(ij)))
	buf.Write(lb[:])
	data := buf.Bytes()

	if _, err := s.PutPack(owner, objID(data), data, 0); !errors.Is(err, ErrBadPack) {
		t.Fatalf("overflowing slice: got %v, want ErrBadPack (must not panic)", err)
	}
}

// assertPackCounters recomputes every pack's obj_count/live_bytes straight from
// the object rows and compares them to the maintained columns, so a write path
// that forgot its recount fails the test that used it. The reads run on the read
// pool: the single writer connection cannot serve a nested query while a cursor
// is open.
func (s *Store) assertPackCounters(t *testing.T, owner string) {
	t.Helper()
	type counters struct {
		objCount  int
		liveBytes int64
	}
	got := map[string]counters{}
	rows, err := s.rdb.Query(
		`SELECT pack_id, obj_count, live_bytes FROM packs WHERE owner_handle = ?`, owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var (
			id string
			c  counters
		)
		if err := rows.Scan(&id, &c.objCount, &c.liveBytes); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		got[id] = c
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatal(err)
	}
	_ = rows.Close()

	for id, c := range got {
		var want counters
		if err := s.rdb.QueryRow(
			`SELECT count(*), COALESCE(sum(o.length), 0) FROM objects o
			 WHERE o.owner_handle = ? AND o.pack_id = ?`, owner, id,
		).Scan(&want.objCount, &want.liveBytes); err != nil {
			t.Fatal(err)
		}
		if c != want {
			t.Fatalf("pack %s counters = %+v, recomputed %+v", id, c, want)
		}
	}
}

// The per-pack counters GC selects on must stay exact through every write that
// can move or delete an object row — pack ingest, chunk delete, sweep, and repack
// — and must be undisturbed by the ref writes (manifest create/supersede,
// snapshot pin/unpin, resource delete) that no longer touch them.
func TestPackCountersStayConsistent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "counters@example.com")
	ck, _ := crypto.GenerateContentKey()
	put := func(id string, expected int, refs []string) string {
		t.Helper()
		blob, _ := crypto.Seal([]byte("manifest"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		rid, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expected,
		})
		if err != nil {
			t.Fatalf("put resource: %v", err)
		}
		return rid
	}

	// pack1's middle object (big, to make the pack a repack candidate) will be
	// pruned; pack2's only object will be pruned outright.
	pack1, data1, ids1 := packOf("alive-a", strings.Repeat("dead-b", 60), "alive-c")
	pack2, data2, ids2 := packOf("never rooted")
	if _, err := s.PutPack(owner, pack1, data1, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(owner, pack2, data2, 0); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)

	// Ref writes — root, snapshot, supersede, unpin — must leave the counters
	// exactly as pack ingest wrote them.
	id := put("", 0, []string{ids1[0], ids1[1]})
	s.assertPackCounters(t, owner)
	snap, err := s.CreateSnapshot(owner, id, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)
	put(id, 1, []string{ids1[0], ids1[2]})
	s.assertPackCounters(t, owner)
	if err := s.DeleteSnapshot(owner, snap.ID); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)

	// A prune deletes b and pack2's object: pack2 empties and is swept in the same
	// call, pack1 turns sparse and the repack compacts it.
	if deleted, _, freed, err := s.DeleteOwnerChunks(owner, []string{ids1[1], ids2[0]}, forceGC); err != nil || deleted != 2 || freed != int64(len(data2)) {
		t.Fatalf("prune = (%d, %d) err=%v, want 2 deleted and pack2's %d bytes freed", deleted, freed, err, len(data2))
	}
	s.assertPackCounters(t, owner)
	if repacked, _, err := s.RepackOwner(owner, forceGC); err != nil || repacked != 1 {
		t.Fatalf("repack = %d err=%v, want 1", repacked, err)
	}
	s.assertPackCounters(t, owner)

	// Deleting the resource only unroots; the surviving objects go when a prune
	// names them, and that empties the last pack.
	if err := s.DeleteResource(owner, id); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, []string{ids1[0], ids1[2]}, forceGC); err != nil || deleted != 2 {
		t.Fatalf("final prune deleted %d err=%v, want 2", deleted, err)
	}
	s.assertPackCounters(t, owner)
	var n int
	if err := s.rdb.QueryRow(`SELECT count(*) FROM packs WHERE owner_handle = ?`, owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d packs remain after full teardown, want 0", n)
	}
}
