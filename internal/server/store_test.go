// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
)

// forceGC sweeps ignoring the age guard (cutoff in the future), so a test does
// not have to wait out gcMinAge to collect a just-uploaded pack.
const forceGC = -time.Hour

func newStore(t testing.TB) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// objID returns the content address of an object's ciphertext.
func objID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// packOf assembles a valid pack from the given object payloads, in order. It builds
// the wire format independently of the client's PackBuilder so the server's parse
// path is exercised on its own. Returns the pack id, the pack bytes, and the object
// ids in order.
func packOf(payloads ...string) (packID string, pack []byte, ids []string) {
	var buf bytes.Buffer
	var index []api.PackIndexEntry
	for _, p := range payloads {
		b := []byte(p)
		id := objID(b)
		ids = append(ids, id)
		index = append(index, api.PackIndexEntry{ID: id, Off: buf.Len(), Len: len(b)})
		buf.Write(b)
	}
	indexJSON, _ := json.Marshal(index)
	buf.Write(indexJSON)
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(indexJSON)))
	buf.Write(lenbuf[:])
	pack = buf.Bytes()
	return objID(pack), pack, ids
}

func (s *Store) mustAccount(t testing.TB, email string) string {
	t.Helper()
	kdf := cryptotest.KdfParams(t)
	acc, err := s.CreateAccount(email, kdf, make([]byte, 32), crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)}, make([]byte, 32), nil, nil)
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	return acc.OwnerHandle
}

// rootResource creates a folder resource referencing the given object ids, so a
// sweep treats them (and their packs) as live.
func (s *Store) rootResource(t *testing.T, owner string, refs []string) string {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed manifest"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"folder","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: refs,
	})
	if err != nil {
		t.Fatalf("root resource: %v", err)
	}
	return id
}

// TestResourceMinClientDefaultsToBaseline covers migration 9's DEFAULT and the
// store's normalization: an undeclared write stores the baseline capability (so a
// pre-migration row and a legacy writer are never over-restricted), while a declared
// value is stored verbatim.
func TestResourceMinClientDefaultsToBaseline(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "mincli@example.com")
	ck, _ := crypto.GenerateContentKey()
	req := func(minClient int) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, MinClient: minClient}
	}
	stored := func(id string) int {
		var n int
		if err := s.db.QueryRow(`SELECT min_client FROM resources WHERE id = ?`, id).Scan(&n); err != nil {
			t.Fatalf("read min_client: %v", err)
		}
		return n
	}

	undeclared, _, err := s.PutResource(owner, api.CapabilityIDBinding, req(0))
	if err != nil {
		t.Fatal(err)
	}
	if got := stored(undeclared); got != api.CapabilityBaseline {
		t.Fatalf("undeclared min_client = %d, want %d", got, api.CapabilityBaseline)
	}

	declared, _, err := s.PutResource(owner, api.CapabilityIDBinding, req(api.CapabilityIDBinding))
	if err != nil {
		t.Fatal(err)
	}
	if got := stored(declared); got != api.CapabilityIDBinding {
		t.Fatalf("declared min_client = %d, want %d", got, api.CapabilityIDBinding)
	}
}

func TestGitRemoteResourcePolicy(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "gitremote@example.com")
	ck, _ := crypto.GenerateContentKey()
	defer ck.Wipe()
	newReq := func() api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(`{"version":1,"generation":0}`), ck, crypto.AADGitRefsRoot)
		meta, _ := crypto.Seal([]byte(`{"name":"brain","kind":"gitremote"}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
			MinClient: api.CapabilityGitRemote, CompactAt: 64,
		}
	}

	req := newReq()
	id, version, err := s.PutResource(owner, api.ClientCapability, req)
	if err != nil {
		t.Fatalf("create git remote: %v", err)
	}
	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if got.CompactAt != 64 || got.MinClient != api.CapabilityGitRemote {
		t.Fatalf("stored policy = compactAt %d minClient %d", got.CompactAt, got.MinClient)
	}
	items, _, err := s.ListResources(owner, pageParams{})
	if err != nil || len(items) != 1 || items[0].CompactAt != 64 {
		t.Fatalf("list policy: items=%+v err=%v", items, err)
	}

	update := newReq()
	update.ID, update.ExpectedVersion, update.CompactAt = id, version, 0 // omission preserves the server setting
	if _, version, err = s.PutResource(owner, api.ClientCapability, update); err != nil || version != 2 {
		t.Fatalf("update git remote: version=%d err=%v", version, err)
	}
	if err := s.PutGrant(owner, id, "grantee", []byte("wrap"), nil, version); !errors.Is(err, ErrGitRemotePolicy) {
		t.Fatalf("grant error = %v, want ErrGitRemotePolicy", err)
	}
	if _, err := s.SetVisibility(owner, id, api.SetVisibilityRequest{Visibility: api.Public, ExpectedVersion: version}); !errors.Is(err, ErrGitRemotePolicy) {
		t.Fatalf("public visibility error = %v, want ErrGitRemotePolicy", err)
	}

	bad := newReq()
	bad.MinClient = api.CapabilityRootKeyRotation
	if _, _, err := s.PutResource(owner, api.ClientCapability, bad); !errors.Is(err, ErrGitRemotePolicy) {
		t.Fatalf("under-gated create error = %v, want ErrGitRemotePolicy", err)
	}
	bad = newReq()
	bad.Visibility = api.Public
	if _, _, err := s.PutResource(owner, api.ClientCapability, bad); !errors.Is(err, ErrGitRemotePolicy) {
		t.Fatalf("public create error = %v, want ErrGitRemotePolicy", err)
	}

	bad = newReq()
	bad.CompactAt = -1
	if _, _, err := s.PutResource(owner, api.ClientCapability, bad); !errors.Is(err, ErrGitRemotePolicy) {
		t.Fatalf("negative compactAt create error = %v, want ErrGitRemotePolicy", err)
	}
}

func TestPackStoreRoundTripAndGC(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "packs@example.com")
	packA, dataA, idsA := packOf("alpha chunk", "beta chunk")
	packB, dataB, idsB := packOf("gamma chunk")

	all := append(append([]string{}, idsA...), idsB...)
	if missing, err := s.MissingChunks(owner, all); err != nil || len(missing) != 3 {
		t.Fatalf("missing before upload = %v err=%v, want 3", missing, err)
	}
	if n, err := s.PutPack(owner, packA, dataA, 0); err != nil || n != 2 {
		t.Fatalf("put pack A: n=%d err=%v, want 2", n, err)
	}
	if n, err := s.PutPack(owner, packB, dataB, 0); err != nil || n != 1 {
		t.Fatalf("put pack B: n=%d err=%v, want 1", n, err)
	}
	if missing, _ := s.MissingChunks(owner, all); len(missing) != 0 {
		t.Fatalf("missing after upload = %d, want 0", len(missing))
	}

	// Locate resolves an object to its pack and byte range; the range decrypts to
	// the original ciphertext.
	locs, err := s.LocateObjects(owner, []string{idsA[1]})
	if err != nil || len(locs) != 1 {
		t.Fatalf("locate: %+v err=%v", locs, err)
	}
	loc := locs[0]
	if loc.PackID != packA {
		t.Fatalf("object located in pack %s, want %s", loc.PackID, packA)
	}
	if got := dataA[loc.Off : loc.Off+loc.Len]; string(got) != "beta chunk" {
		t.Fatalf("located slice = %q, want beta chunk", got)
	}

	// A poisoned pack (an object's bytes do not hash to its id) is rejected.
	_, bad, _ := packOf("honest")
	bad[0] ^= 0xff // corrupt an object byte; pack id no longer matches either
	if _, err := s.PutPack(owner, packA, bad, 0); !errors.Is(err, ErrBadPack) {
		t.Fatalf("corrupt pack: got %v, want ErrBadPack", err)
	}

	// A prune that names pack B's object empties and sweeps that pack; pack A's
	// objects are untouched.
	s.rootResource(t, owner, []string{idsA[0]})
	deleted, _, freed, err := s.DeleteOwnerChunks(owner, idsB, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || freed != int64(len(dataB)) {
		t.Fatalf("prune deleted %d freed %d, want 1 object / %d bytes", deleted, freed, len(dataB))
	}
	if missing, _ := s.MissingChunks(owner, idsA); len(missing) != 0 {
		t.Fatal("pack A objects must survive the prune")
	}
	if missing, _ := s.MissingChunks(owner, idsB); len(missing) != 1 {
		t.Fatal("pruned pack B object must be gone")
	}
}

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

// Repack honors the same age guard as the sweep, so a pack uploaded moments ago (its
// manifest may still be committing) is left untouched.
func TestRepackHonorsAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "young@example.com")
	packID, data, ids := packOf("keep", strings.Repeat("dead", 64))
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]})

	if repacked, _, err := s.RepackOwner(owner, gcMinAge); err != nil || repacked != 0 {
		t.Fatalf("repack = %d err=%v, want 0 (pack younger than the guard)", repacked, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("young pack must be left intact: %v", err)
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

func TestUpdateResourceVersionConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "occ@example.com")
	ck, _ := crypto.GenerateContentKey()

	req := func(id string, expected int, body string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ExpectedVersion: expected,
		}
	}

	id, v, err := s.PutResource(owner, api.CapabilityIDBinding, req("", 0, "v1"))
	if err != nil || v != 1 {
		t.Fatalf("create: v=%d err=%v", v, err)
	}
	// An update based on the current version succeeds and bumps it.
	if _, v2, err := s.PutResource(owner, api.CapabilityIDBinding, req(id, 1, "v2")); err != nil || v2 != 2 {
		t.Fatalf("update@1: v=%d err=%v", v2, err)
	}
	// A second update still claiming version 1 is stale and must be rejected.
	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, req(id, 1, "v3")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update: got %v, want ErrVersionConflict", err)
	}
	// Catching up to the current version works again (the retry path).
	if _, v3, err := s.PutResource(owner, api.CapabilityIDBinding, req(id, 2, "v3")); err != nil || v3 != 3 {
		t.Fatalf("update@2: v=%d err=%v", v3, err)
	}
}

func TestStoreConcurrencyConfig(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1 (concurrent writers would hit SQLITE_BUSY)", got)
	}
	var fk int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1 (the dangling-reference backstop is off)", fk)
	}
	var busy int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if busy == 0 {
		t.Error("busy_timeout = 0, want a positive timeout")
	}
}

func TestConcurrentPackWritesDoNotError(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "concurrent@example.com")

	const writers = 32
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
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

// Uploads racing a concurrent sweep must not lose data: every pack uploaded in the
// race window is fresh, so the age guard spares it even though the sweep runs
// against it. This is the pack analogue of the chunk-store upload/GC race.
func TestConcurrentUploadAndGCKeepsFreshPacks(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "uploadrace@example.com")

	const uploaders = 24
	var wg sync.WaitGroup
	errs := make(chan error, uploaders*2)
	packIDs := make([]string, uploaders)
	for i := 0; i < uploaders; i++ {
		packID, data, _ := packOf(fmt.Sprintf("racing object %d", i))
		packIDs[i] = packID
		wg.Add(2)
		go func(id string, d []byte) {
			defer wg.Done()
			_, err := s.PutPack(owner, id, d, 0)
			errs <- err
		}(packID, data)
		go func() {
			defer wg.Done()
			// A sweep at the real guard must never reap a pack uploaded in this window.
			_, _, err := s.GCPacks(owner, gcMinAge)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent upload/gc errored: %v", err)
		}
	}
	// Every freshly uploaded pack must still be present.
	for _, id := range packIDs {
		if _, err := os.Stat(s.packPath(owner, id)); err != nil {
			t.Fatalf("fresh pack %s lost to a concurrent sweep: %v", id, err)
		}
	}
}

// An object that has aged past the guard and lost its last reference must survive a
// sweep if a concurrent sync checks it (dedup hit) before referencing it: the check
// re-arms the age guard on the pack holding it.
func TestDedupCheckReArmsGCAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "race@example.com")
	packID, data, ids := packOf("dedup target")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	// Age the pack past gcMinAge and leave it unreferenced: the state a prior sync's
	// dropped reference creates.
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, packID,
	); err != nil {
		t.Fatal(err)
	}
	// The check a concurrent sync issues before referencing the object re-arms the
	// pack's guard, so the sweep below cannot reap it in the window before that PUT.
	if missing, err := s.MissingChunks(owner, ids); err != nil || len(missing) != 0 {
		t.Fatalf("missing = %v err = %v, want the object present", missing, err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err = %v, want 0 (the dedup touch must keep the pack)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("pack reaped despite the dedup touch: %v", err)
	}
}

// A manifest referencing an object the owner does not store is rejected by the FK,
// not committed as a dangling reference; a failed update leaves the prior blob
// intact and decryptable (no leftover staged temp).
func TestManifestRejectsDanglingChunkReference(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "fk@example.com")
	ck, _ := crypto.GenerateContentKey()
	mkReq := func(id string, expected int, body string, refs []string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expected,
		}
	}
	ghost := objID([]byte("never uploaded"))

	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq("", 0, "v1", []string{ghost})); err == nil {
		t.Fatal("create referencing a missing object must be rejected")
	}

	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq("", 0, "v1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, 1, "v2", []string{ghost})); err == nil {
		t.Fatal("update introducing a missing object reference must be rejected")
	}

	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d after a failed update, want 1 (old blob clobbered)", got.Version)
	}
	if plain, err := crypto.Open(got.Blob, ck, crypto.AADBlob); err != nil || string(plain) != "v1" {
		t.Fatalf("blob after a failed update = %q err = %v, want v1", plain, err)
	}
	if n := countBlobs(t, s.blobsDir); n != 1 {
		t.Fatalf("blobsDir has %d blob files, want 1 (a staged temp leaked)", n)
	}
}

// countBlobs returns the number of blob files anywhere under dir. Blobs fan out by
// id prefix (blobs/<ab>/<cd>/...), so they are no longer direct children of blobsDir.
func countBlobs(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".bin") {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Re-opening a data dir re-runs migrate as a no-op (user_version gates already-applied
// steps), and the scaffold has created the device-token index.
func TestMigrateIsIdempotentAndIndexesDeviceToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	s2, err := OpenStore(dir) // second migrate over the same dir must not error
	if err != nil {
		t.Fatalf("re-open after migrate: %v", err)
	}
	defer s2.Close()

	var uv int
	if err := s2.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d, want %d (all migrations applied)", uv, len(migrations))
	}
	var name string
	if err := s2.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_devices_token_hash'`,
	).Scan(&name); err != nil {
		t.Fatalf("device-token index missing after migrate: %v", err)
	}
}

// seedSchemaAt builds a data dir holding exactly the first k migration steps — what
// the release that shipped step k would have left behind — without going through
// OpenStore, which would run the whole chain.
func seedSchemaAt(t *testing.T, dir string, k int) {
	t.Helper()
	for _, d := range []string{"blobs", "packs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "aqt.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < k; i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			t.Fatalf("seed migration %d: %v", i+1, err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, k)); err != nil {
		t.Fatal(err)
	}
}

// A data dir written by any older release migrates forward to the current schema.
// The idempotency test above only re-opens an already-current dir, so it never
// exercises a step running against the shape that preceded it. This covers schema
// shape only: the seeded dirs hold no rows, so a step's backfill UPDATE runs over an
// empty table.
func TestMigrateForwardFromEveryVersion(t *testing.T) {
	t.Parallel()
	for k := 0; k < len(migrations); k++ {
		t.Run(fmt.Sprintf("from_v%d", k), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			seedSchemaAt(t, dir, k)
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatalf("migrate forward from user_version %d: %v", k, err)
			}
			defer s.Close()
			var uv int
			if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
				t.Fatal(err)
			}
			if uv != len(migrations) {
				t.Fatalf("user_version = %d after migrating from %d, want %d", uv, k, len(migrations))
			}
		})
	}
}

// A step that fails partway must leave nothing behind: not its already-executed
// statements, and not a user_version bump. Otherwise the next start replays the step
// over its own half-applied output and fails forever with `duplicate column name`.
func TestFailedMigrationStepRollsBackWhole(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Shaped like a real step: an ALTER TABLE ADD COLUMN that succeeds, then a
	// statement that does not — the power-loss-in-the-middle case, only deterministic.
	step := "ALTER TABLE accounts ADD COLUMN wedge_probe INTEGER NOT NULL DEFAULT 0;"
	if err := s.applyMigration(len(migrations)+1, step+"\nALTER TABLE no_such_table ADD COLUMN x INTEGER;"); err == nil {
		t.Fatal("applyMigration accepted a step whose second statement is invalid")
	}

	var uv int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d after a failed step, want %d (bumped despite the failure)", uv, len(migrations))
	}
	if _, err := s.db.Exec(`SELECT wedge_probe FROM accounts`); err == nil {
		t.Fatal("the failed step's first statement survived the rollback")
	}

	// The point of the rollback: with the transient cause gone, the step applies. If
	// its first statement had survived, this is where the data dir wedges forever with
	// `duplicate column name`.
	if err := s.applyMigration(len(migrations)+1, step); err != nil {
		t.Fatalf("retry of a rolled-back step: %v", err)
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations)+1 {
		t.Fatalf("user_version = %d after the retry, want %d", uv, len(migrations)+1)
	}
	if _, err := s.db.Exec(`SELECT wedge_probe FROM accounts`); err != nil {
		t.Fatalf("retry did not apply the step: %v", err)
	}
}

// The crash-window guarantee rests on the driver journaling PRAGMA user_version with
// the transaction: a bump inside a rolled-back tx must be undone, or an interrupted
// migration leaves the version ahead of the schema. The rollback test above fails
// before its bump runs, so this pins the driver behavior itself against upgrades.
func TestUserVersionRollsBackWithTransaction(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+7)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var uv int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d after rollback, want %d: the driver no longer journals the pragma", uv, len(migrations))
	}
}

// A data dir a newer aqt-server has already migrated is refused, not served against
// a schema this build does not understand.
func TestMigrateRefusesNewerDataDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+3)); err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err = OpenStore(dir)
	if err == nil {
		t.Fatal("OpenStore accepted a data dir migrated by a newer build")
	}
	if !strings.Contains(err.Error(), "newer aqt-server") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// Repeated updates must leave exactly one blob file on disk (superseded
// nonce-addressed blobs reclaimed) and the live blob must decrypt to the latest.
func TestUpdatesReclaimSupersededBlobs(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "blobs@example.com")
	ck, _ := crypto.GenerateContentKey()
	put := func(id string, expected int, body string) string {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		rid, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ExpectedVersion: expected,
		})
		if err != nil {
			t.Fatalf("put %q: %v", body, err)
		}
		return rid
	}
	id := put("", 0, "v1")
	put(id, 1, "v2")
	put(id, 2, "v3-final-content")

	if n := countBlobs(t, s.blobsDir); n != 1 {
		t.Fatalf("blobsDir has %d blob files after 3 writes, want 1 (superseded blobs not reclaimed)", n)
	}
	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := crypto.Open(got.Blob, ck, crypto.AADBlob); err != nil || string(plain) != "v3-final-content" {
		t.Fatalf("latest blob = %q err=%v, want v3-final-content", plain, err)
	}
}

// A data dir from the pre-pack build (a `chunks` table, no `objects`/`packs`) must
// be rejected loudly at open, not limped along with a broken FK backstop.
func TestLegacyChunkStoreFailsLoud(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "aqt.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`CREATE TABLE chunks (owner_handle TEXT, chunk_id TEXT, length INTEGER, created_at INTEGER, PRIMARY KEY(owner_handle, chunk_id))`,
	); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "older build") {
		t.Fatalf("OpenStore on a pre-pack data dir = %v, want a clear stale-schema error", err)
	}
}

// A data dir from the even-older flat layout (resource_chunks without owner_handle)
// must also be rejected loudly.
func TestStaleResourceChunksSchemaFailsLoud(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "aqt.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`CREATE TABLE resource_chunks (resource_id TEXT NOT NULL, chunk_id TEXT NOT NULL, PRIMARY KEY(resource_id, chunk_id))`,
	); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "older build") {
		t.Fatalf("OpenStore on a legacy schema = %v, want a clear stale-schema error", err)
	}
}

// A freshly uploaded pack must survive both the sweep and a prune's delete at the
// real age guard: it is what keeps an in-flight push's packs alive until its
// manifest PUT roots their objects. Only once aged does a prune reclaim it.
func TestFreshPackSurvivesAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "ageguard@example.com")
	packID, data, ids := packOf("in flight")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (young pack must survive the age guard)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("young pack reaped: %v", err)
	}
	// Bypassing the guard, a prune naming its object empties and sweeps it.
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids, forceGC); err != nil || deleted != 1 {
		t.Fatalf("forced prune deleted %d err=%v, want 1", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("emptied pack file should be gone, stat err=%v", err)
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

// Locating an object re-arms the age guard on its pack, so a concurrent GC cannot
// reap a pack a download is mid-read of (the read-path analogue of the dedup touch).
func TestLocateRearmsAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "locaterace@example.com")
	packID, data, ids := packOf("download target")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	// Age the pack past the guard and leave it unreferenced: a superseded version's
	// object that a slow reader still needs.
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, packID,
	); err != nil {
		t.Fatal(err)
	}
	if locs, err := s.LocateObjects(owner, ids); err != nil || len(locs) != 1 {
		t.Fatalf("locate: %+v err=%v", locs, err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (locate must re-arm the guard)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("pack reaped despite the locate touch: %v", err)
	}
}

func TestGCDoesNotCrossOwners(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "mine@example.com")
	other := s.mustAccount(t, "theirs@example.com")

	packID, data, ids := packOf("only mine")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	// Another owner's sweep must not touch my packs.
	if deleted, _, err := s.GCPacks(other, forceGC); err != nil || deleted != 0 {
		t.Fatalf("cross-owner gc deleted %d err=%v, want 0", deleted, err)
	}
	if missing, _ := s.MissingChunks(owner, ids); len(missing) != 0 {
		t.Fatal("my pack must survive another owner's gc")
	}
}

// A refs-less replace of a private object-backed resource is the ordinary
// client-GC push: it lands, the stored ref rows stay as they were, and the
// objects survive GC regardless — the server never sweeps by reachability.
func TestUpdateWithoutRefsKeepsRowsAndObjects(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "roots@example.com")
	ck, _ := crypto.GenerateContentKey()
	packID, data, ids := packOf("obj-one", "obj-two")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	mkReq := func(id string, expected int, body string, refs []string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expected,
		}
	}

	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq("", 0, "v1", ids))
	if err != nil {
		t.Fatal(err)
	}

	if _, v, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, 1, "v2", nil)); err != nil || v != 2 {
		t.Fatalf("refs-less replace = v%d err=%v, want v2 nil", v, err)
	}
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0", deleted, err)
	}
	if missing, _ := s.MissingChunks(owner, ids); len(missing) != 0 {
		t.Fatal("objects must survive a refs-less replace and a GC pass")
	}

	// A refs-full replace still works and replaces the rows.
	if _, v, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, 2, "v3", ids[:1])); err != nil || v != 3 {
		t.Fatalf("refs-full replace = v%d err=%v, want v3 nil", v, err)
	}
}

// Blobs are addressed by id+nonce and immutable per nonce, so an update repeating the
// stored nonce would target the live file: the write truncates it, and any failure
// exit before the commit deletes it while the committed row still names that nonce.
// The store rejects the reuse instead, leaving the live blob untouched.
func TestUpdateRejectsReusedBlobNonce(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "nonce@example.com")
	ck, _ := crypto.GenerateContentKey()
	packID, data, ids := packOf("obj-one", "obj-two")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	blob, _ := crypto.Seal([]byte("v1"), ck, crypto.AADBlob)
	mkReq := func(id string, b crypto.SealedBlob, refs []string) api.PutResourceRequest {
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: b, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs,
		}
	}

	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq("", blob, ids))
	if err != nil {
		t.Fatal(err)
	}

	// The replay carries no ExpectedVersion, so nothing else rejects it first.
	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, blob, ids)); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("replace reusing the stored nonce = %v, want ErrNonceReuse", err)
	}
	// A rejected reuse whose other fields would have failed later must not have
	// touched the blob either: this one drops the roots, an exit past the blob write.
	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, blob, nil)); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("root-dropping reuse = %v, want ErrNonceReuse", err)
	}
	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatalf("resource must stay readable after a rejected reuse: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d after rejected replaces, want 1", got.Version)
	}
	plain, err := crypto.Open(got.Blob, ck, crypto.AADBlob)
	if err != nil || string(plain) != "v1" {
		t.Fatalf("blob = %q err=%v, want v1", plain, err)
	}

	// A fresh nonce (what every reseal draws) replaces as before.
	next, _ := crypto.Seal([]byte("v2"), ck, crypto.AADBlob)
	if _, v, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, next, ids)); err != nil || v != 2 {
		t.Fatalf("replace with a fresh nonce = v%d err=%v, want v2 nil", v, err)
	}
}

// isUnique feeds CreateAccount's ErrConflict ("email already registered"), so it must
// match only UNIQUE violations. A NOT NULL or CHECK failure is a server bug and must
// not be reported to the caller as a duplicate.
func TestIsUniqueMatchesOnlyUniqueViolations(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.db.Exec(`CREATE TABLE probe(a TEXT UNIQUE, b TEXT NOT NULL, c INT CHECK (c > 0))`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO probe(a,b,c) VALUES('x','y',1)`); err != nil {
		t.Fatal(err)
	}
	_, dup := s.db.Exec(`INSERT INTO probe(a,b,c) VALUES('x','y',1)`)
	_, notNull := s.db.Exec(`INSERT INTO probe(a,b,c) VALUES('z',NULL,1)`)
	_, check := s.db.Exec(`INSERT INTO probe(a,b,c) VALUES('w','y',0)`)
	if !isUnique(dup) {
		t.Fatalf("UNIQUE violation not matched: %v", dup)
	}
	if isUnique(notNull) {
		t.Fatalf("NOT NULL violation matched as unique: %v", notNull)
	}
	if isUnique(check) {
		t.Fatalf("CHECK violation matched as unique: %v", check)
	}
}

// The drop-roots guard only fires when the prior version actually had roots, so the
// legitimate `aqt private` on an inline file (which never had any ChunkRefs) still
// replaces in place with none.
func TestUpdateAllowsEmptyRootsWhenNoneExisted(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "inline@example.com")
	ck, _ := crypto.GenerateContentKey()
	mkReq := func(id string, expected int, body string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ExpectedVersion: expected,
		}
	}
	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq("", 0, "v1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, v, err := s.PutResource(owner, api.CapabilityIDBinding, mkReq(id, 1, "v2")); err != nil || v != 2 {
		t.Fatalf("inline replace with no roots = v%d err=%v, want v2 nil", v, err)
	}
}

// Two GC passes for one owner race in production (two folders syncing at once, two
// devices, or a manual sync racing the watch daemon — each triggers a GC). Without
// the per-owner lock both would pick the same repack candidate, write the same
// content-addressed new pack, and the loser's stale-plan branch would delete the
// now-live new pack file, losing the live object. With it, the live object always
// survives a burst of concurrent GCs.
func TestConcurrentGCKeepsLivePack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "racegc@example.com")
	livePayload := "live-object-keep"
	deadPayload := strings.Repeat("dead", 64) // enough dead space to make a repack candidate
	packID, data, ids := packOf(livePayload, deadPayload)
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]}) // only the first object is live

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.GC(owner, forceGC)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent GC %d: %v", i, err)
		}
	}

	// The live object survived the burst and still decrypts to its original bytes.
	if got := s.readLocated(t, owner, ids[0]); string(got) != livePayload {
		t.Fatalf("live object after concurrent GC = %q, want %q", got, livePayload)
	}
	if missing, _ := s.MissingChunks(owner, []string{ids[0]}); len(missing) != 0 {
		t.Fatal("rooted object must survive concurrent GC")
	}
}

// assertPackCounters recomputes every pack's obj_count/live_count/live_bytes
// straight from the object rows and compares them to the maintained columns, so a
// write path that forgot its recount fails the test that used it. The reads run
// on the read pool: the single writer connection cannot serve a nested query
// while a cursor is open.
func (s *Store) assertPackCounters(t *testing.T, owner string) {
	t.Helper()
	type counters struct {
		objCount, liveCount int
		liveBytes           int64
	}
	got := map[string]counters{}
	rows, err := s.rdb.Query(
		`SELECT pack_id, obj_count, live_count, live_bytes FROM packs WHERE owner_handle = ?`, owner,
	)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var (
			id string
			c  counters
		)
		if err := rows.Scan(&id, &c.objCount, &c.liveCount, &c.liveBytes); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		got[id] = c
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()

	for id, c := range got {
		var want counters
		if err := s.rdb.QueryRow(
			`SELECT count(*) FROM objects o WHERE o.owner_handle = ? AND o.pack_id = ?`, owner, id,
		).Scan(&want.objCount); err != nil {
			t.Fatal(err)
		}
		if err := s.rdb.QueryRow(
			`SELECT count(*), COALESCE(sum(o.length), 0) FROM objects o
			 WHERE o.owner_handle = ? AND o.pack_id = ?`, owner, id,
		).Scan(&want.liveCount, &want.liveBytes); err != nil {
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

// A read must not queue behind an open write transaction: reads run on the WAL
// read pool, not the single writer connection. Before the read pool existed this
// deadlocked outright — the write tx held the store's only connection.
func TestReadsProceedDuringOpenWriteTx(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "readpool@example.com")
	id := s.rootResource(t, owner, nil)

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Take the write lock so the writer connection is genuinely busy.
	if _, err := tx.Exec(`INSERT INTO server_meta(key, value) VALUES('test-write-lock', x'00')`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.GetResource(id, owner)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read during an open write tx: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read blocked behind an open write transaction")
	}
}

// The read pool must reject writes loudly (query_only), so a mutation routed to it
// by mistake fails instead of racing the single writer to SQLITE_BUSY.
func TestReadPoolRejectsWrites(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.rdb.Exec(`INSERT INTO server_meta(key, value) VALUES('nope', x'00')`); err == nil {
		t.Fatal("write on the read pool succeeded, want a query_only failure")
	}
}

// Cached token resolutions must die with their device (revocation) and their epoch
// (passphrase change) immediately, not at TTL expiry.
func TestAuthCacheInvalidation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "authcache@example.com")
	devA, tokA, err := s.CreateDevice(owner, "keeper", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	devB, tokB, err := s.CreateDevice(owner, "revoked", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Prime the cache with both tokens.
	if o, d, err := s.AuthByToken(tokA); err != nil || o != owner || d != devA {
		t.Fatalf("auth A = (%s, %s, %v)", o, d, err)
	}
	if _, d, err := s.AuthByToken(tokB); err != nil || d != devB {
		t.Fatalf("auth B = (%s, %v)", d, err)
	}

	// Revoking B must invalidate its cached entry, not wait out the TTL.
	if err := s.DeleteDevice(owner, devB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthByToken(tokB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token resolved from cache: %v, want ErrNotFound", err)
	}
	if _, _, err := s.AuthByToken(tokA); err != nil {
		t.Fatalf("unrelated token invalidated: %v", err)
	}

	// A passphrase change bumps the epoch: every other device's cached token dies,
	// the calling device's keeps working.
	_, tokC, err := s.CreateDevice(owner, "staled", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthByToken(tokC); err != nil {
		t.Fatal(err)
	}
	kdf := cryptotest.KdfParams(t)
	if _, err := s.ChangePassphrase(owner, devA, kdf,
		crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)},
		make([]byte, 32), []byte("new-verifier"), 1); err != nil {
		t.Fatalf("change passphrase: %v", err)
	}
	if _, _, err := s.AuthByToken(tokC); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-change token resolved from cache: %v, want ErrNotFound", err)
	}
	if _, _, err := s.AuthByToken(tokA); err != nil {
		t.Fatalf("initiating device's token must survive the epoch bump: %v", err)
	}
}

// RunGCAll (the scheduled sweep's tick body) covers every owner, so packs a prune
// left sparse get compacted even on an account whose devices stopped syncing.
func TestRunGCAllRepacksAllOwners(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	a := s.mustAccount(t, "idle-a@example.com")
	b := s.mustAccount(t, "idle-b@example.com")
	for _, owner := range []string{a, b} {
		packID, data, ids := packOf(strings.Repeat("pruned", 64), "tiny survivor")
		if _, err := s.PutPack(owner, packID, data, 0); err != nil {
			t.Fatal(err)
		}
		if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids[:1], forceGC); err != nil || deleted != 1 {
			t.Fatalf("prune for %s deleted %d err=%v, want 1", owner, deleted, err)
		}
	}

	res, err := s.RunGCAll(forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if res.RepackedPacks != 2 || res.ReclaimedBytes <= 0 {
		t.Fatalf("RunGCAll = %+v, want both owners' sparse packs compacted", res)
	}
}

// StartGC's timer path end-to-end: a pack a prune left sparse is compacted without
// any client triggering POST /v1/gc.
func TestStartGCRepacksOnTimer(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "sched-gc@example.com")
	packID, data, ids := packOf(strings.Repeat("pruned", 64), "tiny survivor")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.BackdatePacksForTest(owner, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids[:1], gcMinAge); err != nil || deleted != 1 {
		t.Fatalf("prune deleted %d err=%v, want 1", deleted, err)
	}

	stop := make(chan struct{})
	defer close(stop)
	NewWithConfig(s, Config{}).StartGC(5*time.Millisecond, stop)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s.packPath(owner, packID)); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scheduled gc never compacted the sparse pack")
}

// TestUpdateResourceMetadataOnly verifies rename's store primitive cannot alter
// content, chunk roots, visibility, or link lifecycle and rejects stale writers.
func TestUpdateResourceMetadataOnly(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "metadata-owner@example.com")
	other := s.mustAccount(t, "metadata-other@example.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("content stays"), ck, crypto.AADBlob)
	oldMeta, _ := crypto.Seal([]byte(`{"name":"old"}`), ck, crypto.AADMeta)
	newMeta, _ := crypto.Seal([]byte(`{"name":"new"}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})

	id, version, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: oldMeta, WrappedKey: &wrapped,
		ExpireSeconds: 3600, MaxReads: 5, OnExpiry: api.ExpiryRetire, MinClient: api.CapabilityIDBinding,
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	var upgrade *UpgradeRequiredError
	if _, err := s.UpdateResourceMetadata(owner, id, api.CapabilityBaseline, api.UpdateResourceMetadataRequest{
		EncryptedMeta: newMeta, ExpectedVersion: version,
	}); !errors.As(err, &upgrade) || upgrade.MinClient != api.CapabilityIDBinding {
		t.Fatalf("under-capable metadata update err = %v, want UpgradeRequiredError{%d}", err, api.CapabilityIDBinding)
	}
	gotVersion, err := s.UpdateResourceMetadata(owner, id, api.CapabilityIDBinding, api.UpdateResourceMetadataRequest{
		EncryptedMeta: newMeta, ExpectedVersion: version,
	})
	if err != nil || gotVersion != version+1 {
		t.Fatalf("metadata update: version=%d err=%v", gotVersion, err)
	}
	after, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Blob.Nonce, before.Blob.Nonce) || !bytes.Equal(after.Blob.Ciphertext, before.Blob.Ciphertext) {
		t.Fatal("metadata update changed content blob")
	}
	if !bytes.Equal(after.EncryptedMeta.Ciphertext, newMeta.Ciphertext) || after.Visibility != api.Public {
		t.Fatalf("metadata/visibility after update = %+v", after)
	}
	if after.ExpiresAt != before.ExpiresAt || after.MaxReads != 5 || after.Reads != 0 {
		t.Fatalf("metadata update changed lifecycle: before=%+v after=%+v", before, after)
	}
	if after.CreatedAt == 0 || after.UpdatedAt < after.CreatedAt {
		t.Fatalf("invalid timestamps: created=%d updated=%d", after.CreatedAt, after.UpdatedAt)
	}
	if _, err := s.UpdateResourceMetadata(owner, id, api.CapabilityIDBinding, api.UpdateResourceMetadataRequest{
		EncryptedMeta: oldMeta, ExpectedVersion: version,
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale metadata update err = %v, want ErrVersionConflict", err)
	}
	if _, err := s.UpdateResourceMetadata(other, id, api.CapabilityIDBinding, api.UpdateResourceMetadataRequest{
		EncryptedMeta: oldMeta, ExpectedVersion: version + 1,
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign metadata update err = %v, want ErrNotFound", err)
	}
}

// The quota preflight trusts this probe's bare "key exists" answer to skip the
// quota check, on the strength of the create's own key lookup later refusing to
// store anything. A row the GC sweep deletes between the two would break that
// chain and let the create land unmetered — so a row near enough to the TTL to
// be sweepable mid-request must read as unrecorded, and the request falls back
// to the normal quota-checked path.
func TestResourceCreateKeyProbeIgnoresSweepableRows(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "probe-age@example.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	req := api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, IdempotencyKey: "aging-key"}
	if _, _, err := s.PutResource(owner, api.ClientCapability, req); err != nil {
		t.Fatal(err)
	}
	if !s.ResourceCreateKeyRecorded(owner, req) {
		t.Fatal("fresh key not recognized by the probe")
	}

	// Half an hour of TTL left: still present, but sweepable too soon to trust.
	backdated := time.Now().Add(-(idempotencyTTL - 30*time.Minute)).Unix()
	if _, err := s.db.Exec(`UPDATE idempotency_keys SET created_at = ? WHERE owner_handle = ? AND key = ?`,
		backdated, owner, "aging-key"); err != nil {
		t.Fatal(err)
	}
	if s.ResourceCreateKeyRecorded(owner, req) {
		t.Fatal("probe trusted a row the GC sweep could delete mid-request")
	}
	// The fallback path still replays: the row is present, so the create's own
	// lookup answers with the recorded response rather than storing again.
	id, _, err := s.PutResource(owner, api.ClientCapability, req)
	if err != nil {
		t.Fatalf("near-TTL replay: %v", err)
	}
	if id == "" {
		t.Fatal("near-TTL replay returned no id")
	}
}

func TestCreationIdempotencyKeysReplayAndRejectPayloadReuse(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "idem.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	req := api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, IdempotencyKey: "resource-key"}
	id1, version1, err := s.PutResource(owner, api.ClientCapability, req)
	if err != nil {
		t.Fatal(err)
	}
	id2, version2, err := s.PutResource(owner, api.ClientCapability, req)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 || version1 != version2 {
		t.Fatalf("replay = %s/v%d, want %s/v%d", id2, version2, id1, version1)
	}
	changed := req
	changed.Blob.Ciphertext = append([]byte(nil), req.Blob.Ciphertext...)
	changed.Blob.Ciphertext[0] ^= 1
	if _, _, err := s.PutResource(owner, api.ClientCapability, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}

	snapReq := api.CreateSnapshotRequest{ResourceID: id1, IdempotencyKey: "snapshot-key"}
	snap1, err := s.CreateSnapshotIdempotent(owner, snapReq)
	if err != nil {
		t.Fatal(err)
	}
	snap2, err := s.CreateSnapshotIdempotent(owner, snapReq)
	if err != nil {
		t.Fatal(err)
	}
	if snap1.ID != snap2.ID {
		t.Fatalf("snapshot replay ids = %s/%s", snap1.ID, snap2.ID)
	}
	snapReq.Anchor = true
	if _, err := s.CreateSnapshotIdempotent(owner, snapReq); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed snapshot replay error = %v", err)
	}
}

func TestMutationsRejectStaleResourceVersions(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "cas.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, version, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped})
	if err != nil {
		t.Fatal(err)
	}
	version, err = s.SetVisibility(owner, id, api.SetVisibilityRequest{Visibility: api.Public, ExpectedVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetVisibility(owner, id, api.SetVisibilityRequest{Visibility: api.Private, ExpectedVersion: version - 1}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale visibility = %v", err)
	}
	if err := s.PutGrant(owner, id, "grantee", []byte("wrapped"), nil, version); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(owner, id, "other", []byte("wrapped"), nil, version); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale grant = %v", err)
	}
	if err := s.DeleteResourceVersion(owner, id, version); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale delete = %v", err)
	}
}

// A resource row whose blob file is gone (operator deletion, crash-window
// orphan) must not fail usage accounting: AccountUsage feeds metrics, pack and
// resource puts, and auto-snapshots, so a hard error would wedge the whole
// account on one missing file.
func TestAccountUsageToleratesMissingBlob(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "orphan@example.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.blobPath(id, blob.Nonce)); err != nil {
		t.Fatal(err)
	}
	u, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatalf("usage with missing blob: %v", err)
	}
	if u.Resources != 1 {
		t.Fatalf("resources = %d, want 1", u.Resources)
	}
}

// A reclaimed tombstone holds no ciphertext, so it must stop counting toward
// the modeled quota; otherwise a delete-heavy account sits over quota with no
// way to recover.
func TestAccountUsageExcludesReclaimedTombstones(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "tombstone@example.com")
	base, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("public body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"p","size":11}`), ck, crypto.AADMeta)
	if _, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Public, Blob: blob, EncryptedMeta: meta, ExpireSeconds: 1}); err != nil {
		t.Fatal(err)
	}
	live, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	if live.StorageBytes <= base.StorageBytes {
		t.Fatalf("live usage %d not above baseline %d", live.StorageBytes, base.StorageBytes)
	}
	if _, err := s.SweepExpired(owner, time.Now().Unix()+2); err != nil {
		t.Fatal(err)
	}
	after, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	if after.StorageBytes != base.StorageBytes {
		t.Fatalf("usage after reclaim = %d, want baseline %d", after.StorageBytes, base.StorageBytes)
	}
}

// Recorded idempotency responses only matter for short-lived retries; GC must
// reap rows past the TTL or the table grows without bound.
func TestGCSweepsStaleIdempotencyKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "idemgc@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	for _, key := range []string{"stale-key", "fresh-key"} {
		blob, _ := crypto.Seal([]byte("body "+key), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
		if _, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, IdempotencyKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE idempotency_keys SET created_at = ? WHERE key = 'stale-key'`,
		time.Now().Add(-idempotencyTTL-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GC(owner, time.Hour); err != nil {
		t.Fatal(err)
	}
	var keys []string
	rows, err := s.rdb.Query(`SELECT key FROM idempotency_keys WHERE owner_handle = ?`, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	if len(keys) != 1 || keys[0] != "fresh-key" {
		t.Fatalf("keys after gc = %v, want [fresh-key]", keys)
	}
}

// A share block is the store-level guarantee behind `aqt shares rm --block`:
// registration is open, so without it the account that appended a row to someone's
// share list is also the only one able to keep it out.
func TestShareBlockRefusesFurtherGrants(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "sender@example.com")
	grantee := s.mustAccount(t, "recipient@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	put := func(name string) string {
		blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"`+name+`","size":4}`), ck, crypto.AADMeta)
		id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, second := put("first"), put("second")
	for _, id := range []string{first, second} {
		if err := s.PutGrant(owner, id, grantee, []byte("wrap"), nil); err != nil {
			t.Fatal(err)
		}
	}

	// A removal without a block takes one row and leaves the sender free to re-grant.
	if _, removed, err := s.DeleteShare(grantee, first, false); err != nil || removed != 1 {
		t.Fatalf("DeleteShare = (%d, %v), want (1, nil)", removed, err)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); err != nil {
		t.Fatalf("re-grant after a plain removal: %v", err)
	}

	gotOwner, removed, err := s.DeleteShare(grantee, first, true)
	if err != nil {
		t.Fatalf("DeleteShare with block: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("blocked owner = %q, want %q", gotOwner, owner)
	}
	// Blocking clears the sender's other shares too, not only the named one.
	if removed != 2 {
		t.Fatalf("removed = %d, want both of the sender's shares", removed)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); !errors.Is(err, ErrSenderBlocked) {
		t.Fatalf("grant from a blocked sender = %v, want ErrSenderBlocked", err)
	}
	// The block is per-pair: another account is unaffected.
	third := s.mustAccount(t, "someone-else@example.com")
	if err := s.PutGrant(owner, first, third, []byte("wrap"), nil); err != nil {
		t.Fatalf("grant to an unrelated account: %v", err)
	}

	blocks, _, err := s.ListShareBlocks(grantee, pageParams{})
	if err != nil || len(blocks) != 1 || blocks[0].OwnerHandle != owner {
		t.Fatalf("ListShareBlocks = (%+v, %v), want one block on %s", blocks, err, owner)
	}
	if err := s.DeleteShareBlock(grantee, owner); err != nil {
		t.Fatalf("DeleteShareBlock: %v", err)
	}
	if err := s.DeleteShareBlock(grantee, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lifting a lifted block = %v, want ErrNotFound", err)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); err != nil {
		t.Fatalf("grant after the block was lifted: %v", err)
	}
}

// The delete predicate is the caller's own grantee handle: a third account must not
// be able to strip somebody else's access (or block a sender on their behalf).
func TestDeleteShareIsGranteeScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "owner@example.com")
	grantee := s.mustAccount(t, "grantee@example.com")
	stranger := s.mustAccount(t, "stranger@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(owner, id, grantee, []byte("wrap"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteShare(stranger, id, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger removing another account's share = %v, want ErrNotFound", err)
	}
	shares, _, err := s.ListShares(grantee, pageParams{})
	if err != nil || len(shares) != 1 {
		t.Fatalf("ListShares = (%+v, %v), want the grant intact", shares, err)
	}
	blocks, _, err := s.ListShareBlocks(stranger, pageParams{})
	if err != nil || len(blocks) != 0 {
		t.Fatalf("ListShareBlocks = (%+v, %v), want no block recorded", blocks, err)
	}
}

// A manifest PUT whose refs name objects the owner no longer stores fails with the
// named ErrDanglingRefs (the 400 missing_chunks mapping) and rolls back whole,
// rather than committing dangling refs or surfacing an opaque constraint error —
// the slow-push race (#177), now with a concurrent prune as the reaper.
func TestPutResourceWithSweptRefsFailsNamed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "sweptpush@example.com")
	pack, data, ids := packOf("slow push chunk")
	if _, err := s.PutPack(owner, pack, data, 0); err != nil {
		t.Fatal(err)
	}
	// The push stalls past the age guard; another device's prune reaps the
	// uploaded-but-unrooted objects.
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids, forceGC); err != nil || deleted != 1 {
		t.Fatalf("prune deleted %d err=%v, want the unrooted object gone", deleted, err)
	}
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed manifest"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"folder","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	_, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: ids,
	})
	if !errors.Is(err, ErrDanglingRefs) {
		t.Fatalf("put with swept refs = %v, want ErrDanglingRefs", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM resources WHERE owner_handle = ?`, owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed create left %d resource row(s), want a whole rollback", n)
	}

	// The update path shares the same backstop: a healthy resource cannot be moved
	// onto swept refs.
	live, liveData, liveIDs := packOf("healthy chunk")
	if _, err := s.PutPack(owner, live, liveData, 0); err != nil {
		t.Fatal(err)
	}
	id := s.rootResource(t, owner, liveIDs)
	blob2, _ := crypto.Seal([]byte("sealed manifest v2"), ck, crypto.AADBlob)
	_, _, err = s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob2, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: ids, ExpectedVersion: 1,
	})
	if !errors.Is(err, ErrDanglingRefs) {
		t.Fatalf("update with swept refs = %v, want ErrDanglingRefs", err)
	}
	if missing, err := s.MissingChunks(owner, liveIDs); err != nil || len(missing) != 0 {
		t.Fatalf("live refs after failed update: missing=%v err=%v, want the old roots intact", missing, err)
	}
}
