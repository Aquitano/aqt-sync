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
)

// forceGC sweeps ignoring the age guard (cutoff in the future), so a test does
// not have to wait out gcMinAge to collect a just-uploaded pack.
const forceGC = -time.Hour

func newStore(t *testing.T) *Store {
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

func (s *Store) mustAccount(t *testing.T, email string) string {
	t.Helper()
	kdf, _ := crypto.NewKdfParams()
	acc, err := s.CreateAccount(email, kdf, make([]byte, 32), crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)}, make([]byte, 32))
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
	id, _, err := s.PutResource(owner, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: refs,
	})
	if err != nil {
		t.Fatalf("root resource: %v", err)
	}
	return id
}

func TestPackStoreRoundTripAndGC(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "packs@example.com")
	packA, dataA, idsA := packOf("alpha chunk", "beta chunk")
	packB, dataB, idsB := packOf("gamma chunk")

	all := append(append([]string{}, idsA...), idsB...)
	if missing, err := s.MissingChunks(owner, all); err != nil || len(missing) != 3 {
		t.Fatalf("missing before upload = %v err=%v, want 3", missing, err)
	}
	if n, err := s.PutPack(owner, packA, dataA); err != nil || n != 2 {
		t.Fatalf("put pack A: n=%d err=%v, want 2", n, err)
	}
	if n, err := s.PutPack(owner, packB, dataB); err != nil || n != 1 {
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
	if _, err := s.PutPack(owner, packA, bad); !errors.Is(err, ErrBadPack) {
		t.Fatalf("corrupt pack: got %v, want ErrBadPack", err)
	}

	// A resource referencing one object in pack A roots that whole pack; pack B is
	// fully unreferenced and swept.
	s.rootResource(t, owner, []string{idsA[0]})
	deleted, freed, err := s.GCPacks(owner, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || freed != int64(len(dataB)) {
		t.Fatalf("gc deleted %d freed %d, want 1 pack / %d bytes", deleted, freed, len(dataB))
	}
	if missing, _ := s.MissingChunks(owner, idsA); len(missing) != 0 {
		t.Fatal("pack A objects must survive gc (one is referenced)")
	}
	if missing, _ := s.MissingChunks(owner, idsB); len(missing) != 1 {
		t.Fatal("unreferenced pack B must be swept")
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
	s := newStore(t)
	owner := s.mustAccount(t, "partial@example.com")
	packID, data, ids := packOf("kept object", "dead object")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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

// RepackOwner compacts a pack that mixes live and dead objects: the live object is
// copied into a fresh pack and still decrypts, the dead object is dropped, and the
// old pack file is removed.
func TestRepackCompactsPartiallyDeadPack(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "repack@example.com")
	livePayload := "live-object-keep"
	deadPayload := strings.Repeat("dead", 64) // 256 bytes of soon-to-be-reclaimed space
	packID, data, ids := packOf(livePayload, deadPayload)
	if _, err := s.PutPack(owner, packID, data); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]}) // only the first object is live

	// GC alone cannot reclaim the dead bytes: the pack is still partly live.
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
	s := newStore(t)
	owner := s.mustAccount(t, "dense@example.com")
	packID, data, ids := packOf("aaaa", "bbbb")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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
	s := newStore(t)
	owner := s.mustAccount(t, "young@example.com")
	packID, data, ids := packOf("keep", strings.Repeat("dead", 64))
	if _, err := s.PutPack(owner, packID, data); err != nil {
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

func TestUpdateResourceVersionConflict(t *testing.T) {
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

	id, v, err := s.PutResource(owner, req("", 0, "v1"))
	if err != nil || v != 1 {
		t.Fatalf("create: v=%d err=%v", v, err)
	}
	// An update based on the current version succeeds and bumps it.
	if _, v2, err := s.PutResource(owner, req(id, 1, "v2")); err != nil || v2 != 2 {
		t.Fatalf("update@1: v=%d err=%v", v2, err)
	}
	// A second update still claiming version 1 is stale and must be rejected.
	if _, _, err := s.PutResource(owner, req(id, 1, "v3")); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update: got %v, want ErrVersionConflict", err)
	}
	// Catching up to the current version works again (the retry path).
	if _, v3, err := s.PutResource(owner, req(id, 2, "v3")); err != nil || v3 != 3 {
		t.Fatalf("update@2: v=%d err=%v", v3, err)
	}
}

func TestStoreConcurrencyConfig(t *testing.T) {
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
			_, err := s.PutPack(owner, packID, data)
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
			_, err := s.PutPack(owner, id, d)
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
	s := newStore(t)
	owner := s.mustAccount(t, "race@example.com")
	packID, data, ids := packOf("dedup target")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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

	if _, _, err := s.PutResource(owner, mkReq("", 0, "v1", []string{ghost})); err == nil {
		t.Fatal("create referencing a missing object must be rejected")
	}

	id, _, err := s.PutResource(owner, mkReq("", 0, "v1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutResource(owner, mkReq(id, 1, "v2", []string{ghost})); err == nil {
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

// Repeated updates must leave exactly one blob file on disk (superseded
// nonce-addressed blobs reclaimed) and the live blob must decrypt to the latest.
func TestUpdatesReclaimSupersededBlobs(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "blobs@example.com")
	ck, _ := crypto.GenerateContentKey()
	put := func(id string, expected int, body string) string {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		rid, _, err := s.PutResource(owner, api.PutResourceRequest{
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

// A freshly uploaded, not-yet-referenced pack must survive a real-age sweep: the
// age guard is what keeps an in-flight push's packs alive until its manifest PUT
// roots their objects. Only once aged and still unreferenced is it reaped.
func TestFreshPackSurvivesAgeGuard(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "ageguard@example.com")
	packID, data, _ := packOf("in flight")
	if _, err := s.PutPack(owner, packID, data); err != nil {
		t.Fatal(err)
	}
	// A sweep at the real guard must not touch a pack uploaded moments ago.
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (young pack must survive the age guard)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("young pack reaped: %v", err)
	}
	// Bypassing the guard, the still-unreferenced pack is collectable.
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 1 {
		t.Fatalf("forced gc deleted %d err=%v, want 1", deleted, err)
	}
}

// Re-uploading a stored pack stores no new objects but re-arms its age guard, so a
// client that re-pushes a pack mid-sync (idempotent retry) keeps it alive.
func TestPutPackIdempotentReArm(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "idem@example.com")
	packID, data, _ := packOf("once", "twice")
	if n, err := s.PutPack(owner, packID, data); err != nil || n != 2 {
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
	if n, err := s.PutPack(owner, packID, data); err != nil || n != 0 {
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
	s := newStore(t)
	owner := s.mustAccount(t, "batch@example.com")

	const n = 2*objectInsertBatch + 50 // spans more than two insert batches
	payloads := make([]string, n)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("chunk-%05d", i)
	}
	packID, data, ids := packOf(payloads...)

	if stored, err := s.PutPack(owner, packID, data); err != nil || stored != n {
		t.Fatalf("PutPack stored=%d err=%v, want %d", stored, err, n)
	}
	if missing, err := s.MissingChunks(owner, ids); err != nil || len(missing) != 0 {
		t.Fatalf("missing after upload = %d err=%v, want 0", len(missing), err)
	}
	// Re-uploading the identical pack stores nothing new (dedup on chunk_id).
	if stored, err := s.PutPack(owner, packID, data); err != nil || stored != 0 {
		t.Fatalf("re-put stored=%d err=%v, want 0", stored, err)
	}
}

// An object slice that escapes the object region (into the index trailer) is
// rejected, so a crafted pack cannot smuggle an id that points at index bytes.
func TestPutPackRejectsSliceOutOfRange(t *testing.T) {
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

	if _, err := s.PutPack(owner, newID, tampered); !errors.Is(err, ErrBadPack) {
		t.Fatalf("out-of-range slice: got %v, want ErrBadPack", err)
	}
	_ = packID
}

// A crafted pack whose index offset overflows int64 (off=MaxInt64, len=1) must be
// rejected as a bad pack, not slip past the bounds check and panic the slice.
func TestPutPackRejectsOverflowSlice(t *testing.T) {
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

	if _, err := s.PutPack(owner, objID(data), data); !errors.Is(err, ErrBadPack) {
		t.Fatalf("overflowing slice: got %v, want ErrBadPack (must not panic)", err)
	}
}

// Locating an object re-arms the age guard on its pack, so a concurrent GC cannot
// reap a pack a download is mid-read of (the read-path analogue of the dedup touch).
func TestLocateRearmsAgeGuard(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "locaterace@example.com")
	packID, data, ids := packOf("download target")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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
	s := newStore(t)
	owner := s.mustAccount(t, "mine@example.com")
	other := s.mustAccount(t, "theirs@example.com")

	packID, data, ids := packOf("only mine")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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

// A replace that clears every GC root of a resource that still has some is the
// `aqt private` data-loss bug: re-sealing an object-backed resource's root blob
// without its ChunkRefs would orphan the still-referenced objects for the next GC.
// The store refuses it and leaves the resource untouched.
func TestUpdateRejectsDroppingAllRoots(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "roots@example.com")
	ck, _ := crypto.GenerateContentKey()
	packID, data, ids := packOf("obj-one", "obj-two")
	if _, err := s.PutPack(owner, packID, data); err != nil {
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

	id, _, err := s.PutResource(owner, mkReq("", 0, "v1", ids))
	if err != nil {
		t.Fatal(err)
	}

	// The root-dropping replace is rejected.
	if _, _, err := s.PutResource(owner, mkReq(id, 1, "v2", nil)); !errors.Is(err, ErrDropsRoots) {
		t.Fatalf("replace dropping all roots = %v, want ErrDropsRoots", err)
	}

	// And it changed nothing: version, roots, and the pack all survive a GC.
	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d after a refused replace, want 1", got.Version)
	}
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (roots intact)", deleted, err)
	}
	if missing, _ := s.MissingChunks(owner, ids); len(missing) != 0 {
		t.Fatal("rooted objects must survive a refused root-dropping replace")
	}

	// A replace that keeps the roots is unaffected (no false positive).
	if _, v, err := s.PutResource(owner, mkReq(id, 1, "v2", ids)); err != nil || v != 2 {
		t.Fatalf("replace keeping roots = v%d err=%v, want v2 nil", v, err)
	}
}

// The drop-roots guard only fires when the prior version actually had roots, so the
// legitimate `aqt private` on an inline file (which never had any ChunkRefs) still
// replaces in place with none.
func TestUpdateAllowsEmptyRootsWhenNoneExisted(t *testing.T) {
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
	id, _, err := s.PutResource(owner, mkReq("", 0, "v1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, v, err := s.PutResource(owner, mkReq(id, 1, "v2")); err != nil || v != 2 {
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
	s := newStore(t)
	owner := s.mustAccount(t, "racegc@example.com")
	livePayload := "live-object-keep"
	deadPayload := strings.Repeat("dead", 64) // enough dead space to make a repack candidate
	packID, data, ids := packOf(livePayload, deadPayload)
	if _, err := s.PutPack(owner, packID, data); err != nil {
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
// straight from the objects and root tables and compares them to the maintained
// columns, so a write path that forgot its recount fails the test that used it.
// The reads run on the read pool: the single writer connection cannot serve a
// nested query while a cursor is open.
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
			 WHERE o.owner_handle = ? AND o.pack_id = ? AND `+objectIsLive, owner, id,
		).Scan(&want.liveCount, &want.liveBytes); err != nil {
			t.Fatal(err)
		}
		if c != want {
			t.Fatalf("pack %s counters = %+v, recomputed %+v", id, c, want)
		}
	}
}

// The per-pack counters GC selects on must stay exact through every write that can
// move an object or flip its rooted state: pack ingest, manifest create/supersede,
// snapshot pin/unpin, resource delete, sweep, and repack.
func TestPackCountersStayConsistent(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "counters@example.com")
	ck, _ := crypto.GenerateContentKey()
	put := func(id string, expected int, refs []string) string {
		t.Helper()
		blob, _ := crypto.Seal([]byte("manifest"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		rid, _, err := s.PutResource(owner, api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expected,
		})
		if err != nil {
			t.Fatalf("put resource: %v", err)
		}
		return rid
	}

	// pack1 will mix live and dead objects (the dead one big enough to make it a
	// repack candidate); pack2 is never rooted.
	pack1, data1, ids1 := packOf("alive-a", strings.Repeat("dead-b", 60), "alive-c")
	pack2, data2, _ := packOf("never rooted")
	if _, err := s.PutPack(owner, pack1, data1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(owner, pack2, data2); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)

	// Root a+b, snapshot the pin, then supersede to a+c: b stays live only through
	// the snapshot, c flips live.
	id := put("", 0, []string{ids1[0], ids1[1]})
	s.assertPackCounters(t, owner)
	snap, err := s.CreateSnapshot(owner, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)
	put(id, 1, []string{ids1[0], ids1[2]})
	s.assertPackCounters(t, owner)

	// Dropping the snapshot unpins b: pack1 is now partly dead.
	if err := s.DeleteSnapshot(owner, snap.ID); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)

	// Repack compacts pack1's live objects into a fresh pack; the sweep then takes
	// the never-rooted pack2.
	if repacked, _, err := s.RepackOwner(owner, forceGC); err != nil || repacked != 1 {
		t.Fatalf("repack = %d err=%v, want 1", repacked, err)
	}
	s.assertPackCounters(t, owner)
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 1 {
		t.Fatalf("gc deleted %d err=%v, want 1 (pack2)", deleted, err)
	}
	s.assertPackCounters(t, owner)

	// Deleting the resource unroots a+c; the final sweep leaves no packs at all.
	if err := s.DeleteResource(owner, id); err != nil {
		t.Fatal(err)
	}
	s.assertPackCounters(t, owner)
	if deleted, _, err := s.GCPacks(owner, forceGC); err != nil || deleted != 1 {
		t.Fatalf("final gc deleted %d err=%v, want 1", deleted, err)
	}
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
	s := newStore(t)
	if _, err := s.rdb.Exec(`INSERT INTO server_meta(key, value) VALUES('nope', x'00')`); err == nil {
		t.Fatal("write on the read pool succeeded, want a query_only failure")
	}
}

// Cached token resolutions must die with their device (revocation) and their epoch
// (passphrase change) immediately, not at TTL expiry.
func TestAuthCacheInvalidation(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "authcache@example.com")
	devA, tokA, err := s.CreateDevice(owner, "keeper", 1)
	if err != nil {
		t.Fatal(err)
	}
	devB, tokB, err := s.CreateDevice(owner, "revoked", 1)
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
	_, tokC, err := s.CreateDevice(owner, "staled", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthByToken(tokC); err != nil {
		t.Fatal(err)
	}
	kdf, _ := crypto.NewKdfParams()
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

// RunGCAll (the scheduled sweep's tick body) covers every owner, so an account
// whose devices stopped syncing still gets its dead packs reclaimed.
func TestRunGCAllSweepsAllOwners(t *testing.T) {
	s := newStore(t)
	a := s.mustAccount(t, "idle-a@example.com")
	b := s.mustAccount(t, "idle-b@example.com")
	packA, dataA, _ := packOf("dead on a")
	packB, dataB, _ := packOf("dead on b")
	if _, err := s.PutPack(a, packA, dataA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutPack(b, packB, dataB); err != nil {
		t.Fatal(err)
	}

	res, err := s.RunGCAll(forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if res.DeletedPacks != 2 || res.FreedBytes != int64(len(dataA)+len(dataB)) {
		t.Fatalf("RunGCAll = %+v, want 2 packs / %d bytes across both owners",
			res, len(dataA)+len(dataB))
	}
	for _, p := range []struct{ owner, id string }{{a, packA}, {b, packB}} {
		if _, err := os.Stat(s.packPath(p.owner, p.id)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pack %s of %s survived the all-owner sweep: %v", p.id, p.owner, err)
		}
	}
}

// StartGC's timer path end-to-end: an aged, unrooted pack is reclaimed without any
// client triggering POST /v1/gc.
func TestStartGCSweepsAgedPacksOnTimer(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "sched-gc@example.com")
	packID, data, _ := packOf("orphaned by an idle account")
	if _, err := s.PutPack(owner, packID, data); err != nil {
		t.Fatal(err)
	}
	// Age the pack past the guard: the state an idle account's dropped reference
	// leaves behind.
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, packID,
	); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	New(s).StartGC(5*time.Millisecond, stop)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s.packPath(owner, packID)); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scheduled gc never swept the aged dead pack")
}
