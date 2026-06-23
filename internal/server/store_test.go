package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
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
// not have to wait out gcMinAge to collect a just-uploaded chunk.
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

// chunkOf builds a well-formed chunk (id = hex sha256 of the data).
func chunkOf(data string) api.ChunkData {
	sum := sha256.Sum256([]byte(data))
	return api.ChunkData{ID: hex.EncodeToString(sum[:]), Data: []byte(data)}
}

func (s *Store) mustAccount(t *testing.T, email string) string {
	t.Helper()
	kdf, _ := crypto.NewKdfParams()
	acc, err := s.CreateAccount(email, kdf, make([]byte, 32))
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	return acc.OwnerHandle
}

func TestChunkStoreRoundTripAndGC(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "chunks@example.com")
	a, b := chunkOf("alpha chunk"), chunkOf("beta chunk")

	if missing, err := s.MissingChunks(owner, []string{a.ID, b.ID}); err != nil || len(missing) != 2 {
		t.Fatalf("missing before upload = %v err=%v, want 2", missing, err)
	}
	if n, err := s.PutChunks(owner, []api.ChunkData{a, b}); err != nil || n != 2 {
		t.Fatalf("put chunks: n=%d err=%v", n, err)
	}
	if missing, _ := s.MissingChunks(owner, []string{a.ID, b.ID}); len(missing) != 0 {
		t.Fatalf("missing after upload = %d, want 0", len(missing))
	}
	got, err := s.GetChunks(owner, []string{a.ID})
	if err != nil || len(got) != 1 || string(got[0].Data) != "alpha chunk" {
		t.Fatalf("get chunk: %+v err=%v", got, err)
	}

	// A poisoned address (data does not hash to id) is rejected.
	if _, err := s.PutChunks(owner, []api.ChunkData{{ID: "deadbeef", Data: []byte("x")}}); err == nil {
		t.Fatal("id/data mismatch must be rejected")
	}

	// A resource referencing chunk a roots it; an immediate sweep keeps a, drops b.
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed manifest"), ck)
	meta, _ := crypto.Seal([]byte(`{"name":"folder","size":0}`), ck)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: []string{a.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := s.GCChunks(owner, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("gc deleted %d, want 1 (only unreferenced b)", deleted)
	}
	if missing, _ := s.MissingChunks(owner, []string{a.ID}); len(missing) != 0 {
		t.Fatal("referenced chunk a must survive gc")
	}
	if missing, _ := s.MissingChunks(owner, []string{b.ID}); len(missing) != 1 {
		t.Fatal("unreferenced chunk b must be swept")
	}

	// Deleting the resource unroots a; the next sweep reclaims it.
	if err := s.DeleteResource(owner, id); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.GCChunks(owner, forceGC); err != nil || deleted != 1 {
		t.Fatalf("gc after delete removed %d err=%v, want 1", deleted, err)
	}
}

func TestUpdateResourceVersionConflict(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "occ@example.com")
	ck, _ := crypto.GenerateContentKey()

	req := func(id string, expected int, body string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck)
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

func TestConcurrentChunkWritesDoNotError(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "concurrent@example.com")

	const writers = 32
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.PutChunks(owner, []api.ChunkData{chunkOf(fmt.Sprintf("chunk %d", i))})
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

// A chunk that has aged past the guard and lost its last reference must survive
// a sweep if a concurrent sync checks it (dedup hit) before referencing it.
func TestDedupCheckReArmsGCAgeGuard(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "race@example.com")
	x := chunkOf("dedup target")
	if _, err := s.PutChunks(owner, []api.ChunkData{x}); err != nil {
		t.Fatal(err)
	}
	// Age the chunk past gcMinAge and leave it unreferenced: the state a prior
	// sync's dropped reference creates.
	if _, err := s.db.Exec(
		`UPDATE chunks SET created_at = ? WHERE owner_handle = ? AND chunk_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, x.ID,
	); err != nil {
		t.Fatal(err)
	}
	// The check a concurrent sync issues before referencing the chunk re-arms the
	// guard, so the sweep below cannot reap it in the window before that PUT.
	if missing, err := s.MissingChunks(owner, []string{x.ID}); err != nil || len(missing) != 0 {
		t.Fatalf("missing = %v err = %v, want the chunk present", missing, err)
	}
	if deleted, err := s.GCChunks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err = %v, want 0 (the dedup touch must keep the chunk)", deleted, err)
	}
	if got, err := s.GetChunks(owner, []string{x.ID}); err != nil || len(got) != 1 {
		t.Fatalf("chunk reaped despite the dedup touch: got %d err = %v", len(got), err)
	}
}

// A manifest referencing a chunk the owner does not store is rejected by the FK,
// not committed as a dangling reference; a failed update leaves the prior blob
// intact and decryptable (no leftover staged temp).
func TestManifestRejectsDanglingChunkReference(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "fk@example.com")
	ck, _ := crypto.GenerateContentKey()
	mkReq := func(id string, expected int, body string, refs []string) api.PutResourceRequest {
		blob, _ := crypto.Seal([]byte(body), ck)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
		return api.PutResourceRequest{
			ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
			WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expected,
		}
	}
	ghost := chunkOf("never uploaded").ID

	if _, _, err := s.PutResource(owner, mkReq("", 0, "v1", []string{ghost})); err == nil {
		t.Fatal("create referencing a missing chunk must be rejected")
	}

	id, _, err := s.PutResource(owner, mkReq("", 0, "v1", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutResource(owner, mkReq(id, 1, "v2", []string{ghost})); err == nil {
		t.Fatal("update introducing a missing chunk reference must be rejected")
	}

	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 {
		t.Fatalf("version = %d after a failed update, want 1 (old blob clobbered)", got.Version)
	}
	if plain, err := crypto.Open(got.Blob, ck); err != nil || string(plain) != "v1" {
		t.Fatalf("blob after a failed update = %q err = %v, want v1", plain, err)
	}
	entries, err := os.ReadDir(s.blobsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("blobsDir has %d entries, want 1 (a staged temp leaked)", len(entries))
	}
}

// Repeated updates must leave exactly one blob file on disk (superseded
// nonce-addressed blobs reclaimed) and the live blob must decrypt to the latest.
func TestUpdatesReclaimSupersededBlobs(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "blobs@example.com")
	ck, _ := crypto.GenerateContentKey()
	put := func(id string, expected int, body string) string {
		blob, _ := crypto.Seal([]byte(body), ck)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck)
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

	entries, err := os.ReadDir(s.blobsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("blobsDir has %d files after 3 writes, want 1 (superseded blobs not reclaimed)", len(entries))
	}
	got, err := s.GetResource(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := crypto.Open(got.Blob, ck); err != nil || string(plain) != "v3-final-content" {
		t.Fatalf("latest blob = %q err=%v, want v3-final-content", plain, err)
	}
}

// A data dir from an older build (resource_chunks without owner_handle) must be
// rejected loudly at open, not limped along with a broken FK backstop.
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

func TestGCDoesNotCrossOwners(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "mine@example.com")
	other := s.mustAccount(t, "theirs@example.com")

	mine := chunkOf("only mine")
	if _, err := s.PutChunks(owner, []api.ChunkData{mine}); err != nil {
		t.Fatal(err)
	}
	// Another owner's sweep must not touch my chunks.
	if deleted, err := s.GCChunks(other, forceGC); err != nil || deleted != 0 {
		t.Fatalf("cross-owner gc deleted %d err=%v, want 0", deleted, err)
	}
	if missing, _ := s.MissingChunks(owner, []string{mine.ID}); len(missing) != 0 {
		t.Fatal("my chunk must survive another owner's gc")
	}
}
