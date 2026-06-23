package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
