// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func (s *Store) mustGCMode(t *testing.T, owner string) api.GCMode {
	t.Helper()
	mode, err := s.GCMode(owner)
	if err != nil {
		t.Fatalf("gc mode: %v", err)
	}
	return mode
}

func (s *Store) countRows(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func putReq(t *testing.T, id string, refs []string, clientGC bool) api.PutResourceRequest {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed manifest "+id), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	return api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
		WrappedKey: &wrapped, ChunkRefs: refs, ClientGC: clientGC,
	}
}

// A ClientGC write flips the account once, permanently; a later write without the
// flag does not flip it back. Refs-less private updates are accepted and leave the
// stored rows alone, while a public or granted resource still demands refs.
func TestClientGCFlipAndRefsRules(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "flip@example.com")
	packID, pack, ids := packOf("chunk-a", "chunk-b")
	if _, err := s.PutPack(owner, packID, pack, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}

	if got := s.mustGCMode(t, owner); got != api.GCModeServer {
		t.Fatalf("initial mode = %q, want server", got)
	}
	id, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, "", ids, true))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got := s.mustGCMode(t, owner); got != api.GCModeClient {
		t.Fatalf("mode after ClientGC create = %q, want client", got)
	}

	// Refs-less private update: accepted, and the create's rows stay untouched.
	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, id, nil, true)); err != nil {
		t.Fatalf("refs-less update: %v", err)
	}
	if n := s.countRows(t, `SELECT count(*) FROM resource_chunks WHERE resource_id = ?`, id); n != len(ids) {
		t.Fatalf("resource_chunks rows = %d, want %d (left untouched)", n, len(ids))
	}

	// A refs-full write without the flag must not unflip the account.
	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, id, ids, false)); err != nil {
		t.Fatalf("refs-full update: %v", err)
	}
	if got := s.mustGCMode(t, owner); got != api.GCModeClient {
		t.Fatalf("mode after plain update = %q, want client", got)
	}

	// Granted resource: the refs-less write is refused.
	if err := s.PutGrant(owner, id, "grantee-handle", []byte("wrapped"), nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, id, nil, true)); !errors.Is(err, ErrSharedNeedsRefs) {
		t.Fatalf("refs-less granted update err = %v, want ErrSharedNeedsRefs", err)
	}

	// Public create without refs: refused up front.
	pub := putReq(t, "", nil, true)
	pub.Visibility = api.Public
	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, pub); !errors.Is(err, ErrSharedNeedsRefs) {
		t.Fatalf("public refs-less create err = %v, want ErrSharedNeedsRefs", err)
	}
}

// The no-sweep invariant of client-GC accounts: once flipped, unrooting a resource
// must not hand its objects to the pack sweep — only an explicit DeleteOwnerChunks
// reclaims them.
func TestClientGCSweepKeepsUnrootedObjects(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "nosweep@example.com")
	packID, pack, ids := packOf("payload-1", "payload-2", "payload-3")
	if _, err := s.PutPack(owner, packID, pack, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}
	id, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, "", ids, true))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.DeleteResourceVersion(owner, id, 0); err != nil {
		t.Fatalf("delete resource: %v", err)
	}
	if _, err := s.GC(owner, forceGC); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if n := s.countRows(t, `SELECT count(*) FROM objects WHERE owner_handle = ?`, owner); n != len(ids) {
		t.Fatalf("objects after unroot+GC = %d, want %d (client mode never sweeps by reachability)", n, len(ids))
	}

	deleted, skipped, freed, err := s.DeleteOwnerChunks(owner, ids, forceGC)
	if err != nil {
		t.Fatalf("delete chunks: %v", err)
	}
	if deleted != len(ids) || skipped != 0 || freed != int64(len(pack)) {
		t.Fatalf("delete = (%d, %d, %d), want (%d, 0, %d)", deleted, skipped, freed, len(ids), len(pack))
	}
	if n := s.countRows(t, `SELECT count(*) FROM objects WHERE owner_handle = ?`, owner); n != 0 {
		t.Fatalf("objects after prune = %d, want 0", n)
	}
	if b, err := s.OwnerPackBytes(owner); err != nil || b != 0 {
		t.Fatalf("pack bytes after prune = %d (%v), want 0", b, err)
	}
}

// A pack most of whose objects were pruned still holds their dead bytes; the
// repack pass must compact it even though every remaining row reads as live.
func TestClientGCRepacksSparsePacks(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "repack@example.com")
	big := make([]byte, 4096)
	for i := range big {
		big[i] = byte(i)
	}
	packID, pack, ids := packOf(string(big), "tiny survivor")
	if _, err := s.PutPack(owner, packID, pack, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}
	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, "", ids, true)); err != nil {
		t.Fatalf("flip: %v", err)
	}
	if _, _, _, err := s.DeleteOwnerChunks(owner, ids[:1], forceGC); err != nil {
		t.Fatalf("delete big chunk: %v", err)
	}
	repacked, reclaimed, err := s.RepackOwner(owner, forceGC)
	if err != nil {
		t.Fatalf("repack: %v", err)
	}
	if repacked != 1 || reclaimed <= 0 {
		t.Fatalf("repack = (%d, %d), want the sparse pack compacted", repacked, reclaimed)
	}
	if n := s.countRows(t, `SELECT count(*) FROM objects WHERE owner_handle = ?`, owner); n != 1 {
		t.Fatalf("objects after repack = %d, want the survivor only", n)
	}
}

func TestDeleteOwnerChunksGuards(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "guards@example.com")
	packID, pack, ids := packOf("young-1", "young-2")
	if _, err := s.PutPack(owner, packID, pack, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}

	// Server-managed account: refused outright.
	if _, _, _, err := s.DeleteOwnerChunks(owner, ids, forceGC); !errors.Is(err, ErrServerManagedGC) {
		t.Fatalf("server-mode delete err = %v, want ErrServerManagedGC", err)
	}

	if _, _, err := s.PutResource(owner, api.CapabilityClientGC, putReq(t, "", ids, true)); err != nil {
		t.Fatalf("flip: %v", err)
	}

	// The pack was just uploaded: inside the grace window every id is skipped, so a
	// concurrent push that re-armed it cannot lose objects it is about to reference.
	deleted, skipped, _, err := s.DeleteOwnerChunks(owner, ids, time.Hour)
	if err != nil {
		t.Fatalf("young delete: %v", err)
	}
	if deleted != 0 || skipped != len(ids) {
		t.Fatalf("young delete = (%d, %d), want (0, %d)", deleted, skipped, len(ids))
	}

	// Unknown ids are ignored, and a stale resource_chunks row (the flip left the
	// create's rows in place) must not FK-block the aged delete.
	deleted, skipped, _, err = s.DeleteOwnerChunks(owner, append([]string{objID([]byte("absent"))}, ids...), forceGC)
	if err != nil {
		t.Fatalf("aged delete: %v", err)
	}
	if deleted != len(ids) || skipped != 0 {
		t.Fatalf("aged delete = (%d, %d), want (%d, 0)", deleted, skipped, len(ids))
	}
}

// Once an account flips, a content write from a client below capability 5 gets a
// 426 naming the required capability; a capability-5 write still lands.
func TestClientGCWriteGate(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("gate@example.com", "pass phrase here")
	owners, err := h.store.Owners()
	if err != nil || len(owners) != 1 {
		t.Fatalf("owners = %v (%v), want one", owners, err)
	}
	if _, _, err := h.store.PutResource(owners[0], api.CapabilityClientGC, putReq(t, "", nil, true)); err != nil {
		t.Fatalf("flip: %v", err)
	}

	packID, pack, _ := packOf("gated payload")
	putPack := func(capability string) int {
		req := httptest.NewRequest(http.MethodPut, "/v1/packs/"+packID, bytes.NewReader(pack))
		req.Header.Set("Authorization", "Bearer "+token)
		if capability != "" {
			req.Header.Set(api.CapabilityHeader, capability)
		}
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := putPack("4"); code != http.StatusUpgradeRequired {
		t.Fatalf("capability-4 pack put = %d, want 426", code)
	}
	if code := putPack(""); code != http.StatusUpgradeRequired {
		t.Fatalf("header-less pack put = %d, want 426", code)
	}
	if code := putPack("5"); code != http.StatusOK {
		t.Fatalf("capability-5 pack put = %d, want 200", code)
	}
}

func TestListOwnerChunks(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "inventory@example.com")
	packID, pack, ids := packOf("inv-a", "inv-b", "inv-c")
	if _, err := s.PutPack(owner, packID, pack, 0); err != nil {
		t.Fatalf("put pack: %v", err)
	}
	got, next, err := s.ListOwnerChunks(owner, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if next != "" {
		t.Fatalf("next cursor = %q, want empty", next)
	}
	if len(got) != len(ids) {
		t.Fatalf("listed %d ids, want %d", len(got), len(ids))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("ids not strictly ascending: %q >= %q", got[i-1], got[i])
		}
	}
	if _, _, err := s.ListOwnerChunks(owner, "!!!not-base64!!!"); !errors.Is(err, errBadCursor) {
		t.Fatalf("bad cursor err = %v, want errBadCursor", err)
	}
}
