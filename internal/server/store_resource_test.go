// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"database/sql"
	"errors"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResourceMinClientStoredVerbatim covers migration 9's column: a declared
// capability is stored exactly as declared, never adjusted. A write that declares
// less than the baseline is refused at the handler instead — see
// TestResourceWriteRefusals.
func TestResourceMinClientStoredVerbatim(t *testing.T) {
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

	baseline, _, err := s.PutResource(owner, api.CapabilityIDBinding, req(api.CapabilityBaseline))
	if err != nil {
		t.Fatal(err)
	}
	if got := stored(baseline); got != api.CapabilityBaseline {
		t.Fatalf("baseline min_client = %d, want %d", got, api.CapabilityBaseline)
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
	_ = raw.Close()

	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "older build") {
		t.Fatalf("OpenStore on a pre-pack data dir = %v, want a clear stale-schema error", err)
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
