// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// putSized creates or replaces a resource with an n-byte body, returning the status.
func (h *harness) putSized(token string, mk crypto.MasterKey, id string, n int) (api.PutResourceResponse, int) {
	h.t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(make([]byte, n), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	var resp api.PutResourceResponse
	code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &resp)
	return resp, code
}

// The quota check used to run only on create, so an in-place update wrote an
// arbitrary blob past it — the headline feature of the release, bypassed by a PUT
// that carried an id.
func TestQuotaAppliesToInPlaceUpdate(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{QuotaBytes: 64 * 1024})
	token, mk := h.signup("quota-update@example.com", "a passphrase here")

	small, code := h.putSized(token, mk, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create small resource = %d, want 201", code)
	}
	if _, code := h.putSized(token, mk, small.ID, 1<<20); code != http.StatusInsufficientStorage {
		t.Fatalf("1 MiB update under a 64 KiB quota = %d, want 507", code)
	}
	var usage api.UsageResponse
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, &usage); code != http.StatusOK {
		t.Fatalf("usage = %d", code)
	}
	if usage.StorageBytes > usage.QuotaBytes {
		t.Fatalf("storage %d exceeds quota %d", usage.StorageBytes, usage.QuotaBytes)
	}
}

// An update replaces the resource's bytes rather than adding to them, so rewriting a
// resource at its current size must not be charged twice and trip the quota.
func TestQuotaChargesOnlyTheUpdateDelta(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{QuotaBytes: 96 * 1024})
	token, mk := h.signup("quota-delta@example.com", "a passphrase here")

	res, code := h.putSized(token, mk, "", 48*1024)
	if code != http.StatusCreated {
		t.Fatalf("create = %d, want 201", code)
	}
	for i := range 4 {
		if _, code := h.putSized(token, mk, res.ID, 48*1024); code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("same-size rewrite %d = %d, want it accepted", i, code)
		}
	}
}

// A create replayed under its Idempotency-Key stores nothing new. Charging it as a
// fresh create answered 507 for a resource that already existed, defeating the retry
// the key exists for.
func TestIdempotentCreateReplayNotChargedAgain(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{QuotaBytes: 96 * 1024})
	token, mk := h.signup("quota-replay@example.com", "a passphrase here")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal(make([]byte, 64*1024), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	body, err := json.Marshal(api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Idempotency-Key": "retry-me", "Content-Type": "application/json"}

	first := h.raw(http.MethodPut, "/v1/resources", token, hdr, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create = %d: %s", first.Code, first.Body.String())
	}
	replay := h.raw(http.MethodPut, "/v1/resources", token, hdr, body)
	if replay.Code != http.StatusCreated {
		t.Fatalf("replayed create = %d (507 means it was charged as a fresh create): %s", replay.Code, replay.Body.String())
	}
	if replay.Body.String() != first.Body.String() {
		t.Fatalf("replay returned a different resource:\n%s\n%s", first.Body.String(), replay.Body.String())
	}
}

// A reused Idempotency-Key with a different payload can never store anything, so the
// key conflict must win over the quota: answering 507 (as the digest-hashing quota
// preflight once did) told the client to free space for a request that would still
// be refused afterwards.
func TestConflictingIdempotencyKeyWinsOverQuota(t *testing.T) {
	t.Parallel()
	h := newHarnessCfg(t, Config{QuotaBytes: 96 * 1024})
	token, mk := h.signup("quota-conflict@example.com", "a passphrase here")

	ck, _ := crypto.GenerateContentKey()
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	hdr := map[string]string{"Idempotency-Key": "reused-key", "Content-Type": "application/json"}
	put := func(n int) *httptest.ResponseRecorder {
		blob, _ := crypto.Seal(make([]byte, n), ck, crypto.AADBlob)
		body, err := json.Marshal(api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		})
		if err != nil {
			t.Fatal(err)
		}
		return h.raw(http.MethodPut, "/v1/resources", token, hdr, body)
	}

	if first := put(16); first.Code != http.StatusCreated {
		t.Fatalf("first create = %d: %s", first.Code, first.Body.String())
	}
	conflict := put(1 << 20)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflicting key over quota = %d, want 409: %s", conflict.Code, conflict.Body.String())
	}
	var resp api.ErrorResponse
	if err := json.Unmarshal(conflict.Body.Bytes(), &resp); err != nil || resp.Code != api.ErrCodeIdempotencyConflict {
		t.Fatalf("conflict code = %q (err %v), want %q", resp.Code, err, api.ErrCodeIdempotencyConflict)
	}
}

// A read the server goes on to refuse serves no bytes, so it must not spend one of a
// --burn / --max-reads link's permits. Both refusal paths run before the count.
func TestRefusedReadDoesNotSpendAPermit(t *testing.T) {
	t.Parallel()
	t.Run("stale capability", func(t *testing.T) {
		h := newHarness(t)
		token, mk := h.signup("burn-cap@example.com", "a passphrase here")
		ck, _ := crypto.GenerateContentKey()
		blob, _ := crypto.Seal([]byte("public body"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
		wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
		rec := h.putCap(token, "2", api.PutResourceRequest{
			Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
			MaxReads: 1, MinClient: api.CapabilityIDBinding,
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
		}
		var put api.PutResourceResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &put); err != nil {
			t.Fatal(err)
		}
		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", map[string]string{"X-Aqt-Capability": "1"}, nil); got.Code != http.StatusUpgradeRequired {
			t.Fatalf("stale-capability read = %d, want 426", got.Code)
		}
		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", map[string]string{"X-Aqt-Capability": "2"}, nil); got.Code != http.StatusOK {
			t.Fatalf("the recipient's read after a 426 = %d, want 200 (410 means the 426 burned the permit)", got.Code)
		}
	})

	t.Run("unacceptable Accept", func(t *testing.T) {
		h := newHarness(t)
		token, mk := h.signup("burn-accept@example.com", "a passphrase here")
		put := h.putPublicViaAPI(token, mk, 0, 1)

		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", map[string]string{"Accept": "text/html"}, nil); got.Code != http.StatusNotAcceptable {
			t.Fatalf("text/html read = %d, want 406", got.Code)
		}
		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil); got.Code != http.StatusOK {
			t.Fatalf("the recipient's read after a 406 = %d, want 200 (410 means the 406 burned the permit)", got.Code)
		}
	})

	t.Run("exhaustion is still enforced", func(t *testing.T) {
		h := newHarness(t)
		token, mk := h.signup("burn-exhaust@example.com", "a passphrase here")
		put := h.putPublicViaAPI(token, mk, 0, 1)

		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil); got.Code != http.StatusOK {
			t.Fatalf("first read = %d, want 200", got.Code)
		}
		if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil); got.Code != http.StatusGone {
			t.Fatalf("second read = %d, want 410", got.Code)
		}
	})
}

// DeleteGrant's failing Exec used to return without rolling back. The writer handle
// is a single connection, so the abandoned transaction held it forever and every
// later write on the server — for any account — blocked indefinitely.
func TestDeleteGrantRollsBackOnExecFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("txleak@example.com", "a passphrase here")
	grantee, _ := h.signup("txleak-g@example.com", "a passphrase here")
	granteeOwner, _ := h.store.OwnerByToken(grantee)
	owner, _ := h.store.OwnerByToken(token)

	res, code := h.putSized(token, mk, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create = %d", code)
	}
	if err := h.store.PutGrant(owner, res.ID, granteeOwner, []byte("wrap"), 0); err != nil {
		t.Fatalf("put grant: %v", err)
	}
	// Make the DELETE inside the transaction fail the way SQLITE_BUSY or an I/O
	// error would.
	if _, err := h.store.db.Exec(
		`CREATE TRIGGER audit_txleak BEFORE DELETE ON grants BEGIN SELECT RAISE(ABORT, 'boom'); END`,
	); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	if err := h.store.DeleteGrant(owner, res.ID, granteeOwner); err == nil {
		t.Fatal("DeleteGrant unexpectedly succeeded")
	}
	if _, err := h.store.db.Exec(`DROP TRIGGER audit_txleak`); err != nil {
		t.Fatalf("the writer connection is still held: %v", err)
	}

	// The writer must still be usable.
	done := make(chan error, 1)
	go func() { done <- h.store.PutGrant(owner, res.ID, granteeOwner, []byte("wrap2"), 0) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write after the rolled-back delete: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the next store write blocked: the transaction leaked its connection")
	}
}

// A reclaimed tombstone answers 410 to everyone, including the owner, whose only
// remaining action is to delete the row. The delete must therefore work.
func TestReclaimedTombstoneIsDeletable(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("tombstone@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 0, 1)

	if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil); got.Code != http.StatusOK {
		t.Fatalf("first public read = %d, want 200", got.Code)
	}
	owner, _ := h.store.OwnerByToken(token)
	if _, err := h.store.SweepExpired(owner, time.Now().Unix()+2*int64(gcMinAge/time.Second)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// An unpinned delete is what the client falls back to once the version fetch
	// reports 410; it must be accepted.
	if code := h.do(http.MethodDelete, "/v1/resources/"+put.ID, token, nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete of a tombstone = %d, want 204", code)
	}
	var list api.ListResourcesResponse
	if code := h.do(http.MethodGet, "/v1/resources", token, nil, &list); code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	if len(list.Resources) != 0 {
		t.Fatalf("listing still has %d row(s) after deleting the tombstone", len(list.Resources))
	}
}

// Snapshotting a reclaimed tombstone has no ciphertext to pin. It used to 500, which
// violates the stable-error-code contract and which the client's idempotent retry
// treats as worth repeating.
func TestSnapshotOfTombstoneIsGoneNot500(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("snap-tombstone@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 0, 1)

	if got := h.raw(http.MethodGet, "/v1/resources/"+put.ID, "", nil, nil); got.Code != http.StatusOK {
		t.Fatalf("first read = %d", got.Code)
	}
	owner, _ := h.store.OwnerByToken(token)
	if _, err := h.store.SweepExpired(owner, time.Now().Unix()+2*int64(gcMinAge/time.Second)); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if code := h.do(http.MethodPost, "/v1/snapshots", token, api.CreateSnapshotRequest{ResourceID: put.ID}, nil); code != http.StatusGone {
		t.Fatalf("snapshot of a tombstone = %d, want 410", code)
	}
}

// Cobra parses a leading dash as a flag cluster, so an id starting with one is
// unaddressable as a bare CLI positional. Both generators fold it identically, which
// is what keeps a deterministic decoy handle indistinguishable from a minted id.
func TestMintedIDsNeverStartWithADash(t *testing.T) {
	t.Parallel()
	for range 20_000 {
		if id := newID(8); id[0] == '-' {
			t.Fatalf("newID produced %q", id)
		}
	}
	// The decoy generator must fold the same way, or a leading character would
	// distinguish a decoy from a real handle and reintroduce an existence oracle.
	if got := newIDFrom([]byte{0xfb, 0xff, 0xff}); got[0] == '-' {
		t.Fatalf("newIDFrom produced %q", got)
	}
}

// The signup decoy exists so a duplicate signup does not confirm an address. It must
// still tell the account's actual owner what happened, since someone presenting the
// account's own passphrase verifier already has everything the answer would leak.
func TestDuplicateSignupConfirmsOnlyToTheOwner(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	req := createReq(t, "dup@example.com", "a passphrase here")
	var first api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", req, &first); code != http.StatusCreated {
		t.Fatalf("signup = %d", code)
	}

	// Same passphrase: the caller owns the account, so it is named plainly.
	var owned api.ErrorResponse
	if code := h.do(http.MethodPost, "/v1/account", "", req, &owned); code != http.StatusConflict {
		t.Fatalf("duplicate signup with the right passphrase = %d, want 409", code)
	}
	if owned.Code != api.ErrCodeAccountExists {
		t.Fatalf("error code = %q, want %q", owned.Code, api.ErrCodeAccountExists)
	}

	// Different passphrase: indistinguishable from a fresh signup.
	other := createReq(t, "dup@example.com", "a different passphrase")
	var decoy api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", other, &decoy); code != http.StatusCreated {
		t.Fatalf("duplicate signup with the wrong passphrase = %d, want the 201 decoy", code)
	}
	if decoy.Token == first.Token || decoy.OwnerHandle == first.OwnerHandle {
		t.Fatal("the decoy leaked the real account's credentials")
	}
	if len(decoy.OwnerHandle) != len(first.OwnerHandle) || len(decoy.Token) != len(first.Token) {
		t.Fatal("the decoy is distinguishable from a real response by field length")
	}
}

// 429 carries a stable code like every other error condition, so a client can branch
// on it without string-matching the message.
func TestRateLimitCarriesStableCode(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	limiter := newIPRateLimiter(0.01, 1)
	h.router.GET("/audit-ratelimit", limiter.middleware, func(c *gin.Context) { c.Status(http.StatusOK) })

	if got := h.get("/audit-ratelimit"); got.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", got.Code)
	}
	got := h.get("/audit-ratelimit")
	if got.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", got.Code)
	}
	var body api.ErrorResponse
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != api.ErrCodeRateLimited {
		t.Fatalf("429 code = %q, want %q", body.Code, api.ErrCodeRateLimited)
	}
	if got.Header().Get("Retry-After") == "" {
		t.Fatal("429 carries no Retry-After")
	}
}
