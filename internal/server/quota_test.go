// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
	code := h.do(createOrReplace(id), "/v1/resources", token, api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &resp)
	return resp, code
}

// Replacing an existing resource must respect the owner's quota.
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
	body, err := api.EncodeResourceUpload(api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		MinClient: api.CapabilityBaseline,
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Idempotency-Key": "retry-me", "Content-Type": api.ResourceEnvelopeMediaType}

	first := h.raw(http.MethodPost, "/v1/resources", token, hdr, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first create = %d: %s", first.Code, first.Body.String())
	}
	replay := h.raw(http.MethodPost, "/v1/resources", token, hdr, body)
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
	hdr := map[string]string{"Idempotency-Key": "reused-key", "Content-Type": api.ResourceEnvelopeMediaType}
	put := func(n int) *httptest.ResponseRecorder {
		blob, _ := crypto.Seal(make([]byte, n), ck, crypto.AADBlob)
		body, err := api.EncodeResourceUpload(api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
			MinClient: api.CapabilityBaseline,
		})
		if err != nil {
			t.Fatal(err)
		}
		return h.raw(http.MethodPost, "/v1/resources", token, hdr, body)
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
