package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// putPublicViaAPI creates a public inline resource with a lifecycle policy through the
// HTTP handler and returns the decoded response.
func (h *harness) putPublicViaAPI(token string, mk crypto.MasterKey, expireSeconds, maxReads int64) api.PutResourceResponse {
	h.t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("public body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	var put api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ExpireSeconds: expireSeconds, MaxReads: maxReads,
	}, &put); code != http.StatusCreated {
		h.t.Fatalf("create public resource: %d", code)
	}
	return put
}

// A PUT echoes the accepted lifecycle policy, so a new client can confirm the server
// enforces it.
func TestPutResourceEchoesPolicy(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("echo@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 3600, 4)

	if put.MaxReads != 4 {
		t.Fatalf("echoed maxReads = %d, want 4", put.MaxReads)
	}
	if now := time.Now().Unix(); put.ExpiresAt < now+3500 || put.ExpiresAt > now+3700 {
		t.Fatalf("echoed expiresAt = %d, want near now+3600", put.ExpiresAt)
	}
}

// SetVisibility echoes the applied policy the same way, so `aqt share --expire` can
// fail closed against an old server.
func TestSetVisibilityEchoesPolicy(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("svecho@example.com", "a passphrase here")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	var put api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	}, &put); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}

	var resp api.PutResourceResponse
	if code := h.do(http.MethodPost, "/v1/resources/"+put.ID+"/visibility", token,
		api.SetVisibilityRequest{Visibility: api.Public, MaxReads: 2}, &resp); code != http.StatusOK {
		t.Fatalf("set visibility: %d", code)
	}
	if resp.MaxReads != 2 {
		t.Fatalf("echoed maxReads = %d, want 2", resp.MaxReads)
	}
}

// An expired public resource returns 410 with the stable "gone" code, not a 404.
func TestGetResourceExpiredReturns410(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("gone410@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 3600, 0)
	h.store.pokeExpiry(t, put.ID, time.Now().Add(-time.Minute).Unix())

	rec := h.get("/v1/resources/" + put.ID)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410; body=%s", rec.Code, rec.Body.String())
	}
	var e api.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != api.ErrCodeGone {
		t.Fatalf("code = %q, want %q", e.Code, api.ErrCodeGone)
	}
}

// A max-reads-exhausted public resource returns 410 to the next reader.
func TestGetResourceExhaustedReturns410(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("exhaust410@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 0, 1)

	if rec := h.get("/v1/resources/" + put.ID); rec.Code != http.StatusOK {
		t.Fatalf("first read = %d, want 200", rec.Code)
	}
	if rec := h.get("/v1/resources/" + put.ID); rec.Code != http.StatusGone {
		t.Fatalf("second read = %d, want 410", rec.Code)
	}
}

// publicObjects 410s on an expired/reclaimed resource, but still serves an exhausted
// (not-yet-swept) one so the final permitted streamed pull can complete.
func TestPublicObjectsGoneVsExhausted(t *testing.T) {
	h := newHarness(t)
	token, _ := h.signup("pubobj@example.com", "a passphrase here")
	owner, _ := h.store.OwnerByToken(token)

	packID, data, ids := packOf("streamed bytes")
	if _, err := h.store.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	// A public streamed resource with a one-read limit.
	id := h.store.putPublic(t, owner, "sealed root", 0, 1)
	if _, err := h.store.db.Exec(
		`INSERT INTO resource_chunks(resource_id, owner_handle, chunk_id) VALUES(?,?,?)`,
		id, owner, ids[0],
	); err != nil {
		t.Fatal(err)
	}

	// Consume the single root read, exhausting the resource.
	if rec := h.get("/v1/resources/" + id); rec.Code != http.StatusOK {
		t.Fatalf("root read = %d, want 200", rec.Code)
	}
	// Object fetch still works while exhausted-but-not-swept (the in-flight pull).
	if rec := postPublicObjects(t, h.router, id, ids); rec.Code != http.StatusOK {
		t.Fatalf("object fetch while exhausted = %d, want 200", rec.Code)
	}
	// Once expired, the object endpoint is gone.
	h.store.pokeExpiry(t, id, time.Now().Add(-time.Minute).Unix())
	if rec := postPublicObjects(t, h.router, id, ids); rec.Code != http.StatusGone {
		t.Fatalf("object fetch after expiry = %d, want 410", rec.Code)
	}
}

// The /x/<id> landing page renders a 410 gone page for an expired public link.
func TestShareViewGonePage(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("shareview@example.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 3600, 0)
	h.store.pokeExpiry(t, put.ID, time.Now().Add(-time.Minute).Unix())

	rec := h.get("/x/" + put.ID)
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "expired") {
		t.Fatalf("gone page missing expiry copy: %s", body)
	}
}

func TestPublicPreflightDoesNotConsumeBurnRead(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("preflight.com", "a passphrase here")
	put := h.putPublicViaAPI(token, mk, 0, 1)
	for i := 0; i < 2; i++ {
		rec := h.get("/v1/public/resources/" + put.ID + "/preflight")
		if rec.Code != http.StatusOK {
			t.Fatalf("preflight %d = %d: %s", i, rec.Code, rec.Body.String())
		}
		var got api.PublicResourcePreflight
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.ID != put.ID || got.Reads != 0 || got.MaxReads != 1 || len(got.EncryptedMeta.Ciphertext) == 0 {
			t.Fatalf("preflight = %+v", got)
		}
		if strings.Contains(rec.Body.String(), "ciphertextBlob") || strings.Contains(rec.Body.String(), "wrappedKey") {
			t.Fatalf("preflight leaked content fields: %s", rec.Body.String())
		}
	}
	if rec := h.get("/v1/resources/" + put.ID); rec.Code != http.StatusOK {
		t.Fatalf("counted read = %d", rec.Code)
	}
	if rec := h.get("/v1/public/resources/" + put.ID + "/preflight"); rec.Code != http.StatusGone {
		t.Fatalf("preflight after burn = %d", rec.Code)
	}
}
