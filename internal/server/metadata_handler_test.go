package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// putMetaCap PUTs a rename's metadata blob with an explicit capability header (empty
// capHdr omits it) and returns the recorder so the caller asserts the status.
func (h *harness) putMetaCap(id, token, capHdr string, req api.UpdateResourceMetadataRequest) *httptest.ResponseRecorder {
	h.t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		h.t.Fatal(err)
	}
	header := map[string]string{"Content-Type": "application/json"}
	if capHdr != "" {
		header[api.CapabilityHeader] = capHdr
	}
	return h.raw(http.MethodPut, "/v1/resources/"+id+"/metadata", token, header, body)
}

// sealedMeta builds a fresh sealed metadata blob (non-empty nonce and ciphertext), the
// shape a rename sends. The key is irrelevant to the handler, which stores it opaquely.
func sealedMeta(t *testing.T, name string) crypto.SealedBlob {
	t.Helper()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.Seal([]byte(`{"name":"`+name+`","size":4}`), ck, crypto.AADMeta)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// TestUpdateResourceMetadataHandler drives PUT /v1/resources/:id/metadata through the
// HTTP layer: happy path, input validation, version conflict, unknown id, and the
// capability gate that keeps a client too old to read the sealed format from overwriting it.
func TestUpdateResourceMetadataHandler(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, _ := h.signup("meta-handler@example.com", "a good long passphrase here")

	create, _ := sealResource(t, api.CapabilityBaseline)
	id := mustPutID(t, h.putCap(token, "2", create))

	t.Run("happy path bumps the version", func(t *testing.T) {
		rec := h.putMetaCap(id, token, "2", api.UpdateResourceMetadataRequest{
			EncryptedMeta: sealedMeta(t, "renamed"), ExpectedVersion: 1,
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
		}
		var out api.PutResourceResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if out.ID != id || out.Version != 2 {
			t.Fatalf("response = {id:%q version:%d}, want {id:%q version:2}", out.ID, out.Version, id)
		}
	})

	t.Run("rejects non-positive expectedVersion", func(t *testing.T) {
		rec := h.putMetaCap(id, token, "2", api.UpdateResourceMetadataRequest{
			EncryptedMeta: sealedMeta(t, "x"), ExpectedVersion: 0,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects empty metadata blob", func(t *testing.T) {
		rec := h.putMetaCap(id, token, "2", api.UpdateResourceMetadataRequest{
			EncryptedMeta: crypto.SealedBlob{}, ExpectedVersion: 2,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("stale expectedVersion is 409", func(t *testing.T) {
		// The happy-path update already advanced the resource to version 2.
		rec := h.putMetaCap(id, token, "2", api.UpdateResourceMetadataRequest{
			EncryptedMeta: sealedMeta(t, "stale"), ExpectedVersion: 1,
		})
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})

	t.Run("unknown id is 404", func(t *testing.T) {
		rec := h.putMetaCap("no-such-resource", token, "2", api.UpdateResourceMetadataRequest{
			EncryptedMeta: sealedMeta(t, "ghost"), ExpectedVersion: 1,
		})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("capability below min_client is 426", func(t *testing.T) {
		gated, _ := sealResource(t, api.CapabilityIDBinding)
		gatedID := mustPutID(t, h.putCap(token, "2", gated))
		rec := h.putMetaCap(gatedID, token, "1", api.UpdateResourceMetadataRequest{
			EncryptedMeta: sealedMeta(t, "nope"), ExpectedVersion: 1,
		})
		if rec.Code != http.StatusUpgradeRequired {
			t.Fatalf("status = %d, want 426", rec.Code)
		}
		var e api.ErrorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
			t.Fatalf("decode error body: %v", err)
		}
		if e.MinClient != api.CapabilityIDBinding {
			t.Fatalf("error min_client = %d, want %d", e.MinClient, api.CapabilityIDBinding)
		}
	})
}
