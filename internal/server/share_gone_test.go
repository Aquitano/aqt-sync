// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// A burned or read-exhausted link must be gone the moment its last permit is
// spent: GET /x/:id used to keep serving a live 200 share page until the GC sweep
// tombstoned the row — up to hours after the owner believed the link was dead
// (issue #180). The landing page must answer 410 as soon as reads are exhausted.
func TestShareViewGoneOnceReadsExhausted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	token, mk := h.signup("burned@example.com", "a passphrase for burned links")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	var resp api.PutResourceResponse
	if code := h.do(http.MethodPost, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		MaxReads: 1,
	}, &resp); code != http.StatusCreated {
		t.Fatalf("put: status %d", code)
	}

	// The link is live before its permit is spent.
	if rec := h.get("/x/" + resp.ID); rec.Code != http.StatusOK {
		t.Fatalf("fresh link: got %d, want 200", rec.Code)
	}

	// Spend the only read permit.
	if err := h.store.CountResourceRead(resp.ID); err != nil {
		t.Fatalf("spend read permit: %v", err)
	}

	// No GC has run; the landing page must already refuse.
	if rec := h.get("/x/" + resp.ID); rec.Code != http.StatusGone {
		t.Fatalf("exhausted link: got %d, want 410", rec.Code)
	}
}
