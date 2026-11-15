// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// A client from before signed grants gets a 426 on every route that writes or hands
// out a grant, a grant without the owner's signature is refused, and a signed one is
// stored and returned opaquely to the owner and the grantee alike.
func TestGrantRoutesNeedASigningClient(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	bobToken, _ := h.signup("bob@example.com", "bob passphrase here")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatalf("create resource = %d", code)
	}
	bob := h.handleOf("bob@example.com")
	grantsPath := "/v1/resources/" + res.ID + "/grants"

	const old = api.CapabilityPQGrants
	for _, r := range []struct{ method, path, token string }{
		{http.MethodPost, grantsPath, aliceToken},
		{http.MethodGet, grantsPath, aliceToken},
		{http.MethodPut, "/v1/account/root-key", aliceToken},
		{http.MethodGet, "/v1/shares", bobToken},
	} {
		if rec := h.doAt(old, r.method, r.path, r.token, nil); rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s %s at capability %d = %d, want 426", r.method, r.path, old, rec.Code)
		}
	}

	grant := api.CreateGrantRequest{GranteeHandle: bob, WrappedKey: make([]byte, crypto.GrantWrapSize)}
	if rec := h.doAt(api.ClientCapability, http.MethodPost, grantsPath, aliceToken, grant); rec.Code != http.StatusBadRequest {
		t.Fatalf("unsigned grant = %d, want 400", rec.Code)
	}
	grant.Signature = bytes.Repeat([]byte{7}, ed25519.SignatureSize)
	if rec := h.doAt(api.ClientCapability, http.MethodPost, grantsPath, aliceToken, grant); rec.Code != http.StatusCreated {
		t.Fatalf("signed grant = %d %s, want 201", rec.Code, rec.Body)
	}
	if rec := h.getCap(res.ID, bobToken, strconv.Itoa(old)); rec.Code != http.StatusUpgradeRequired {
		t.Errorf("grantee read at capability %d = %d, want 426", old, rec.Code)
	}

	var listed api.ListGrantsResponse
	if code := h.do(http.MethodGet, grantsPath, aliceToken, nil, &listed); code != http.StatusOK || len(listed.Grants) != 1 || !bytes.Equal(listed.Grants[0].Signature, grant.Signature) {
		t.Fatalf("owner's grant listing = %d %+v, want the stored signature", code, listed)
	}
	var shares api.ListSharesResponse
	if code := h.do(http.MethodGet, "/v1/shares", bobToken, nil, &shares); code != http.StatusOK || len(shares.Shares) != 1 || !bytes.Equal(shares.Shares[0].Signature, grant.Signature) {
		t.Fatalf("grantee's share listing = %d %+v, want the stored signature", code, shares)
	}
	rec := h.getCap(res.ID, bobToken, strconv.Itoa(api.ClientCapability))
	var read api.GetResourceResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &read) != nil {
		t.Fatalf("grantee read = %d %s", rec.Code, rec.Body)
	}
	aliceKey := crypto.DeriveSigningKey(aliceMK).Public().(ed25519.PublicKey)
	if !bytes.Equal(read.GrantSig, grant.Signature) || !bytes.Equal(read.OwnerPublicKey, aliceKey) {
		t.Fatalf("grantee read carries signature %x and owner key %x, want the stored signature and alice's identity key", read.GrantSig, read.OwnerPublicKey)
	}
}
