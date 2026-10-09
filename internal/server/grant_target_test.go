// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestGrantTargetPreconditionTreatsRealAndDecoyAlike(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	_, _ = h.signup("bob@example.com", "bob passphrase here")
	_, _ = h.signup("legacy@example.com", "legacy passphrase here")
	if _, err := h.store.db.Exec(`UPDATE accounts SET enc_public_key=? WHERE email=?`, make([]byte, 32), "legacy@example.com"); err != nil {
		t.Fatal(err)
	}
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	for _, email := range []string{"bob@example.com", "unknown@example.com", "legacy@example.com"} {
		var keys api.AccountKeysResponse
		if code := h.do(http.MethodGet, "/v1/account/keys?email="+email, aliceToken, nil, &keys); code != http.StatusOK {
			t.Fatal(code)
		}
		wrap, err := crypto.WrapGrant(crypto.ContentKey{}, keys.EncPublicKey, res.ID, h.handleOf("alice@example.com"), keys.Handle)
		if err != nil {
			t.Fatal(err)
		}
		req := api.CreateGrantRequest{GranteeHandle: keys.Handle, WrappedKey: wrap, GranteeEmail: email, GranteeEncPublicKey: keys.EncPublicKey}
		if rec := h.doAt(api.ClientCapability, http.MethodPost, "/v1/resources/"+res.ID+"/grants", aliceToken, req); rec.Code != http.StatusCreated {
			t.Fatalf("%s: matching lookup = %d %s", email, rec.Code, rec.Body)
		}
		req.GranteeEncPublicKey = bytes.Repeat([]byte{1}, crypto.EncPublicKeySize)
		var refused api.ErrorResponse
		if code := h.do(http.MethodPost, "/v1/resources/"+res.ID+"/grants", aliceToken, req, &refused); code != http.StatusConflict || refused.Code != api.ErrCodeVersionConflict {
			t.Fatalf("%s: mismatched lookup = %d %+v, want 409 version_conflict", email, code, refused)
		}
		stored, ok, err := h.store.grantWrappedKey(res.ID, keys.Handle)
		if err != nil || !ok || !bytes.Equal(stored, wrap) {
			t.Fatalf("%s: mismatched lookup changed the grant: ok=%v err=%v", email, ok, err)
		}
		for _, incomplete := range []api.CreateGrantRequest{
			{GranteeHandle: keys.Handle, WrappedKey: wrap, GranteeEmail: email},
			{GranteeHandle: keys.Handle, WrappedKey: wrap, GranteeEncPublicKey: keys.EncPublicKey},
		} {
			if rec := h.doAt(api.ClientCapability, http.MethodPost, "/v1/resources/"+res.ID+"/grants", aliceToken, incomplete); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: incomplete lookup precondition = %d, want 400", email, rec.Code)
			}
		}
	}
}

// A grantee's share list carries who the server says sent each row: the grantor's
// email and identity key, joined from the grantor's account rather than the caller's.
func TestListSharesCarriesTheGrantorsClaim(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	bobToken, _ := h.signup("bob@example.com", "bob passphrase here")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	if err := h.store.PutGrant(h.handleOf("alice@example.com"), res.ID, h.handleOf("bob@example.com"), make([]byte, crypto.GrantWrapSize), nil); err != nil {
		t.Fatal(err)
	}

	var list api.ListSharesResponse
	if code := h.do(http.MethodGet, "/v1/shares", bobToken, nil, &list); code != http.StatusOK {
		t.Fatal(code)
	}
	if len(list.Shares) != 1 {
		t.Fatalf("shares = %+v, want one", list.Shares)
	}
	got := list.Shares[0]
	alicePub := crypto.DeriveSigningKey(aliceMK).Public().(ed25519.PublicKey)
	if got.OwnerEmail != "alice@example.com" || !bytes.Equal(got.OwnerPublicKey, alicePub) {
		t.Fatalf("share names %q / %x, want alice's email and identity key", got.OwnerEmail, got.OwnerPublicKey)
	}
}
