// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
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
	if !bytes.Equal(read.GrantSig, grant.Signature) || !bytes.Equal(read.OwnerPublicKey, aliceKey) || read.OwnerEmail != "alice@example.com" {
		t.Fatalf("grantee read carries signature %x, owner key %x and email %q, want the stored signature and alice's identity key and email", read.GrantSig, read.OwnerPublicKey, read.OwnerEmail)
	}
}

// A root-key rotation re-signs the owner's grants under its new identity, and it has to
// name every one: a grant created after the client listed them would otherwise keep a
// signature under the identity the rotation retires. A request that misses one is
// refused. One that names a grant without a new signature keeps the stored one, which
// is how a client passes over a grant its old identity never signed for the current key.
func TestRootRotationNamesEveryOutgoingGrant(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "owner@example.com")
	bob, carol, dave := s.mustAccount(t, "bob@example.com"), s.mustAccount(t, "carol@example.com"), s.mustAccount(t, "dave@example.com")
	deviceID, _, err := s.CreateDevice(owner, "laptop", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, nil)
	signed, stale := bytes.Repeat([]byte{1}, ed25519.SignatureSize), bytes.Repeat([]byte{2}, ed25519.SignatureSize)
	wrap := make([]byte, crypto.GrantWrapSize)
	if err := s.putGrant(owner, rid, bob, wrap, signed, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.putGrant(owner, rid, carol, wrap, stale, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(owner, rid, dave, wrap, nil); err != nil {
		t.Fatal(err)
	}
	res, err := s.GetResource(rid, owner)
	if err != nil {
		t.Fatal(err)
	}
	resigned := bytes.Repeat([]byte{3}, ed25519.SignatureSize)
	req := rotateReq([]api.KeyWrapMigration{{ID: rid, WrappedKey: wrappedTestKey(t), ExpectedVersion: res.Version}})
	req.OutgoingGrants = []api.GrantSignatureMigration{
		{ResourceID: rid, GranteeHandle: bob, Signature: resigned, ExpectedSignature: signed},
		{ResourceID: rid, GranteeHandle: carol, ExpectedSignature: stale},
	}
	if _, _, err := s.RotateRootKey(owner, deviceID, req); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("rotation that leaves out dave's grant = %v, want ErrVersionConflict", err)
	}
	req.OutgoingGrants = append(req.OutgoingGrants, api.GrantSignatureMigration{ResourceID: rid, GranteeHandle: dave})
	if _, _, err := s.RotateRootKey(owner, deviceID, req); err != nil {
		t.Fatalf("rotation naming every grant: %v", err)
	}
	for grantee, want := range map[string][]byte{bob: resigned, carol: stale, dave: nil} {
		var got []byte
		if err := s.rdb.QueryRow(`SELECT signature FROM grants WHERE resource_id = ? AND grantee_handle = ?`, rid, grantee).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("signature on %s's grant after the rotation = %x, want %x", grantee, got, want)
		}
	}
}
