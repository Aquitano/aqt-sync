// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestRootRotationRemovesReclaimedXWingGrants(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
	bobToken, bobMK := h.signup("bob@example.com", "bob passphrase here")
	alice, bob := h.handleOf("alice@example.com"), h.handleOf("bob@example.com")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	wrap, err := crypto.WrapGrant(crypto.ContentKey{}, crypto.DeriveEncKey(bobMK).Public(), res.ID, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutGrant(alice, res.ID, bob, wrap, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE resources SET reclaimed=1 WHERE id=?`, res.ID); err != nil {
		t.Fatal(err)
	}
	acc, err := h.store.AccountByEmail("bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey("bob passphrase here", acc.Kdf)
	if err != nil {
		t.Fatal(err)
	}
	defer uk.Wipe()
	newRoot, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	defer newRoot.Wipe()
	wrapped, err := crypto.WrapRoot(newRoot, uk)
	if err != nil {
		t.Fatal(err)
	}
	signing := crypto.DeriveSigningKey(newRoot)
	enc := crypto.DeriveEncKey(newRoot).Public()
	verifier := crypto.DeriveAuthVerifier(uk)
	code = h.do(http.MethodPut, "/v1/account/root-key", bobToken, api.RootKeyRotationRequest{
		Kdf: acc.Kdf, WrappedRoot: wrapped, OldAuthVerifier: verifier, NewAuthVerifier: verifier,
		ExpectedEpoch: 1, PublicKey: signing.Public().(ed25519.PublicKey), EncPublicKey: enc,
		EncKeySig: crypto.SignEncKey(signing, enc),
	}, nil)
	if code != http.StatusOK {
		t.Fatalf("root rotation = %d", code)
	}
	if _, ok, err := h.store.grantWrappedKey(res.ID, bob); err != nil || ok {
		t.Fatalf("reclaimed X-Wing wrap still depends on the destroyed root: ok=%v err=%v", ok, err)
	}
	if _, code := h.putSized(aliceToken, aliceMK, res.ID, 16); code != http.StatusOK {
		t.Fatalf("revive resource = %d", code)
	}
	if _, err := h.store.GetResource(res.ID, bob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revived resource served a grant that no longer opens: %v", err)
	}
}
