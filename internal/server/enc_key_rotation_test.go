// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestRootRotationRemovesReclaimedLegacyGrants(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("alice-review@example.com", "alice passphrase here")
	bobToken, bobMK := h.signup("bob-review@example.com", "bob passphrase here")
	alice := h.handleOf("alice-review@example.com")
	bob := h.handleOf("bob-review@example.com")
	res, code := h.putSized(aliceToken, aliceMK, "", 16)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	seed, err := hkdf.Key(sha256.New, bobMK[:], nil, "aqt-share-x25519-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	legacyPriv, err := hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyPriv.PublicKey().Bytes()
	if _, err := h.store.db.Exec(`UPDATE accounts SET enc_public_key=?, enc_key_sig=? WHERE owner_handle=?`, legacy, crypto.SignEncKey(crypto.DeriveSigningKey(bobMK), legacy), bob); err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	var info bytes.Buffer
	info.WriteString("aqt-grant-v1")
	for _, field := range []string{res.ID, alice, bob} {
		if err := binary.Write(&info, binary.BigEndian, uint16(len(field))); err != nil {
			t.Fatal(err)
		}
		info.WriteString(field)
	}
	legacyWrap, sender, err := hpke.NewSender(legacyPriv.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sender.Seal([]byte("aqt-grantwrap-v1"), ck[:])
	if err != nil {
		t.Fatal(err)
	}
	legacyWrap = append(legacyWrap, sealed...)
	if opened, err := crypto.UnwrapGrant(legacyWrap, bobMK, res.ID, alice, bob); err != nil || opened != ck {
		t.Fatalf("real legacy wrap: %v", err)
	}
	if err := h.store.PutGrant(alice, res.ID, bob, legacyWrap, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutGrant(alice, res.ID, "other-grantee", legacyWrap, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE resources SET reclaimed=1 WHERE id=?`, res.ID); err != nil {
		t.Fatal(err)
	}
	acc, err := h.store.AccountByEmail("bob-review@example.com")
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey("bob passphrase here", acc.Kdf)
	if err != nil {
		t.Fatal(err)
	}
	newRoot, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapRoot(newRoot, uk)
	if err != nil {
		t.Fatal(err)
	}
	signing := crypto.DeriveSigningKey(newRoot)
	enc := crypto.DeriveEncKey(newRoot).Public()
	verifier := crypto.DeriveAuthVerifier(uk)
	var rotated api.AuthResponse
	code = h.do(http.MethodPut, "/v1/account/root-key", bobToken, api.RootKeyRotationRequest{
		Kdf: acc.Kdf, WrappedRoot: wrapped, OldAuthVerifier: verifier, NewAuthVerifier: verifier,
		ExpectedEpoch: 1, PublicKey: signing.Public().(ed25519.PublicKey), EncPublicKey: enc,
		EncKeySig: crypto.SignEncKey(signing, enc),
	}, &rotated)
	if code != http.StatusOK {
		t.Fatalf("root rotation: %d", code)
	}
	if code := h.do(http.MethodPut, "/v1/account/enc-key", rotated.Token, api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: crypto.SignEncKey(signing, enc)}, nil); code != http.StatusNoContent {
		t.Fatalf("subsequent enc-key upgrade: %d", code)
	}
	var remaining int
	if err := h.store.db.QueryRow(`SELECT count(*) FROM grants WHERE grantee_handle=? AND length(wrapped_key)<>?`, bob, crypto.GrantWrapSize).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("root rotation published X-Wing and the follow-up upgrade returned 204, but %d dormant X25519 wrap(s) remain in the database", remaining)
	}
	stored, ok, err := h.store.grantWrappedKey(res.ID, "other-grantee")
	if err != nil || !ok || !bytes.Equal(stored, legacyWrap) {
		t.Fatalf("another grantee's wrap changed: ok=%v err=%v", ok, err)
	}
}
