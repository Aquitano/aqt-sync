// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func testMasterKey(t *testing.T) MasterKey {
	t.Helper()
	mk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

// TestGrantWrapRoundTrip proves a content key wrapped to the grantee's derived
// key opens under the same (resource, owner, grantee) binding.
func TestGrantWrapRoundTrip(t *testing.T) {
	ownerMK := testMasterKey(t)
	granteeMK := testMasterKey(t)
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	_ = ownerMK // the owner needs no key material beyond ck; the wrap targets the grantee

	wrapped, err := WrapGrant(ck, DeriveEncKey(granteeMK).Public(), "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapGrant(wrapped, granteeMK, "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got != ck {
		t.Fatal("unwrapped key differs from the original content key")
	}
}

// TestGrantWrapInfoMismatch proves the info binding: the same wrap fails to open
// when any of the three context fields changes, and no concatenation ambiguity
// lets shifted field boundaries collide.
func TestGrantWrapInfoMismatch(t *testing.T) {
	granteeMK := testMasterKey(t)
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapGrant(ck, DeriveEncKey(granteeMK).Public(), "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ res, owner, grantee string }{
		{"res2", "owner1", "grantee1"},
		{"res1", "owner2", "grantee1"},
		{"res1", "owner1", "grantee2"},
		{"res1owner1", "", "grantee1"}, // shifted field boundary
		{"", "", ""},
	}
	for _, c := range cases {
		if _, err := UnwrapGrant(wrapped, granteeMK, c.res, c.owner, c.grantee); err == nil {
			t.Errorf("grant opened under mismatched info (%q,%q,%q)", c.res, c.owner, c.grantee)
		}
	}
}

// TestGrantWrapWrongKey proves a wrap to one account cannot be opened by another.
func TestGrantWrapWrongKey(t *testing.T) {
	granteeMK := testMasterKey(t)
	otherMK := testMasterKey(t)
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapGrant(ck, DeriveEncKey(granteeMK).Public(), "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapGrant(wrapped, otherMK, "res1", "owner1", "grantee1"); err == nil {
		t.Fatal("grant opened under a different account's key")
	}
	if _, err := UnwrapGrant(wrapped[:10], granteeMK, "res1", "owner1", "grantee1"); err == nil {
		t.Fatal("truncated grant opened")
	}
}

// TestDeriveEncKeyDeterministic pins that the enc keypair is a pure function of
// the master key, so every unlocked device derives the same published key.
func TestDeriveEncKeyDeterministic(t *testing.T) {
	mk := testMasterKey(t)
	a, b := DeriveEncKey(mk).Public(), DeriveEncKey(mk).Public()
	if !bytes.Equal(a, b) {
		t.Fatal("enc key derivation is not deterministic")
	}
	if len(a) != EncPublicKeySize {
		t.Fatalf("enc public key length = %d, want %d", len(a), EncPublicKeySize)
	}
	other := testMasterKey(t)
	if bytes.Equal(a, DeriveEncKey(other).Public()) {
		t.Fatal("distinct master keys derived the same enc key")
	}
}

// TestEncKeyBinding covers the Ed25519 self-signature over the enc public key:
// it verifies for the signing identity, and fails for a swapped enc key, a
// tampered signature, or a different identity.
func TestEncKeyBinding(t *testing.T) {
	mk := testMasterKey(t)
	identity := DeriveSigningKey(mk)
	identityPub := identity.Public().(ed25519.PublicKey)
	encPub := DeriveEncKey(mk).Public()
	sig := SignEncKey(identity, encPub)
	if !VerifyEncKey(identityPub, encPub, sig) {
		t.Fatal("binding signature did not verify")
	}
	otherPub := DeriveEncKey(testMasterKey(t)).Public()
	if VerifyEncKey(identityPub, otherPub, sig) {
		t.Fatal("signature verified over a substituted enc key")
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	if VerifyEncKey(identityPub, encPub, bad) {
		t.Fatal("tampered signature verified")
	}
	otherIdentity := DeriveSigningKey(testMasterKey(t)).Public().(ed25519.PublicKey)
	if VerifyEncKey(otherIdentity, encPub, sig) {
		t.Fatal("signature verified under a different identity")
	}
}

// TestGrantFormatIsPinned fixes what every stored grant depends on: the X-Wing key a
// given root derives, and the wrap length. Changing either — a new HKDF label, or a
// library that generates X-Wing keys differently — would strand every grant already
// on a server, so it has to fail here first.
func TestGrantFormatIsPinned(t *testing.T) {
	var mk MasterKey
	for i := range mk {
		mk[i] = byte(i)
	}
	pub := DeriveEncKey(mk).Public()
	sum := sha256.Sum256(pub)
	if got := hex.EncodeToString(sum[:]); got != "2fade9224633d1e681d7594b96a0d13f55940edbf11e320ce567afd381fefd19" {
		t.Fatalf("X-Wing key derived from a fixed root changed: sha256 = %s", got)
	}
	wrapped, err := WrapGrant(ContentKey{}, pub, "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != GrantWrapSize {
		t.Fatalf("wrap is %d bytes, GrantWrapSize is %d", len(wrapped), GrantWrapSize)
	}
}

// TestPreXWingGrantStillOpens fixes one wrap made by the X25519 code this package
// shipped before X-Wing (cloudflare/circl): grants still in that format on a server
// must keep opening until their grantee's next login re-wraps them.
func TestPreXWingGrantStillOpens(t *testing.T) {
	var mk MasterKey
	var want ContentKey
	for i := range mk {
		mk[i] = byte(i)
		want[i] = byte(0xa0 + i)
	}
	wrapped, err := hex.DecodeString("4ce2895d4266e9b353775a79cfdce001e59c3380b4fe79832199a8b2772f73467e106712ee1073827628830a01717a8badd42888d1a23ea342634593c45b28e94b3b9ce53fbeda40503ff86e13b50103")
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapGrant(wrapped, mk, "res1", "owner1", "grantee1")
	if err != nil {
		t.Fatalf("pre-X-Wing grant did not open: %v", err)
	}
	if got != want {
		t.Fatal("pre-X-Wing grant opened to the wrong content key")
	}
	if _, err := UnwrapGrant(wrapped, mk, "res1", "owner1", "grantee2"); err == nil {
		t.Fatal("pre-X-Wing grant opened under another grantee's binding")
	}
}
