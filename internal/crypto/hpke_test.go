package crypto

import (
	"bytes"
	"crypto/ed25519"
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
	if !ConstantTimeEqual(got, ck) {
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
