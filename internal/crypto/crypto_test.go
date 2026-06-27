package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestDeriveSigningKeyDeterministicAndVerifiable(t *testing.T) {
	params, err := NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := DeriveMasterKey("passphrase for signing", params)
	if err != nil {
		t.Fatal(err)
	}

	priv := DeriveSigningKey(mk)
	again := DeriveSigningKey(mk)
	if !priv.Equal(again) {
		t.Fatal("same master key must derive the same signing key")
	}

	msg := []byte("server challenge nonce")
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature must verify under the derived public key")
	}

	other := DeriveSigningKey(mustDerive(t, "different passphrase", params))
	if ed25519.Verify(other.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("signature must not verify under a different key")
	}
}

func TestKeyFingerprintStableAndKeyDependent(t *testing.T) {
	params, err := NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	pub := DeriveSigningKey(mustDerive(t, "first passphrase", params)).Public().(ed25519.PublicKey)

	fp := KeyFingerprint(pub)
	if fp != KeyFingerprint(pub) {
		t.Fatal("same key must produce the same fingerprint")
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("fingerprint must carry the SHA256: prefix, got %q", fp)
	}

	other := DeriveSigningKey(mustDerive(t, "second passphrase", params)).Public().(ed25519.PublicKey)
	if KeyFingerprint(other) == fp {
		t.Fatal("different keys must produce different fingerprints")
	}
}

func mustDerive(t *testing.T, pass string, p KdfParams) MasterKey {
	t.Helper()
	mk, err := DeriveMasterKey(pass, p)
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

func TestDeriveMasterKeyDeterministic(t *testing.T) {
	params, err := NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	a, err := DeriveMasterKey("correct horse battery staple", params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveMasterKey("correct horse battery staple", params)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("same passphrase + params must derive the same key")
	}

	other, err := DeriveMasterKey("different passphrase", params)
	if err != nil {
		t.Fatal(err)
	}
	if a == other {
		t.Fatal("different passphrase must derive a different key")
	}
}

func TestDeriveMasterKeyRejectsBadParams(t *testing.T) {
	if _, err := DeriveMasterKey("pw", KdfParams{Algo: "scrypt", Salt: []byte("x")}); err == nil {
		t.Fatal("expected error for unsupported algo")
	}
	if _, err := DeriveMasterKey("pw", KdfParams{Algo: "argon2id"}); err == nil {
		t.Fatal("expected error for missing salt")
	}
}

func TestDeriveMasterKeyClampsParams(t *testing.T) {
	base, err := NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	// Params above the caps are rejected before the expensive derivation runs, so a
	// crafted link / hostile server cannot force an OOM or hang.
	oversize := base
	oversize.Memory = maxKdfMemory + 1
	if _, err := DeriveMasterKey("pw", oversize); err == nil {
		t.Fatal("expected error for memory above the cap")
	}
	hot := base
	hot.Time = maxKdfTime + 1
	if _, err := DeriveMasterKey("pw", hot); err == nil {
		t.Fatal("expected error for time above the cap")
	}

	gated, err := NewGatedKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := gated.validate(); err != nil {
		t.Fatalf("gated params must validate: %v", err)
	}
	if gated.Memory <= base.Memory || gated.Time < base.Time {
		t.Fatal("gated profile should cost more than the interactive default")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("DATABASE_URL=postgres://localhost/app\nAPI_KEY=sk-secret\n")

	blob, err := Seal(plaintext, ck, AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob.Ciphertext, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := Open(blob, ck, AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	ck, _ := GenerateContentKey()
	blob, err := Seal([]byte("secret"), ck, AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	blob.Ciphertext[0] ^= 0xff
	if _, err := Open(blob, ck, AADBlob); err == nil {
		t.Fatal("tampered ciphertext must fail the auth tag check")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	ck, _ := GenerateContentKey()
	other, _ := GenerateContentKey()
	blob, err := Seal([]byte("secret"), ck, AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(blob, other, AADBlob); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	ck, _ := GenerateContentKey()
	// A blob sealed in the metadata role must not open in the body role, even with
	// the right key: this is what stops a server reinterpreting one field as another.
	blob, err := Seal([]byte("metadata"), ck, AADMeta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(blob, ck, AADBlob); err == nil {
		t.Fatal("a blob sealed under one role must not open under another")
	}
	if _, err := Open(blob, ck, AADMeta); err != nil {
		t.Fatalf("matching role must open: %v", err)
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	params, _ := NewKdfParams()
	mk, err := DeriveMasterKey("master passphrase", params)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := GenerateContentKey()

	wrapped, err := WrapKey(ck, [KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(wrapped, [KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(got, ck) {
		t.Fatal("unwrapped content key does not match original")
	}
}

func TestContentKeyWipe(t *testing.T) {
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	ck.Wipe()
	if ck != (ContentKey{}) {
		t.Fatal("Wipe must zero the content key")
	}
}

func TestWrapUnwrapRoot(t *testing.T) {
	params, _ := NewKdfParams()
	rk, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := DeriveUnlockKey("the account passphrase", params)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapRoot(rk, uk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapRoot(wrapped, uk)
	if err != nil {
		t.Fatal(err)
	}
	if got != rk {
		t.Fatal("unwrapped root key does not match the original")
	}

	// A different passphrase derives a different unlock key and fails the AEAD tag,
	// so a wrong passphrase is caught at unwrap rather than yielding a wrong key.
	wrongUK, _ := DeriveUnlockKey("not the passphrase", params)
	if _, err := UnwrapRoot(wrapped, wrongUK); err == nil {
		t.Fatal("a wrong passphrase must fail to unwrap the root")
	}
}

func TestDeriveAuthVerifier(t *testing.T) {
	params, _ := NewKdfParams()
	uk, _ := DeriveUnlockKey("passphrase one", params)
	v1 := DeriveAuthVerifier(uk)
	if len(v1) != KeySize {
		t.Fatalf("verifier length = %d, want %d", len(v1), KeySize)
	}
	// Deterministic for the same unlock key, distinct for a different one.
	if !bytes.Equal(v1, DeriveAuthVerifier(uk)) {
		t.Fatal("verifier must be deterministic for a given unlock key")
	}
	other, _ := DeriveUnlockKey("passphrase two", params)
	if bytes.Equal(v1, DeriveAuthVerifier(other)) {
		t.Fatal("a different passphrase must yield a different verifier")
	}
}

func TestFragmentPublicRoundTrip(t *testing.T) {
	ck, _ := GenerateContentKey()
	frag, err := EncodeFragment(ck, "")
	if err != nil {
		t.Fatal(err)
	}
	if frag[:2] != fragPublic {
		t.Fatalf("expected public prefix, got %q", frag[:2])
	}
	got, err := DecodeFragment(frag, "")
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(got, ck) {
		t.Fatal("public fragment round trip mismatch")
	}
}

func TestFragmentGatedRoundTrip(t *testing.T) {
	ck, _ := GenerateContentKey()
	frag, err := EncodeFragment(ck, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if frag[:2] != fragGated {
		t.Fatalf("expected gated prefix, got %q", frag[:2])
	}

	got, err := DecodeFragment(frag, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !ConstantTimeEqual(got, ck) {
		t.Fatal("gated fragment round trip mismatch")
	}

	if _, err := DecodeFragment(frag, "wrong"); err == nil {
		t.Fatal("wrong password must fail")
	}
	if _, err := DecodeFragment(frag, ""); err == nil {
		t.Fatal("missing password on a gated link must fail")
	}
}

func TestDecodeFragmentRejectsGarbage(t *testing.T) {
	if _, err := DecodeFragment("z.whatever", ""); err == nil {
		t.Fatal("unrecognized prefix must fail")
	}
}
