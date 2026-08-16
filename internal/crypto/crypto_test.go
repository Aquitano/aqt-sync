// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestDeriveSigningKeyDeterministicAndVerifiable(t *testing.T) {
	params := cheapKdf(t)
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
	params := cheapKdf(t)
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

// cheapKdf is NewKdfParams at the minimum cost the validator accepts, for the
// tests that need a derived key rather than an expensive one. At the real
// default a derivation is ~215ms under -race, and far worse on a small CI
// runner; the in-package twin of internal/cryptotest, which crypto itself
// cannot import. Tests that assert on cost keep NewKdfParams.
func cheapKdf(t *testing.T) KdfParams {
	t.Helper()
	p, err := NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
	p.Time, p.Memory, p.Threads = 1, 8, 1
	return p
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
	params := cheapKdf(t)
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

func TestSealBoundRoundTrip(t *testing.T) {
	ck, _ := GenerateContentKey()
	plaintext := []byte("bound body")

	blob, err := SealBound(plaintext, ck, AADBlob, "res-a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenBound(blob, ck, AADBlob, "res-a")
	if err != nil {
		t.Fatalf("matching id must open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestOpenBoundRejectsWrongID(t *testing.T) {
	ck, _ := GenerateContentKey()
	// The record-swap detection: a blob sealed for one resource id must not open
	// under another, even with the right key and role — a server moving a whole
	// record (blob + meta + wrapped key) between ids fails here.
	blob, err := SealBound([]byte("secret"), ck, AADBlob, "res-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBound(blob, ck, AADBlob, "res-b"); err == nil {
		t.Fatal("a blob bound to one id must not open under another")
	}
	if _, err := OpenBound(blob, ck, AADMeta, "res-a"); err == nil {
		t.Fatal("a bound blob must still not cross roles")
	}
	if _, err := Open(blob, ck, AADBlob); err == nil {
		t.Fatal("a bound blob must not open under the unbound v1 tag")
	}
}

func TestOpenBoundFallsBackToUnbound(t *testing.T) {
	ck, _ := GenerateContentKey()
	// Pre-binding blobs (and create-time seals, where the id does not exist yet)
	// carry the plain v1 tag; OpenBound must still read them under any id.
	legacy, err := Seal([]byte("legacy"), ck, AADMeta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBound(legacy, ck, AADMeta, "res-a"); err != nil {
		t.Fatalf("v1 blob must open via fallback: %v", err)
	}

	// SealBound with an empty id is the create path and must equal a v1 seal.
	createTime, err := SealBound([]byte("created"), ck, AADMeta, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(createTime, ck, AADMeta); err != nil {
		t.Fatalf("empty-id seal must open under the v1 tag: %v", err)
	}
	if _, err := OpenBound(createTime, ck, AADMeta, "res-a"); err != nil {
		t.Fatalf("empty-id seal must open when later fetched by id: %v", err)
	}
}

func TestBoundAADDisjointAcrossRoles(t *testing.T) {
	// The id-bound tags must stay disjoint per role and never collide with a v1
	// tag, or the domain separation the roles exist for silently vanishes.
	roles := [][]byte{AADBlob, AADMeta, AADSnapshotLabel, AADPack, AADPackRoot, AADTreeRoot}
	seen := map[string]bool{}
	for _, role := range roles {
		seen[string(role)] = true
	}
	for _, role := range roles {
		bound := string(BoundAAD(role, "res-a"))
		if seen[bound] {
			t.Fatalf("bound AAD %q collides", bound)
		}
		seen[bound] = true
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	params := cheapKdf(t)
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
	if got != ck {
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
	params := cheapKdf(t)
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
	params := cheapKdf(t)
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
	if got != ck {
		t.Fatal("public fragment round trip mismatch")
	}
}

// useCheapGate shrinks the gated-link profile for the duration of a test. The
// costs travel inside the fragment, so encode and decode stay self-consistent;
// what the round trip proves is unchanged, and the real profile still costs
// three 256 MiB derivations per test. TestDeriveMasterKeyClampsParams keeps the
// real values for its cost assertion.
func useCheapGate(t *testing.T) {
	t.Helper()
	origTime, origMemory, origThreads := gatedTime, gatedMemory, gatedThreads
	t.Cleanup(func() { gatedTime, gatedMemory, gatedThreads = origTime, origMemory, origThreads })
	gatedTime, gatedMemory, gatedThreads = 1, 8, 1
}

func TestFragmentGatedRoundTrip(t *testing.T) {
	useCheapGate(t)
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
	if got != ck {
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
