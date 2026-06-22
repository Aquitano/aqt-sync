package crypto

import (
	"bytes"
	"testing"
)

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

func TestSealOpenRoundTrip(t *testing.T) {
	ck, err := GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("DATABASE_URL=postgres://localhost/app\nAPI_KEY=sk-secret\n")

	blob, err := Seal(plaintext, ck)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob.Ciphertext, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := Open(blob, ck)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestOpenRejectsTamper(t *testing.T) {
	ck, _ := GenerateContentKey()
	blob, err := Seal([]byte("secret"), ck)
	if err != nil {
		t.Fatal(err)
	}
	blob.Ciphertext[0] ^= 0xff
	if _, err := Open(blob, ck); err == nil {
		t.Fatal("tampered ciphertext must fail the auth tag check")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	ck, _ := GenerateContentKey()
	other, _ := GenerateContentKey()
	blob, err := Seal([]byte("secret"), ck)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(blob, other); err == nil {
		t.Fatal("wrong key must not decrypt")
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
