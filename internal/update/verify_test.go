// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestVerifyAcceptsAGenuineSignature(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	keyID, err := Verify(manifest, sig, rootsOf(key))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if want := KeyID(key.Public().(ed25519.PublicKey)); keyID != want {
		t.Fatalf("Verify returned key %q, want %q", keyID, want)
	}
}

func TestVerifyRejectsATamperedManifest(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)

	tampered := bytes.Replace(manifest, []byte("v0.4.0"), []byte("v9.4.0"), 1)
	if bytes.Equal(tampered, manifest) {
		t.Fatal("fixture did not change")
	}
	if _, err := Verify(tampered, sig, rootsOf(key)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}

	// A single flipped byte anywhere is enough.
	flipped := bytes.Clone(manifest)
	flipped[len(flipped)/2] ^= 0x01
	if _, err := Verify(flipped, sig, rootsOf(key)); err == nil {
		t.Fatal("a flipped byte verified")
	}
}

func TestVerifyRejectsAnUntrustedKey(t *testing.T) {
	signer := fixtureKey(t, seedC)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), signer)
	if _, err := Verify(manifest, sig, rootsOf(fixtureKey(t, seedA))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
}

// Rotation only works if a release can be signed by both keys while clients catch
// up: the old client accepts the old signature, the new one accepts either.
func TestVerifySupportsOverlappingKeyRotation(t *testing.T) {
	outgoing, incoming := fixtureKey(t, seedA), fixtureKey(t, seedB)
	m := fixtureManifest("v0.4.0", ChannelStable)

	manifest, dual := signFixture(t, m, outgoing, incoming)
	if _, err := Verify(manifest, dual, rootsOf(outgoing)); err != nil {
		t.Fatalf("client that knows only the outgoing key: %v", err)
	}
	if _, err := Verify(manifest, dual, rootsOf(incoming)); err != nil {
		t.Fatalf("client that knows only the incoming key: %v", err)
	}
	if _, err := Verify(manifest, dual, rootsOf(outgoing, incoming)); err != nil {
		t.Fatalf("client that knows both keys: %v", err)
	}

	// Once the overlap ends and only the incoming key signs, a client that never
	// upgraded is left out rather than fooled.
	incomingOnly := signBytes(t, manifest, incoming)
	if _, err := Verify(manifest, incomingOnly, rootsOf(incoming)); err != nil {
		t.Fatalf("upgraded client: %v", err)
	}
	if _, err := Verify(manifest, incomingOnly, rootsOf(outgoing)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("client left behind: got %v, want ErrUnknownKey", err)
	}
}

// A trusted key id paired with someone else's signature must not pass just
// because another entry in the same file happens to be well formed.
func TestVerifyRejectsASpoofedKeyID(t *testing.T) {
	trusted, attacker := fixtureKey(t, seedA), fixtureKey(t, seedC)
	m := fixtureManifest("v0.4.0", ChannelStable)
	manifest, _ := signFixture(t, m, trusted)

	forged := signBytes(t, manifest, attacker)
	var s Signature
	if err := json.Unmarshal(forged, &s); err != nil {
		t.Fatal(err)
	}
	s.Signatures[0].KeyID = KeyID(trusted.Public().(ed25519.PublicKey))
	b, err := s.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifest, b, rootsOf(trusted)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsMalformedSignatureFiles(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	roots := rootsOf(key)

	cases := []struct {
		name string
		sig  []byte
		want error
	}{
		{"not json", []byte("nope"), ErrMalformedSignature},
		{"unknown field", bytes.Replace(sig, []byte(`"schema": 1,`), []byte(`"schema": 1,`+"\n  "+`"comment": "hi",`), 1), ErrMalformedSignature},
		{"future schema", bytes.Replace(sig, []byte(`"schema": 1`), []byte(`"schema": 2`), 1), ErrMalformedSignature},
		{"other algorithm", bytes.Replace(sig, []byte(`"ed25519"`), []byte(`"rsa"`), 1), ErrMalformedSignature},
		{"no signatures", []byte(`{"schema":1,"alg":"ed25519","signatures":[]}`), ErrMalformedSignature},
		{"trailing data", append(bytes.Clone(sig), []byte("{}")...), ErrMalformedSignature},
		{"short key id", bytes.Replace(sig, []byte(`"keyid": "`), []byte(`"keyid": "zz`), 1), ErrMalformedSignature},
		{"oversized", bytes.Repeat([]byte(" "), MaxSignatureBytes+1), ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(manifest, tc.sig, roots); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyRejectsARepeatedKey(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)

	var s Signature
	if err := json.Unmarshal(sig, &s); err != nil {
		t.Fatal(err)
	}
	s.Signatures = append(s.Signatures, s.Signatures[0])
	b, err := s.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifest, b, rootsOf(key)); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("got %v, want ErrMalformedSignature", err)
	}
}

func TestVerifyWithoutTrustRootsFailsClosed(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, sig := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	if _, err := Verify(manifest, sig, nil); !errors.Is(err, ErrNoTrustRoots) {
		t.Fatalf("got %v, want ErrNoTrustRoots", err)
	}
}

// Signing is domain separated, so an Ed25519 signature this project produces for
// any other purpose cannot be replayed onto a release manifest — including a
// signature over the manifest bytes themselves.
func TestSigningIsDomainSeparated(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, _ := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)

	undomained := Signature{
		Schema: signatureSchema,
		Alg:    "ed25519",
		Signatures: []KeySignature{{
			KeyID: KeyID(key.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest)),
		}},
	}
	b, err := undomained.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(manifest, b, rootsOf(key)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// The trust-root table is compiled in, so a malformed entry has to fail the build,
// not silently ship a client that trusts one key fewer than intended.
func TestCompiledTrustRootsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range TrustRoots() {
		if seen[r.KeyID] {
			t.Fatalf("trust root %s is listed twice", r.KeyID)
		}
		seen[r.KeyID] = true
		if KeyID(r.PublicKey) != r.KeyID {
			t.Fatalf("trust root %s does not match its key", r.KeyID)
		}
	}
}
