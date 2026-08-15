// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// sigDomain prefixes the signed bytes. Domain separation keeps a release
// signature from being interchangeable with any other Ed25519 signature this
// project produces (account auth, key self-signatures), even if a key were ever
// reused by mistake.
const sigDomain = "aqt-update-manifest-v1\x00"

// signatureSchema is the layout of the detached signature file.
const signatureSchema = 1

const maxSignatures = 8

var (
	// ErrUnknownKey means the manifest is signed, but by no key this build trusts.
	// Distinct from a bad signature: it is what a client sees after a key rotation
	// it is too old to know about.
	ErrUnknownKey = errors.New("update manifest is signed by an unknown key")
	// ErrBadSignature means a trusted key was named but the signature over these
	// bytes does not verify.
	ErrBadSignature = errors.New("update manifest signature is invalid")
	// ErrMalformedSignature covers a structurally broken signature file.
	ErrMalformedSignature = errors.New("malformed update signature")
	// ErrNoTrustRoots means this build has no release-signing keys compiled in, so
	// it cannot authenticate anything.
	ErrNoTrustRoots = errors.New("this build has no release-signing keys compiled in")
)

// Signature is the detached signature file. It carries one entry per signing key
// so a release can be signed by both the outgoing and incoming key during a
// rotation, and clients on either side of the rotation accept it.
type Signature struct {
	Schema     int            `json:"schema"`
	Alg        string         `json:"alg"`
	Signatures []KeySignature `json:"signatures"`
}

// KeySignature is one key's signature over the canonical manifest bytes.
type KeySignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// KeyID identifies a public key by the first 8 bytes of its SHA-256, hex encoded.
// It is a lookup handle only; it is never trusted in place of verifying.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// SignManifest signs canonical manifest bytes with one or more keys.
func SignManifest(manifest []byte, keys ...ed25519.PrivateKey) (Signature, error) {
	if len(keys) == 0 || len(keys) > maxSignatures {
		return Signature{}, fmt.Errorf("%w: %d signing keys", ErrMalformedSignature, len(keys))
	}
	sig := Signature{Schema: signatureSchema, Alg: "ed25519"}
	for _, k := range keys {
		pub, ok := k.Public().(ed25519.PublicKey)
		if !ok {
			return Signature{}, errors.New("signing key is not Ed25519")
		}
		sig.Signatures = append(sig.Signatures, KeySignature{
			KeyID: KeyID(pub),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(k, signedBytes(manifest))),
		})
	}
	return sig, nil
}

// Bytes renders the signature file.
func (s Signature) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks a detached signature over exactly the bytes it was handed, and
// returns the key id that vouched for them. Callers must verify before parsing:
// every field of the manifest is attacker-controlled until this returns nil.
func Verify(manifest, signature []byte, roots []TrustRoot) (string, error) {
	if len(roots) == 0 {
		return "", ErrNoTrustRoots
	}
	if len(signature) > MaxSignatureBytes {
		return "", fmt.Errorf("%w: signature is %d bytes", ErrTooLarge, len(signature))
	}
	if len(manifest) > MaxManifestBytes {
		return "", fmt.Errorf("%w: manifest is %d bytes", ErrTooLarge, len(manifest))
	}

	dec := json.NewDecoder(bytes.NewReader(signature))
	dec.DisallowUnknownFields()
	var s Signature
	if err := dec.Decode(&s); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformedSignature, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("%w: trailing data after the signature", ErrMalformedSignature)
	}
	if s.Schema != signatureSchema {
		return "", fmt.Errorf("%w: schema %d", ErrMalformedSignature, s.Schema)
	}
	if s.Alg != "ed25519" {
		return "", fmt.Errorf("%w: algorithm %q", ErrMalformedSignature, s.Alg)
	}
	if len(s.Signatures) == 0 || len(s.Signatures) > maxSignatures {
		return "", fmt.Errorf("%w: %d signatures", ErrMalformedSignature, len(s.Signatures))
	}

	// The whole envelope is checked before any signature is verified, so a
	// structurally broken file cannot be accepted just because its first entry
	// happened to check out.
	raw := make([][]byte, len(s.Signatures))
	seen := make(map[string]bool, len(s.Signatures))
	for i, entry := range s.Signatures {
		if len(entry.KeyID) != 16 {
			return "", fmt.Errorf("%w: bad key id", ErrMalformedSignature)
		}
		if _, err := hex.DecodeString(entry.KeyID); err != nil {
			return "", fmt.Errorf("%w: bad key id", ErrMalformedSignature)
		}
		if seen[entry.KeyID] {
			return "", fmt.Errorf("%w: key %s signs twice", ErrMalformedSignature, entry.KeyID)
		}
		seen[entry.KeyID] = true

		b, err := base64.StdEncoding.DecodeString(entry.Sig)
		if err != nil || len(b) != ed25519.SignatureSize {
			return "", fmt.Errorf("%w: key %s has a malformed signature", ErrMalformedSignature, entry.KeyID)
		}
		raw[i] = b
	}

	signed := signedBytes(manifest)
	trusted := false
	for i, entry := range s.Signatures {
		root, ok := findRoot(roots, entry.KeyID)
		if !ok {
			continue
		}
		trusted = true
		if ed25519.Verify(root.PublicKey, signed, raw[i]) {
			return entry.KeyID, nil
		}
	}
	if !trusted {
		return "", ErrUnknownKey
	}
	return "", ErrBadSignature
}

func findRoot(roots []TrustRoot, keyID string) (TrustRoot, bool) {
	for _, r := range roots {
		if r.KeyID == keyID {
			return r, true
		}
	}
	return TrustRoot{}, false
}

func signedBytes(manifest []byte) []byte {
	return append([]byte(sigDomain), manifest...)
}
