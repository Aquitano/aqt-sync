// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Account-to-account grants wrap a resource's content key to a grantee's published
// encryption key with HPKE (RFC 9180, base mode) over X-Wing: ML-KEM-768 combined
// with X25519, so a wrap stays sealed unless both are broken. A grant row sits on the
// server indefinitely, which makes it exactly what an adversary would store today
// and decrypt once a quantum computer can break X25519 alone. The HPKE info binds the
// wrap to (resource id, owner handle, grantee handle), the same discipline as the v2
// id-bound AAD: a grant ciphertext replayed onto another resource or grantee fails to
// open.
//
// Grants written before X-Wing used DHKEM(X25519). UnwrapGrant still opens them so
// the grantee's next login can re-wrap them to X-Wing; nothing seals that format any
// more, and the server refuses to store it.

// grantKDF and grantAEAD complete the suite for both KEMs. The KEM id is part of
// HPKE's key schedule, so a wrap never opens under the other KEM: a suite change
// is a new format, not a downgrade surface.
var (
	grantKDF  = hpke.HKDFSHA256()
	grantAEAD = hpke.ChaCha20Poly1305()
)

const x25519Size = 32

const (
	// EncPublicKeySize is the X-Wing public key length: the ML-KEM-768
	// encapsulation key followed by the X25519 key.
	EncPublicKeySize = mlkem.EncapsulationKeySize768 + x25519Size
	// GrantWrapSize is the length of every wrap WrapGrant produces: the X-Wing
	// encapsulation, then the sealed content key and its tag.
	GrantWrapSize = mlkem.CiphertextSize768 + x25519Size + KeySize + chacha20poly1305.Overhead

	legacyGrantWrapSize = x25519Size + KeySize + chacha20poly1305.Overhead
)

// aadGrantWrap domain-separates the grant AEAD from every other ciphertext this
// package mints (the contextual binding itself lives in the HPKE info).
var aadGrantWrap = []byte("aqt-grantwrap-v1")

// encKeyBindingPrefix domain-separates the Ed25519 self-signature over the enc
// public key from challenge signatures (which sign server-issued random nonces).
const encKeyBindingPrefix = "aqt-enc-key-binding-v1\x00"

// EncKeyPair is an account's X-Wing encryption keypair, derived from the master key
// (DeriveEncKey) so any unlocked device can reconstruct it — nothing new to back up,
// mirroring the Ed25519 signing key.
type EncKeyPair struct {
	priv hpke.PrivateKey
}

// DeriveEncKey derives the account's X-Wing encryption keypair from the master key
// via HKDF, the same construction as DeriveSigningKey. The public half is published
// on the account; the private half is re-derived on demand and never stored or sent.
func DeriveEncKey(mk MasterKey) EncKeyPair {
	return DeriveEncKeyFromSeed(derive(mk[:], nil, "aqt-share-xwing-v1"))
}

// DeriveEncKeyFromSeed turns a 32-byte seed into an X-Wing keypair. The seed is the
// X-Wing private key itself, so the published key depends only on the X-Wing
// specification and not on any library's DeriveKeyPair, whose X-Wing mapping is
// still a draft that implementations disagree on. The server uses it to synthesize a
// decoy keypair for unknown-email lookups (see the existence-oracle rule on the
// account bootstrap): a decoy derived like a real key is indistinguishable on the
// wire from one.
func DeriveEncKeyFromSeed(seed []byte) EncKeyPair {
	priv, err := hpke.MLKEM768X25519().NewPrivateKey(seed)
	if err != nil {
		panic("x-wing private key: " + err.Error()) // unreachable: every caller passes a 32-byte seed
	}
	return EncKeyPair{priv: priv}
}

// Public returns the marshaled X-Wing public key.
func (k EncKeyPair) Public() []byte {
	return k.priv.PublicKey().Bytes()
}

// legacyEncKey re-derives the X25519 key grants were wrapped to before X-Wing.
func legacyEncKey(mk MasterKey) (hpke.PrivateKey, error) {
	return hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(derive(mk[:], nil, "aqt-share-x25519-v1"))
}

// SignEncKey self-signs an enc public key with the account's Ed25519 identity
// key, binding the two halves of the account's published identity. A client
// verifies the binding on lookup, so a server substituting only the enc key is
// caught; substituting both keys remains possible for the server and is what
// first-use pinning (aqt contacts) addresses.
func SignEncKey(identity ed25519.PrivateKey, encPub []byte) []byte {
	return ed25519.Sign(identity, append([]byte(encKeyBindingPrefix), encPub...))
}

// VerifyEncKey checks the SignEncKey binding.
func VerifyEncKey(identityPub ed25519.PublicKey, encPub, sig []byte) bool {
	if len(identityPub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(identityPub, append([]byte(encKeyBindingPrefix), encPub...), sig)
}

// grantInfo is the HPKE info binding: a version tag plus the three context
// fields, each length-prefixed so no concatenation of different (resource,
// owner, grantee) triples can collide.
func grantInfo(resourceID, ownerHandle, granteeHandle string) []byte {
	var buf bytes.Buffer
	buf.WriteString("aqt-grant-v1")
	for _, f := range []string{resourceID, ownerHandle, granteeHandle} {
		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(len(f)))
		buf.Write(n[:])
		buf.WriteString(f)
	}
	return buf.Bytes()
}

// WrapGrant seals a content key to the grantee's published X-Wing key. The result
// is the KEM encapsulation followed by the AEAD ciphertext, stored server-side as
// one opaque blob of GrantWrapSize bytes; the server never sees the content key.
func WrapGrant(ck ContentKey, granteeEncPub []byte, resourceID, ownerHandle, granteeHandle string) ([]byte, error) {
	pk, err := hpke.MLKEM768X25519().NewPublicKey(granteeEncPub)
	if err != nil {
		return nil, fmt.Errorf("grantee enc key: %w", err)
	}
	enc, sender, err := hpke.NewSender(pk, grantKDF, grantAEAD, grantInfo(resourceID, ownerHandle, granteeHandle))
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(aadGrantWrap, ck[:])
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// UnwrapGrant reverses WrapGrant with the grantee's derived private key, and opens
// a pre-X-Wing X25519 wrap too, told apart by length. A wrap bound to a different
// resource, owner, or grantee fails the HPKE key schedule (wrong info) and returns an
// error.
func UnwrapGrant(wrapped []byte, mk MasterKey, resourceID, ownerHandle, granteeHandle string) (ContentKey, error) {
	var ck ContentKey
	var priv hpke.PrivateKey
	switch len(wrapped) {
	case GrantWrapSize:
		priv = DeriveEncKey(mk).priv
	case legacyGrantWrapSize:
		legacy, err := legacyEncKey(mk)
		if err != nil {
			return ck, err
		}
		priv = legacy
	default:
		return ck, fmt.Errorf("grant wrap is %d bytes, not a known format", len(wrapped))
	}
	encSize := len(wrapped) - KeySize - chacha20poly1305.Overhead
	recipient, err := hpke.NewRecipient(wrapped[:encSize], priv, grantKDF, grantAEAD, grantInfo(resourceID, ownerHandle, granteeHandle))
	if err != nil {
		return ck, err
	}
	plain, err := recipient.Open(aadGrantWrap, wrapped[encSize:])
	if err != nil {
		return ck, fmt.Errorf("open grant: %w", err)
	}
	if len(plain) != KeySize {
		return ck, errors.New("unwrapped grant key has wrong length")
	}
	copy(ck[:], plain)
	return ck, nil
}
