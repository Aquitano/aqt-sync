package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
)

// Account-to-account grants wrap a resource's content key to a grantee's X25519
// encryption key with HPKE (RFC 9180: X25519-HKDF-SHA256 + ChaCha20-Poly1305,
// base mode). The HPKE info parameter binds the wrap to (resource id, owner
// handle, grantee handle), the same discipline as the v2 id-bound AAD: a grant
// ciphertext replayed onto another resource or grantee fails to open.

// grantSuite is the one HPKE suite this package speaks. The suite id is baked
// into the wrap by HPKE's key schedule, so a future suite change is a new format,
// not a downgrade surface.
func grantSuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_ChaCha20Poly1305)
}

func grantKEM() kem.Scheme { return hpke.KEM_X25519_HKDF_SHA256.Scheme() }

// EncPublicKeySize is the marshaled X25519 public key length.
const EncPublicKeySize = 32

// aadGrantWrap domain-separates the grant AEAD from every other ciphertext this
// package mints (the contextual binding itself lives in the HPKE info).
var aadGrantWrap = []byte("aqt-grantwrap-v1")

// encKeyBindingPrefix domain-separates the Ed25519 self-signature over the enc
// public key from challenge signatures (which sign server-issued random nonces).
const encKeyBindingPrefix = "aqt-enc-key-binding-v1\x00"

// EncKeyPair is an account's X25519 encryption keypair, derived from the master
// key (DeriveEncKey) so any unlocked device can reconstruct it — nothing new to
// back up, mirroring the Ed25519 signing key.
type EncKeyPair struct {
	pub  kem.PublicKey
	priv kem.PrivateKey
}

// DeriveEncKey derives the account's X25519 encryption keypair from the master
// key via HKDF, the same construction as DeriveSigningKey. The public half is
// published on the account; the private half is re-derived on demand and never
// stored or sent.
func DeriveEncKey(mk MasterKey) EncKeyPair {
	r := hkdf.New(sha256.New, mk[:], nil, []byte("aqt-share-x25519-v1"))
	seed := make([]byte, grantKEM().SeedSize())
	if _, err := io.ReadFull(r, seed); err != nil {
		panic("hkdf expand failed: " + err.Error()) // unreachable for an in-memory reader
	}
	return DeriveEncKeyFromSeed(seed)
}

// DeriveEncKeyFromSeed deterministically derives an X25519 keypair from a
// 32-byte seed. Split out of DeriveEncKey so the server can synthesize a valid
// decoy keypair for unknown-email lookups (see the existence-oracle rule on the
// account bootstrap): a decoy derived like a real key is indistinguishable on
// the wire from one.
func DeriveEncKeyFromSeed(seed []byte) EncKeyPair {
	pub, priv := grantKEM().DeriveKeyPair(seed)
	return EncKeyPair{pub: pub, priv: priv}
}

// Public returns the marshaled X25519 public key.
func (k EncKeyPair) Public() []byte {
	b, err := k.pub.MarshalBinary()
	if err != nil {
		panic("marshal x25519 public key: " + err.Error()) // unreachable: in-memory marshal
	}
	return b
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

// WrapGrant seals a content key to the grantee's published X25519 key. The
// result is the KEM encapsulation followed by the AEAD ciphertext, stored
// server-side as one opaque blob; the server never sees the content key.
func WrapGrant(ck ContentKey, granteeEncPub []byte, resourceID, ownerHandle, granteeHandle string) ([]byte, error) {
	pk, err := grantKEM().UnmarshalBinaryPublicKey(granteeEncPub)
	if err != nil {
		return nil, fmt.Errorf("grantee enc key: %w", err)
	}
	sender, err := grantSuite().NewSender(pk, grantInfo(resourceID, ownerHandle, granteeHandle))
	if err != nil {
		return nil, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, err
	}
	ct, err := sealer.Seal(ck[:], aadGrantWrap)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// UnwrapGrant reverses WrapGrant with the grantee's derived private key. A wrap
// bound to a different resource, owner, or grantee fails the HPKE key schedule
// (wrong info) and returns an error.
func UnwrapGrant(wrapped []byte, mk MasterKey, resourceID, ownerHandle, granteeHandle string) (ContentKey, error) {
	var ck ContentKey
	encSize := grantKEM().CiphertextSize()
	if len(wrapped) <= encSize {
		return ck, errors.New("grant wrap too short")
	}
	kp := DeriveEncKey(mk)
	receiver, err := grantSuite().NewReceiver(kp.priv, grantInfo(resourceID, ownerHandle, granteeHandle))
	if err != nil {
		return ck, err
	}
	opener, err := receiver.Setup(wrapped[:encSize])
	if err != nil {
		return ck, err
	}
	plain, err := opener.Open(wrapped[encSize:], aadGrantWrap)
	if err != nil {
		return ck, fmt.Errorf("open grant: %w", err)
	}
	if len(plain) != KeySize {
		return ck, errors.New("unwrapped grant key has wrong length")
	}
	copy(ck[:], plain)
	return ck, nil
}
