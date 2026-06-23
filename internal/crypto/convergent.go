package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Convergent chunk encryption underpins folder sync. A chunk is sealed with a key
// derived from its own plaintext (keyed by the account's convergence secret), so
// the same account encrypting the same bytes always produces identical ciphertext
// — letting the server store one copy (dedup). Two different accounts derive
// different keys, so identical plaintext yields different ciphertext: no
// cross-account equality oracle. See DESIGN.md section 4.2a.

// ConvergenceKey is an account-scoped secret, derived from the master key, that
// keys convergent chunk encryption. It never leaves the device.
type ConvergenceKey [KeySize]byte

// Wipe best-effort zeroes the convergence key (see MasterKey.Wipe for caveats).
func (k *ConvergenceKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// DeriveConvergenceKey derives the convergence key from the master key via HKDF.
// It is one-way: a leaked convergence key reveals nothing about the master key.
func DeriveConvergenceKey(mk MasterKey) ConvergenceKey {
	r := hkdf.New(sha256.New, mk[:], nil, []byte("aqt-convergence-v1"))
	var ck ConvergenceKey
	if _, err := io.ReadFull(r, ck[:]); err != nil {
		panic("hkdf convergence key: " + err.Error()) // unreachable for an in-memory reader
	}
	return ck
}

// Chunk identifies one sealed chunk: ID is the server storage address (hash of
// the ciphertext, hex so it is safe on case-insensitive filesystems), Key is the
// per-chunk decryption key kept only in the sealed manifest, and Len is the
// plaintext length (a cheap tamper check on open).
type Chunk struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
	Len int    `json:"len"`
}

// chunkNonce is a fixed all-zero nonce. Reusing it is safe precisely because the
// chunk key is derived from the plaintext: the same (key, nonce) pair only ever
// encrypts the same bytes, so no two distinct messages share a key+nonce.
var chunkNonce [NonceSize]byte

// deriveChunkKey binds the plaintext and the account secret into a unique key.
func deriveChunkKey(conv ConvergenceKey, plaintext []byte) [KeySize]byte {
	salt := sha256.Sum256(plaintext)
	r := hkdf.New(sha256.New, conv[:], salt[:], []byte("aqt-chunk-v1"))
	var key [KeySize]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic("hkdf chunk key: " + err.Error())
	}
	return key
}

// SealChunk deterministically encrypts a chunk and returns its ciphertext plus
// the Chunk record (address, key, length) the manifest needs to recover it.
func SealChunk(plaintext []byte, conv ConvergenceKey) (ciphertext []byte, ch Chunk, err error) {
	key := deriveChunkKey(conv, plaintext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, Chunk{}, err
	}
	ciphertext = aead.Seal(nil, chunkNonce[:], plaintext, nil)
	sum := sha256.Sum256(ciphertext)
	return ciphertext, Chunk{
		ID:  hex.EncodeToString(sum[:]),
		Key: append([]byte(nil), key[:]...),
		Len: len(plaintext),
	}, nil
}

// OpenChunk decrypts a chunk's ciphertext using the key from its manifest record,
// verifying both the content-address (ciphertext hash) and the AEAD tag.
func OpenChunk(ciphertext []byte, ch Chunk) ([]byte, error) {
	sum := sha256.Sum256(ciphertext)
	if hex.EncodeToString(sum[:]) != ch.ID {
		return nil, errors.New("chunk id mismatch: ciphertext does not match its address")
	}
	if len(ch.Key) != KeySize {
		return nil, errors.New("chunk key has wrong length")
	}
	aead, err := chacha20poly1305.NewX(ch.Key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, chunkNonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != ch.Len {
		return nil, errors.New("chunk length mismatch")
	}
	return plaintext, nil
}
