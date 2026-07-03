package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/aquitano/aqt-sync/internal/compress"
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
// plaintext length (a cheap tamper check on open). Alg names the compression
// applied to the sealed payload; absence means raw, so chunks sealed before
// compression existed stay readable.
type Chunk struct {
	ID  string `json:"id"`
	Key []byte `json:"key"`
	Len int    `json:"len"`
	Alg string `json:"alg,omitempty"`
}

// chunkNonce is a fixed all-zero nonce. Reusing it is safe precisely because the
// chunk key is derived from the plaintext: the same (key, nonce) pair only ever
// encrypts the same bytes, so no two distinct messages share a key+nonce.
var chunkNonce [NonceSize]byte

// aadChunk domain-separates a convergent chunk's AEAD from the other ciphertext
// roles (AADBlob/AADMeta/key wraps), the same way those tags do, so a chunk's bytes
// can never be reinterpreted as another kind of sealed payload. It is a constant, so
// it does not disturb convergence: the same plaintext still seals to the same
// ciphertext (and thus the same dedup id).
var aadChunk = []byte("aqt-chunk-aad-v1")

// aadTreeNode domain-separates a Merkle-DAG directory-node object from file-content
// chunks. Both seal through this same convergent pipeline, so a directory node and a
// file chunk with byte-identical plaintext would otherwise share one object id; the
// distinct tag keeps the roles apart (identical directory nodes still dedup against
// each other, since the tag is constant). See DESIGN.md section 5 (AEAD domain
// separation) and docs/phase4-merkle-dag.md section 9.6.
var aadTreeNode = []byte("aqt-treenode-v1")

// aadChunkList domain-separates a sealed chunk-list segment — the indirect form of
// a large file's chunk records (see syncengine's chunk-list segmentation) — from
// file-content chunks and directory nodes, which flow through this same convergent
// pipeline. The tag is constant, so identical lists still dedup.
var aadChunkList = []byte("aqt-chunklist-v1")

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

// SealChunk deterministically encrypts a file-content chunk and returns its
// ciphertext plus the Chunk record (address, key, length) the manifest needs to
// recover it.
func SealChunk(plaintext []byte, conv ConvergenceKey) (ciphertext []byte, ch Chunk, err error) {
	return sealConvergent(plaintext, conv, aadChunk)
}

// OpenChunk decrypts a file-content chunk's ciphertext using the key from its
// manifest record, verifying both the content-address (ciphertext hash) and the
// AEAD tag.
func OpenChunk(ciphertext []byte, ch Chunk) ([]byte, error) {
	return openConvergent(ciphertext, ch, aadChunk)
}

// SealNode seals a Merkle-DAG directory-node object through the same convergent
// pipeline as SealChunk but under a distinct AAD, so node objects are
// domain-separated from file chunks while identical subtrees still dedup. The
// returned Chunk.ID is the subtree's Merkle hash.
func SealNode(plaintext []byte, conv ConvergenceKey) (ciphertext []byte, ch Chunk, err error) {
	return sealConvergent(plaintext, conv, aadTreeNode)
}

// OpenNode reverses SealNode, verifying the node object's address and AEAD tag.
func OpenNode(ciphertext []byte, ch Chunk) ([]byte, error) {
	return openConvergent(ciphertext, ch, aadTreeNode)
}

// SealChunkList seals one segment of a serialized chunk list through the convergent
// pipeline under its own AAD, so list segments are domain-separated from file chunks
// and directory nodes while identical lists still dedup.
func SealChunkList(plaintext []byte, conv ConvergenceKey) (ciphertext []byte, ch Chunk, err error) {
	return sealConvergent(plaintext, conv, aadChunkList)
}

// OpenChunkList reverses SealChunkList, verifying the segment's address and AEAD tag.
func OpenChunkList(ciphertext []byte, ch Chunk) ([]byte, error) {
	return openConvergent(ciphertext, ch, aadChunkList)
}

func sealConvergent(plaintext []byte, conv ConvergenceKey, aad []byte) ([]byte, Chunk, error) {
	// The key stays bound to the raw plaintext, so compression never changes
	// dedup identity, and the zero nonce stays safe: the sealed payload is a
	// deterministic function of the plaintext the key derives from, so one
	// (key, nonce) pair still only ever encrypts one message.
	key := deriveChunkKey(conv, plaintext)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, Chunk{}, err
	}
	payload, alg := compress.Encode(plaintext)
	ciphertext := aead.Seal(nil, chunkNonce[:], payload, aad)
	sum := sha256.Sum256(ciphertext)
	return ciphertext, Chunk{
		ID:  hex.EncodeToString(sum[:]),
		Key: append([]byte(nil), key[:]...),
		Len: len(plaintext),
		Alg: alg,
	}, nil
}

func openConvergent(ciphertext []byte, ch Chunk, aad []byte) ([]byte, error) {
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
	payload, err := aead.Open(nil, chunkNonce[:], ciphertext, aad)
	if err != nil {
		return nil, err
	}
	plaintext, err := compress.Decode(payload, ch.Alg, ch.Len)
	if err != nil {
		return nil, fmt.Errorf("chunk %s: %w", ch.ID, err)
	}
	return plaintext, nil
}
