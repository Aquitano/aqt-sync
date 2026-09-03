// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Node-seal reuse. SealNode is deterministic — the same plaintext under the same
// convergence key always yields the same ciphertext and id — but not cheap:
// compression dominates a full-tree seal, and every folder push re-seals the
// whole DAG (see syncengine.SealTree). A NodeSealMemo remembers past results so
// an unchanged node skips the re-encrypt. The memo is advisory by construction:
// every hit is verified by opening the remembered ciphertext under a freshly
// derived key and comparing plaintexts, so a wrong, stale, or corrupt entry is
// indistinguishable from a miss and falls back to a cold seal — a memo can speed
// a seal up but never change its output or fail it.

// NodeSealMemo remembers prior SealNode results, keyed by an account-scoped
// digest of the node plaintext (computed by SealNodeMemo, never by the
// implementation). Implementations hold only public data — the ciphertext the
// server stores plus its id and compression alg — never a node key, which
// SealNodeMemo re-derives from the plaintext on every hit.
type NodeSealMemo interface {
	// GetNodeSeal returns the remembered seal for digest, or ok=false. The
	// ciphertext must be an allocation the caller may retain. Every hit is
	// treated as untrusted until SealNodeMemo verifies it.
	GetNodeSeal(digest string) (id, alg string, ciphertext []byte, ok bool)
	// PutNodeSeal remembers a seal. Best effort: a failure is invisible and only
	// costs a future cold seal.
	PutNodeSeal(digest, id, alg string, ciphertext []byte)
}

// nodeSealDigest keys a node plaintext for a NodeSealMemo: an HMAC under a
// secret derived from the convergence key, not a bare hash. Keying buys two
// things — a stored digest reveals nothing about the plaintext (a bare hash
// would hand anyone reading the memo a directory-listing confirmation oracle,
// the exact oracle account-keyed convergence exists to prevent), and digests
// from different accounts can never land in each other's slots.
func nodeSealDigest(conv ConvergenceKey, plaintext []byte) string {
	mk := derive(conv[:], nil, "aqt-seal-memo-v1", KeySize)
	h := hmac.New(sha256.New, mk)
	h.Write(plaintext)
	return hex.EncodeToString(h.Sum(nil))
}

// SealNodeMemo is SealNode with reuse: a verified memo hit returns the
// remembered ciphertext and reconstructs its Chunk record (the key re-derived
// from the plaintext, so it never rides in the memo); anything else seals cold
// and records the result. Verification is OpenNode plus a plaintext compare
// under the derived key, which binds a hit to exactly this plaintext and key —
// only a ciphertext this account's sealer once produced for these bytes can
// pass. It cannot tell which compressor produced it, so implementations must
// namespace entries by compress.CodecID() to keep a reused seal byte-identical
// to a cold one. A nil memo is exactly SealNode.
func SealNodeMemo(plaintext []byte, conv ConvergenceKey, memo NodeSealMemo) (ciphertext []byte, ch Chunk, err error) {
	if memo == nil {
		return SealNode(plaintext, conv)
	}
	digest := nodeSealDigest(conv, plaintext)
	if id, alg, ct, ok := memo.GetNodeSeal(digest); ok {
		key := deriveChunkKey(conv, plaintext)
		cached := Chunk{ID: id, Key: append([]byte(nil), key[:]...), Len: len(plaintext), Alg: alg}
		if plain, err := OpenNode(ct, cached); err == nil && bytes.Equal(plain, plaintext) {
			return ct, cached, nil
		}
	}
	ct, ch, err := SealNode(plaintext, conv)
	if err == nil {
		memo.PutNodeSeal(digest, ch.ID, ch.Alg, ct)
	}
	return ct, ch, err
}
