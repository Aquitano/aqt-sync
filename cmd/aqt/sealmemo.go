// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/compress"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// sealMemo is the node cache's second key dimension, serving the write path the
// way the id-keyed store serves reads: it maps an account-keyed digest of a
// directory node's plaintext to the id and compression alg the node last sealed
// to, with the ciphertext itself living in the ordinary id-keyed store. A push
// whose tree barely changed then reuses unchanged nodes' ciphertext instead of
// re-compressing and re-encrypting every node. Entries are advisory —
// crypto.SealNodeMemo verifies every hit by reopening, so a corrupt, evicted, or
// mismatched entry is just a miss — and hold only public data plus the keyed
// digest, never a node key.
//
// Entries live under a compress.CodecID() namespace: convergent ids depend on
// the compressor's exact output, so entries sealed by a previous codec — still
// valid, no longer canonical — would otherwise survive an upgrade and make a
// reused push's root drift from what a cold seal produces.
type sealMemo struct {
	cache *nodeCache
	dir   string
}

// openSealMemo returns the persistent seal memo, or nil (seal cold) whenever the
// node cache itself is disabled.
func openSealMemo() crypto.NodeSealMemo {
	c := openNodeCache()
	if c == nil {
		return nil
	}
	return &sealMemo{cache: c, dir: filepath.Join(c.dir, "seal", compress.CodecID())}
}

func (m *sealMemo) path(digest string) string {
	return filepath.Join(m.dir, digest[:2], digest)
}

func (m *sealMemo) GetNodeSeal(digest string) (id, alg string, ciphertext []byte, ok bool) {
	if !validCacheID(digest) {
		return "", "", nil, false
	}
	p := m.path(digest)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", "", nil, false
	}
	id, alg, found := strings.Cut(strings.TrimSuffix(string(b), "\n"), "\n")
	if !found || !validCacheID(id) {
		_ = os.Remove(p) // mangled entry: drop it so the next seal rewrites it
		return "", "", nil, false
	}
	ct, hit := m.cache.get(id)
	if !hit {
		return "", "", nil, false
	}
	now := time.Now()
	_ = os.Chtimes(p, now, now) // LRU signal for the shared cache prune
	return id, alg, ct, true
}

func (m *sealMemo) PutNodeSeal(digest, id, alg string, ciphertext []byte) {
	if !validCacheID(digest) || !validCacheID(id) {
		return
	}
	m.cache.put(id, ciphertext)
	p := m.path(digest)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	// Always write, even over an existing entry: a put after a rejected hit is
	// how a stale record heals, and skipping it would pin that node to a cold
	// seal forever. Temp+rename, like the id-keyed store: a torn entry would
	// just miss, but a concurrent reader should never have to pay that re-seal.
	f, err := os.CreateTemp(filepath.Dir(p), ".aqt-tmp-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.WriteString(id + "\n" + alg + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Rename(tmp, p) != nil {
		_ = os.Remove(tmp)
	}
}
