// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"testing"
	"time"
)

// forceGC sweeps ignoring the age guard (cutoff in the future), so a test does
// not have to wait out gcMinAge to collect a just-uploaded pack.
const forceGC = -time.Hour

func newStore(tb testing.TB) *Store {
	tb.Helper()
	s, err := OpenStore(tb.TempDir())
	if err != nil {
		tb.Fatalf("open store: %v", err)
	}
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

// objID returns the content address of an object's ciphertext.
func objID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// packOf assembles a valid pack from the given object payloads, in order. It builds
// the wire format independently of the client's PackBuilder so the server's parse
// path is exercised on its own. Returns the pack id, the pack bytes, and the object
// ids in order.
func packOf(payloads ...string) (packID string, pack []byte, ids []string) {
	var buf bytes.Buffer
	var index []api.PackIndexEntry
	for _, p := range payloads {
		b := []byte(p)
		id := objID(b)
		ids = append(ids, id)
		index = append(index, api.PackIndexEntry{ID: id, Off: buf.Len(), Len: len(b)})
		buf.Write(b)
	}
	indexJSON, _ := json.Marshal(index)
	buf.Write(indexJSON)
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(indexJSON)))
	buf.Write(lenbuf[:])
	pack = buf.Bytes()
	return objID(pack), pack, ids
}

func (s *Store) mustAccount(tb testing.TB, email string) string {
	tb.Helper()
	kdf := cryptotest.KdfParams(tb)
	acc, err := s.CreateAccount(email, kdf, make([]byte, 32), crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)}, make([]byte, 32), nil, nil)
	if err != nil {
		tb.Fatalf("create account: %v", err)
	}
	return acc.OwnerHandle
}

// rootResource creates a folder resource referencing the given object ids, so a
// sweep treats them (and their packs) as live.
func (s *Store) rootResource(t *testing.T, owner string, refs []string) string {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed manifest"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"folder","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ChunkRefs: refs,
	})
	if err != nil {
		t.Fatalf("root resource: %v", err)
	}
	return id
}
