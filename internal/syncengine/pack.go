// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"github.com/aquitano/aqt-sync/internal/api"
)

// DefaultPackTarget is the object-region size a PackBuilder fills toward before the
// caller flushes it. A pack stays comfortably under the server's pack body cap once
// the index trailer is appended, so the wire unit is bounded regardless of file or
// tree size — the mechanism that turns O(tree) push memory into O(pack).
const DefaultPackTarget = 16 << 20

// PackBuilder concatenates sealed chunk ciphertexts into one self-describing pack:
//
//	[ object0 ][ object1 ] ... [ objectN ][ index JSON ][ uint32 indexLen ]
//
// The index is a JSON array of api.PackIndexEntry recording each object's id and
// byte slice; the four trailing bytes are the index length so a reader can find it
// from the end. The pack id is sha256 over the whole serialized pack. The server
// re-derives both and verifies every slice against its id, so a malformed pack is
// rejected wholesale.
type PackBuilder struct {
	buf   []byte
	index []api.PackIndexEntry
}

func NewPackBuilder() *PackBuilder { return &PackBuilder{} }

// Add appends one sealed object and records its slice in the running index.
func (p *PackBuilder) Add(id string, ciphertext []byte) {
	p.index = append(p.index, api.PackIndexEntry{ID: id, Off: len(p.buf), Len: len(ciphertext)})
	p.buf = append(p.buf, ciphertext...)
}

// Size is the current object-region byte count (the index trailer is not yet
// written), so a caller can flush once it reaches DefaultPackTarget.
func (p *PackBuilder) Size() int { return len(p.buf) }

// Empty reports whether no objects have been added.
func (p *PackBuilder) Empty() bool { return len(p.index) == 0 }

// Finish appends the index and its length trailer, then returns the pack id and the
// serialized bytes. The builder must not be used after Finish; the returned slice
// aliases its internal buffer.
func (p *PackBuilder) Finish() (id string, pack []byte) {
	indexJSON, err := json.Marshal(p.index)
	if err != nil {
		panic("syncengine: marshal pack index: " + err.Error()) // a []PackIndexEntry always marshals
	}
	p.buf = append(p.buf, indexJSON...)
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(indexJSON)))
	p.buf = append(p.buf, lenbuf[:]...)
	sum := sha256.Sum256(p.buf)
	return hex.EncodeToString(sum[:]), p.buf
}
