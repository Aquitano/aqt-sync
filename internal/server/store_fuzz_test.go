// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"unicode/utf8"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// FuzzParsePackIndex feeds arbitrary bytes to the pack-index parser, which reads the
// trailing index a client uploads. Two invariants must hold on every input: it never
// panics, and when it succeeds the objects region it reports is in bounds. It then
// replays exactly the bounds check PutPack applies to each entry and slices the
// object region, so a hostile Off/Len that slips past the guard would panic here and
// fail the fuzz rather than reach production untested.
func FuzzParsePackIndex(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	_, seedPack := buildPack([]string{"a", "bb"}, [][]byte{[]byte("x"), []byte("yy")})
	f.Add(seedPack)
	f.Fuzz(func(t *testing.T, data []byte) {
		index, objectsEnd, err := parsePackIndex(data)
		if err != nil {
			return
		}
		if objectsEnd < 0 || objectsEnd > len(data)-4 {
			t.Fatalf("objectsEnd %d out of range for pack of %d bytes", objectsEnd, len(data))
		}
		for _, e := range index {
			// The exact guard from PutPack: never compute Off+Len before it is proven
			// in range, or a wrapping sum would slip past and panic the slice below.
			if e.Off < 0 || e.Len < 0 || e.Off > objectsEnd || e.Len > objectsEnd-e.Off {
				continue
			}
			_ = data[e.Off : e.Off+e.Len]
		}
	})
}

// FuzzPackRoundTrip builds a pack with the production PackBuilder from fuzzed
// (id, payload) pairs and asserts parsePackIndex recovers every entry and that each
// recorded slice addresses the exact bytes that were added. This pins the encoder and
// the server-side decoder to one shared layout, so a change to either that breaks the
// other is caught immediately.
func FuzzPackRoundTrip(f *testing.F) {
	f.Add([]byte("id0"), []byte("payload0"), []byte("id1"), []byte("payload1"))
	f.Add([]byte(""), []byte(""), []byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, id0, p0, id1, p1 []byte) {
		// The index serializes ids as JSON strings, which cannot carry invalid UTF-8
		// losslessly. Real object ids are hex content addresses, so valid UTF-8 covers
		// every id a genuine pack contains.
		if !utf8.Valid(id0) || !utf8.Valid(id1) {
			return
		}
		ids := []string{string(id0), string(id1)}
		payloads := [][]byte{p0, p1}

		_, pack := buildPack(ids, payloads)
		index, objectsEnd, err := parsePackIndex(pack)
		if err != nil {
			t.Fatalf("parse a pack we just built: %v", err)
		}
		if len(index) != len(ids) {
			t.Fatalf("recovered %d entries, added %d", len(index), len(ids))
		}
		for i, e := range index {
			if e.ID != ids[i] {
				t.Fatalf("entry %d id %q, want %q", i, e.ID, ids[i])
			}
			if e.Off < 0 || e.Len < 0 || e.Off > objectsEnd || e.Len > objectsEnd-e.Off {
				t.Fatalf("entry %d slice [%d,%d) escapes object region ending at %d", i, e.Off, e.Off+e.Len, objectsEnd)
			}
			if !bytes.Equal(pack[e.Off:e.Off+e.Len], payloads[i]) {
				t.Fatalf("entry %d bytes do not match the payload added", i)
			}
		}
	})
}

// buildPack assembles a pack through the real PackBuilder and returns its id and bytes.
func buildPack(ids []string, payloads [][]byte) (string, []byte) {
	b := syncengine.NewPackBuilder()
	for i := range ids {
		b.Add(ids[i], payloads[i])
	}
	id, pack := b.Finish()
	sum := sha256.Sum256(pack)
	if hex.EncodeToString(sum[:]) != id {
		panic("pack id does not match its bytes")
	}
	return id, pack
}
