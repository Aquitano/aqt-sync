// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"fmt"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// BenchmarkPutResourceCreate measures a large create with and without an
// Idempotency-Key. Without a key no request digest is computed at all; with one,
// a single digest of the complete request (blob included) covers both the replay
// lookup and the recorded row.
func BenchmarkPutResourceCreate(b *testing.B) {
	for _, tc := range []struct {
		name    string
		withKey bool
	}{
		{"no-key", false},
		{"with-key", true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := newStore(b)
			owner := s.mustAccount(b, "bench@example.com")
			ck, _ := crypto.GenerateContentKey()
			blob, _ := crypto.Seal(make([]byte, 4<<20), ck, crypto.AADBlob)
			meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
			wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
			b.SetBytes(int64(len(blob.Ciphertext)))
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				req := api.PutResourceRequest{
					Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
				}
				if tc.withKey {
					req.IdempotencyKey = fmt.Sprintf("bench-key-%d", i)
				}
				if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, req); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}
