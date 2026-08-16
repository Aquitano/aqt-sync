// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"strings"
	"testing"
)

// FuzzDecodeFragment feeds arbitrary fragment/password pairs to the link-key decoder,
// which parses the '#' fragment of a share URL an untrusted party controls. The
// invariant is no panic on any input.
//
// Gated ("p.") fragments are skipped: a gated decode runs Argon2id with the memory
// cost carried in the fragment (bounded by validate() to 1 GiB, but still far too
// expensive to run per fuzz iteration). The public and malformed-format branches, where
// the untrusted base64/length parsing lives, are exercised in full.
func FuzzDecodeFragment(f *testing.F) {
	f.Add("k.AAAA", "")
	f.Add("k.", "pw")
	f.Add("p.garbage", "pw")
	f.Add("", "")
	f.Add("nonsense", "x")
	f.Fuzz(func(t *testing.T, fragment, password string) {
		if strings.HasPrefix(fragment, fragGated) {
			return
		}
		_, _ = DecodeFragment(fragment, password)
	})
}

// FuzzFragmentRoundTrip pins the public fragment codec: any 32-byte key encodes to a
// fragment that decodes back to the same key. Only the public (empty-password) path is
// round-tripped; the gated path calibrates fresh Argon2id params on every encode, which
// is too slow to fuzz.
func FuzzFragmentRoundTrip(f *testing.F) {
	f.Add(make([]byte, KeySize))
	seed := make([]byte, KeySize)
	for i := range seed {
		seed[i] = byte(i)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, keyBytes []byte) {
		if len(keyBytes) != KeySize {
			return
		}
		var ck ContentKey
		copy(ck[:], keyBytes)

		frag, err := EncodeFragment(ck, "")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := DecodeFragment(frag, "")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got != ck {
			t.Fatalf("round-trip key mismatch")
		}
	})
}
