// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// FuzzDecodeBase feeds arbitrary bytes to the base.json decoder, which reads a control
// file that a hostile actor with local access could tamper with. The invariant is that
// no byte sequence panics: anything but an openable sealed envelope is an error.
// Keychain access is disabled so the sealed branch resolves deterministically to a
// decrypt failure rather than reaching the host keyring.
func FuzzDecodeBase(f *testing.F) {
	f.Add([]byte(`{"entries":[{"path":"a","hash":"x"}]}`))
	f.Add([]byte(`{"sealed":{"nonce":"AAAA","ciphertext":"AAAA"}}`))
	f.Add([]byte("not json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		t.Setenv("AQT_NO_KEYCHAIN", "1")
		var m syncengine.Manifest
		_ = decodeBase(b, &m)
	})
}

// FuzzMergeModeEditScripts drives arbitrary three-version content through merge
// mode's pure policy seam. The resolution is always either one clean merged primary,
// or byte-exact local primary plus byte-exact remote conflict copy.
func FuzzMergeModeEditScripts(f *testing.F) {
	f.Add([]byte("one\ntwo\nthree\n"), []byte("ONE\ntwo\nthree\n"), []byte("one\ntwo\nTHREE\n"))
	f.Add([]byte("same\n"), []byte("local\n"), []byte("remote\n"))
	f.Fuzz(func(t *testing.T, base, local, remote []byte) {
		if len(base)+len(local)+len(remote) > 64<<10 {
			t.Skip()
		}
		primary, copy, merged := mergeConflictBytes(base, local, remote)
		if merged {
			if copy != nil {
				t.Fatal("clean merge returned a conflict copy")
			}
			return
		}
		if !bytes.Equal(primary, local) || !bytes.Equal(copy, remote) {
			t.Fatal("fallback changed or lost one side")
		}
	})
}
