package main

import (
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// FuzzDecodeBase feeds arbitrary bytes to the base.json decoder, which reads a control
// file that a hostile actor with local access could tamper with. It probes for a sealed
// envelope and otherwise falls through to a plaintext manifest, so the invariant is that
// no byte sequence panics either branch. Keychain access is disabled so the sealed
// branch resolves deterministically to a decrypt failure rather than reaching the host
// keyring.
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
