// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"testing"
)

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
