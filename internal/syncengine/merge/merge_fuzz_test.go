// SPDX-License-Identifier: AGPL-3.0-or-later

package merge

import (
	"bytes"
	"testing"
)

func FuzzChangesReconstructsTarget(f *testing.F) {
	f.Add([]byte("one\ntwo\n"), []byte("ONE\ntwo\nthree\n"))
	f.Add([]byte{}, []byte("tail"))
	f.Fuzz(func(t *testing.T, base, target []byte) {
		if len(base)+len(target) > 64<<10 {
			t.Skip()
		}
		changes, ok := Changes(base, target)
		if !ok {
			return
		}
		if got := apply(base, changes); !bytes.Equal(got, target) {
			t.Fatalf("reconstructed target differs")
		}
	})
}

func FuzzThreeWayCleanLinesComeFromInputs(f *testing.F) {
	f.Add([]byte("one\ntwo\nthree\n"), []byte("ONE\ntwo\nthree\n"), []byte("one\ntwo\nTHREE\n"))
	f.Add([]byte("\n"), []byte("\n0"), []byte("0"))
	f.Fuzz(func(t *testing.T, base, local, remote []byte) {
		if len(base)+len(local)+len(remote) > 64<<10 {
			t.Skip()
		}
		got, clean := ThreeWay(base, local, remote)
		if !clean && got != nil {
			t.Fatal("conflicted merge returned content")
		}
		if !clean {
			return
		}
		inputs := [][][]byte{splitLines(base), splitLines(local), splitLines(remote)}
		for _, line := range splitLines(got) {
			found := false
			for _, input := range inputs {
				for _, candidate := range input {
					if bytes.Equal(line, candidate) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				t.Fatalf("clean merge invented output line %q", line)
			}
		}
	})
}
