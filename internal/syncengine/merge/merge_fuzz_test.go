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
		if got := apply(base, Changes(base, target)); !bytes.Equal(got, target) {
			t.Fatalf("reconstructed target differs")
		}
	})
}

func FuzzThreeWayNeverInventsMarkers(f *testing.F) {
	f.Add([]byte("one\ntwo\nthree\n"), []byte("ONE\ntwo\nthree\n"), []byte("one\ntwo\nTHREE\n"))
	f.Fuzz(func(t *testing.T, base, local, remote []byte) {
		if len(base)+len(local)+len(remote) > 64<<10 {
			t.Skip()
		}
		got, clean := ThreeWay(base, local, remote)
		if !clean && got != nil {
			t.Fatal("conflicted merge returned content")
		}
		if clean && bytes.Contains(got, []byte("<<<<<<< aqt")) {
			t.Fatal("merge invented conflict markers")
		}
	})
}
