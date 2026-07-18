package gitremote

import (
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestRefsRootRoundTripBound(t *testing.T) {
	key, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	want := RefsRoot{
		Version: RefsRootVersion, Head: "refs/heads/main",
		Refs: map[string]string{"refs/heads/main": "abc"}, Generation: 2,
		ObjectFormat: "sha256",
		Bundles: []BundleRef{{ID: "group", Tips: []string{"abc"}, Bases: []string{"def"},
			Segments: []Segment{{ID: "segment", Len: 4, Size: crypto.NonceSize + 20}}}},
	}
	sealed, err := SealRefsRoot(want, key, "resource")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenRefsRoot(sealed, key, "resource")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, want)
	}
	if _, err := OpenRefsRoot(sealed, key, "other"); err == nil {
		t.Fatal("id-bound root opened under another resource id")
	}
}

func TestNewRefsRootIsValid(t *testing.T) {
	root := NewRefsRoot()
	if err := root.Validate(); err != nil {
		t.Fatal(err)
	}
	if root.Size() != 0 || len(root.SegmentIDs()) != 0 {
		t.Fatalf("new root is not empty: %#v", root)
	}
}
