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
		Bundles: []BundleRef{{ID: "group", Full: true, Tips: []string{"abc"}, Bases: []string{"def"},
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

// Validate is the guard between a decrypted root and everything that trusts it,
// so each rejection path gets a case here.
func TestRefsRootValidateRejectsMalformed(t *testing.T) {
	valid := validSegment()
	cases := map[string]RefsRoot{
		"wrong version":           {Version: RefsRootVersion + 1},
		"negative generation":     {Version: RefsRootVersion, Generation: -1},
		"head not a branch":       {Version: RefsRootVersion, Head: "main"},
		"unknown format":          {Version: RefsRootVersion, ObjectFormat: "sha512"},
		"ref outside refs/":       {Version: RefsRootVersion, Refs: map[string]string{"heads/main": "abc"}},
		"ref with empty oid":      {Version: RefsRootVersion, Refs: map[string]string{"refs/heads/main": ""}},
		"bundle without id":       {Version: RefsRootVersion, Bundles: []BundleRef{{Segments: []Segment{valid}}}},
		"bundle without segments": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g"}}},
		"segment without id": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g",
			Segments: []Segment{{Len: 4, Size: crypto.NonceSize + 20}}}}},
		"segment shorter than nonce": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g",
			Segments: []Segment{{ID: "s", Len: 4, Size: crypto.NonceSize}}}}},
		"segment with negative len": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g",
			Segments: []Segment{{ID: "s", Len: -1, Size: crypto.NonceSize + 20}}}}},
	}
	for name, root := range cases {
		if err := root.Validate(); err == nil {
			t.Fatalf("%s: Validate accepted %#v", name, root)
		}
	}
}

func validSegment() Segment {
	return Segment{ID: "s", Len: 4, Size: crypto.NonceSize + 20}
}
