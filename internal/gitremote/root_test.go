package gitremote

import (
	"reflect"
	"strings"
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
		Refs: map[string]string{"refs/heads/main": oid256("a")}, Generation: 2,
		ObjectFormat: "sha256",
		Bundles: []BundleRef{{ID: "group", Full: true, Tips: []string{oid256("a")}, Bases: []string{oid256("d")},
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
		"wrong version":       {Version: RefsRootVersion + 1},
		"negative generation": {Version: RefsRootVersion, Generation: -1},
		"head not a branch":   {Version: RefsRootVersion, Head: "main"},
		"unknown format":      {Version: RefsRootVersion, ObjectFormat: "sha512"},
		"ref outside refs/":   {Version: RefsRootVersion, Refs: map[string]string{"heads/main": oid1("a")}},
		"ref with empty oid":  {Version: RefsRootVersion, Refs: map[string]string{"refs/heads/main": ""}},
		"ref with short oid":  {Version: RefsRootVersion, Refs: map[string]string{"refs/heads/main": "abc"}},
		"ref with non-hex oid": {Version: RefsRootVersion,
			Refs: map[string]string{"refs/heads/main": strings.Repeat("g", 40)}},
		"ref with uppercase oid": {Version: RefsRootVersion,
			Refs: map[string]string{"refs/heads/main": strings.Repeat("A", 40)}},
		"ref with option-like oid": {Version: RefsRootVersion,
			Refs: map[string]string{"refs/heads/main": "-" + strings.Repeat("a", 39)}},
		"sha256 oid under sha1 format": {Version: RefsRootVersion,
			Refs: map[string]string{"refs/heads/main": oid256("a")}},
		"sha1 oid under sha256 format": {Version: RefsRootVersion, ObjectFormat: "sha256",
			Refs: map[string]string{"refs/heads/main": oid1("a")}},
		"bundle tip with bad oid": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g",
			Tips: []string{"abc"}, Segments: []Segment{valid}}}},
		"bundle base with bad oid": {Version: RefsRootVersion, Bundles: []BundleRef{{ID: "g",
			Tips: []string{oid1("a")}, Bases: []string{"-" + strings.Repeat("b", 39)}, Segments: []Segment{valid}}}},
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

func oid1(hexDigit string) string   { return strings.Repeat(hexDigit, 40) }
func oid256(hexDigit string) string { return strings.Repeat(hexDigit, 64) }
