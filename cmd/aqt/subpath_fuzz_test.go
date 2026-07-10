package main

import (
	"strings"
	"testing"
)

// FuzzSplitRefPath drives the aqt://<id>/<sub/path> splitter on arbitrary refs. Beyond
// not panicking it asserts two properties the function actually guarantees:
//
//   - Idempotence: re-splitting the returned baseRef yields that same baseRef and an
//     empty subpath. baseRef either is a non-aqt ref (returned verbatim) or is
//     "aqt://<id>[#frag]" with the subpath already peeled off, so a second split has
//     nothing left to remove. A regression that left a trailing path segment on baseRef
//     would break this.
//   - The subpath is returned without surrounding slashes.
func FuzzSplitRefPath(f *testing.F) {
	f.Add("aqt://id/a/b/c")
	f.Add("aqt://id/a/b#frag")
	f.Add("aqt://id")
	f.Add("https://host/x/id#k.abc")
	f.Add("bareid")
	f.Add("")
	f.Add("aqt://id///trailing///")
	f.Fuzz(func(t *testing.T, ref string) {
		baseRef, subpath := splitRefPath(ref)

		if strings.HasPrefix(subpath, "/") || strings.HasSuffix(subpath, "/") {
			t.Fatalf("subpath %q is not slash-trimmed", subpath)
		}

		base2, sub2 := splitRefPath(baseRef)
		if base2 != baseRef || sub2 != "" {
			t.Fatalf("not idempotent: splitRefPath(%q) = (%q, %q), want (%q, \"\")", baseRef, base2, sub2, baseRef)
		}
	})
}
