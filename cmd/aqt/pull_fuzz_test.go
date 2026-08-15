// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/url"
	"strings"
	"testing"
)

// FuzzParseRef feeds arbitrary ref strings (share URLs, aqt:// refs, bare ids) to the
// parser that runs on untrusted user/link input. Invariants: it never panics; the
// fragment is stripped from the returned id (so a '#' can never leak into an id used
// to build a server route); and a non-empty origin is always a parseable http(s)
// URL, never a value fabricated from an aqt:// ref or bare id.
func FuzzParseRef(f *testing.F) {
	f.Add("https://host.example/x/abc123#k.deadbeef")
	f.Add("aqt://abc123")
	f.Add("aqt://abc123/sub/path")
	f.Add("bareid")
	f.Add("")
	f.Add("#onlyfragment")
	f.Add("http://h/x/id/with/extra")
	f.Fuzz(func(t *testing.T, ref string) {
		id, _, origin := parseRef(ref)
		if strings.Contains(id, "#") {
			t.Fatalf("id %q retains a fragment separator", id)
		}
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				t.Fatalf("origin %q is not a well-formed http(s) origin", origin)
			}
			if origin != u.Scheme+"://"+u.Host {
				t.Fatalf("origin %q carries more than scheme://host", origin)
			}
		}
	})
}
