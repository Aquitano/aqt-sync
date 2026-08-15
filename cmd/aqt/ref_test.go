// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"testing"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func TestParseRefExtractsOrigin(t *testing.T) {
	const id = "rSRi42-HCoc"
	cases := []struct {
		name         string
		ref          string
		wantFragment string
		wantOrigin   string
	}{
		{"bare id", id, "", ""},
		{"aqt scheme", "aqt://" + id, "", ""},
		{"aqt scheme with key", "aqt://" + id + "#k.abc", "k.abc", ""},
		{"https url", "https://example.com/x/" + id, "", "https://example.com"},
		{"https url with key", "https://example.com/x/" + id + "#k.abc", "k.abc", "https://example.com"},
		{"http host:port with key", "http://127.0.0.1:18080/x/" + id + "#k.kDbZ", "k.kDbZ", "http://127.0.0.1:18080"},
		{"https url no /x/ segment", "https://example.com/" + id, "", "https://example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotID, gotFrag, gotOrigin := parseRef(tc.ref)
			if gotID != id {
				t.Errorf("id = %q, want %q", gotID, id)
			}
			if gotFrag != tc.wantFragment {
				t.Errorf("fragment = %q, want %q", gotFrag, tc.wantFragment)
			}
			if gotOrigin != tc.wantOrigin {
				t.Errorf("origin = %q, want %q", gotOrigin, tc.wantOrigin)
			}
		})
	}
}

func TestLinkServerPrecedence(t *testing.T) {
	prof := &identity.Profile{Server: "https://me.example.com"}
	cases := []struct {
		name       string
		flagServer string
		origin     string
		prof       *identity.Profile
		wantServer string
		wantOwn    bool
	}{
		{"explicit flag beats ref host", "https://flag.example.com", "https://foreign.example.com", prof, "https://flag.example.com", true},
		{"foreign ref host is not own server", "", "https://foreign.example.com", prof, "https://foreign.example.com", false},
		{"ref host matching profile is own server", "", "https://me.example.com", prof, "https://me.example.com", true},
		{"trailing slash still matches profile", "", "https://me.example.com/", prof, "https://me.example.com/", true},
		{"no ref host falls back to profile", "", "", prof, "https://me.example.com", true},
		{"no ref host, no profile falls back to default", "", "", nil, defaultServer, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := flagServer
			flagServer = tc.flagServer
			defer func() { flagServer = old }()

			server, own := linkServer(tc.origin, tc.prof)
			if server != tc.wantServer {
				t.Errorf("server = %q, want %q", server, tc.wantServer)
			}
			if own != tc.wantOwn {
				t.Errorf("ownServer = %v, want %v", own, tc.wantOwn)
			}
		})
	}
}

// A share link to a foreign host must never carry the device token. client.New
// refuses a token over a non-HTTPS non-loopback URL, so a plain-http foreign
// origin succeeding proves the token was withheld, and the own-server case
// erroring proves it was attached.
func TestNewLinkClientWithholdsTokenFromForeignHost(t *testing.T) {
	old := flagServer
	flagServer = ""
	defer func() { flagServer = old }()

	prof := &identity.Profile{Server: "https://me.example.com", Token: "secret"}

	if _, err := newLinkClient("http://attacker.example.com", prof); err != nil {
		t.Fatalf("foreign http origin should drop the token and build cleanly, got %v", err)
	}

	own := &identity.Profile{Server: "http://me.example.com", Token: "secret"}
	_, err := newLinkClient("http://me.example.com", own)
	if !errors.Is(err, client.ErrInsecureScheme) {
		t.Fatalf("own-server http origin should attach the token and trip the scheme guard, got %v", err)
	}
}
