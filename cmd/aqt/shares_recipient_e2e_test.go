// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// TestIncomingShareNameIsRenderedInert covers the grantor-controlled metadata that
// lands in the recipient's terminal: an escape sequence there can erase the line and
// forge output that looks like aqt's own (a fake ref, a fake fingerprint MATCH).
func TestIncomingShareNameIsRenderedInert(t *testing.T) {
	h := newE2E(t)
	id := pushSecretFile(t, "innocent.txt", "payload")
	const hostile = "safe\x1b[2K\rforged\naqt://deadbeef  MATCH"
	if err := runRename(id, hostile); err != nil {
		t.Fatalf("rename: %v", err)
	}
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	if err := runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with: %v", err)
	}

	asProfile("bob", func() {
		out := captureStdout(t, func() {
			if err := sharesCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares: %v", err)
			}
		})
		if strings.ContainsAny(out, "\x1b\r") {
			t.Fatalf("shares printed raw control bytes from the grantor: %q", out)
		}
		// One line per share (plus the trailing hint block): the forged newline must
		// not have become a row of its own.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "aqt://") && !strings.Contains(line, id) {
				t.Fatalf("grantor forged an extra share row: %q", line)
			}
		}
	})
}

// TestHostileServerCannotForgeShareRows covers the half of the display surface no
// grantor controls: the resource ids and account handles in `aqt shares` and
// `aqt shares blocked` are the server's strings, and the server is trusted no more
// than the accounts it hosts. The proxy appends a row whose id and handle are made
// of the same control bytes a grantor would use.
func TestHostileServerCannotForgeShareRows(t *testing.T) {
	const hostile = "safe\x1b[2K\rforged\naqt://deadbeef  MATCH"
	newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		listing := r.Method == http.MethodGet && (r.URL.Path == "/v1/shares" || r.URL.Path == "/v1/share-blocks")
		if !listing {
			pass(w, r)
			return
		}
		rec := httptest.NewRecorder()
		pass(rec, r)
		var body map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
			copyRecorded(w, rec)
			return
		}
		if r.URL.Path == "/v1/shares" {
			rows, _ := body["shares"].([]any)
			body["shares"] = append(rows, map[string]any{"resourceId": hostile, "ownerHandle": hostile, "createdAt": 1})
		} else {
			rows, _ := body["blocks"].([]any)
			body["blocks"] = append(rows, map[string]any{"ownerHandle": hostile, "createdAt": 1})
		}
		replaceRecorded(w, rec, body)
	})

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"shares", func() error { return sharesCmd().RunE(nil, nil) }},
		{"shares blocked", func() error { return sharesBlockedCmd().RunE(nil, nil) }},
	} {
		out := captureStdout(t, func() {
			if err := tc.run(); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		})
		if strings.ContainsAny(out, "\x1b\r") {
			t.Fatalf("%s printed raw control bytes from the server: %q", tc.name, out)
		}
		// The server's row has to stay one row: a forged second line is how it would
		// pass off text of its own as ours.
		lines := 0
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "forged") || strings.Contains(line, "MATCH") {
				lines++
			}
		}
		if lines != 1 {
			t.Fatalf("%s spread the server's row over %d lines: %q", tc.name, lines, out)
		}
	}
}

// TestIncomingShareNamesItsSender pins the attribution half: a share from a pinned
// contact shows that contact's email and fingerprint, and an unpinned one is called
// an unknown sender rather than presented as an identity.
func TestIncomingShareNamesItsSender(t *testing.T) {
	h := newE2E(t)
	id := pushSecretFile(t, "shared.txt", "hello")
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	if err := runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with: %v", err)
	}

	asProfile("bob", func() {
		out := captureStdout(t, func() {
			if err := sharesCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares: %v", err)
			}
		})
		if !strings.Contains(out, "unknown sender") {
			t.Fatalf("an unpinned grantor should be marked unknown: %q", out)
		}

		// Pin the sender the way a recipient would once they know who it is.
		cl, prof, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		keys, err := fetchAccountKeys(cl, "e2e@example.com")
		if err != nil {
			t.Fatal(err)
		}
		pins, err := identity.LoadContacts(prof.Name)
		if err != nil {
			t.Fatal(err)
		}
		pins["e2e@example.com"] = identity.Contact{
			Email: "e2e@example.com", Handle: keys.Handle,
			PublicKey: keys.PublicKey, EncPublicKey: keys.EncPublicKey,
		}
		if err := identity.SaveContacts(prof.Name, pins); err != nil {
			t.Fatal(err)
		}

		out = captureStdout(t, func() {
			if err := sharesCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares: %v", err)
			}
		})
		if !strings.Contains(out, "e2e@example.com") || !strings.Contains(out, crypto.KeyFingerprint(keys.PublicKey)) {
			t.Fatalf("a pinned grantor should be named with its fingerprint: %q", out)
		}
		if strings.Contains(out, "unknown sender") {
			t.Fatalf("pinned grantor still reported as unknown: %q", out)
		}
	})
}

// TestGranteeRemovesAndBlocksAShare is the recipient-side acceptance test: decline a
// share, then block the account so it cannot immediately re-append the row.
func TestGranteeRemovesAndBlocksAShare(t *testing.T) {
	h := newE2E(t)
	first := pushSecretFile(t, "first.txt", "one")
	second := pushSecretFile(t, "second.txt", "two")
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	for _, id := range []string{first, second} {
		if err := runShareWith(id, "bob@example.com"); err != nil {
			t.Fatalf("share --with %s: %v", id, err)
		}
	}

	asProfile("bob", func() {
		// A plain removal drops only the named row and leaves the sender able to re-share.
		if err := runSharesRemove("aqt://"+first, false); err != nil {
			t.Fatalf("shares rm: %v", err)
		}
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		shares, err := cl.ListShares()
		if err != nil {
			t.Fatal(err)
		}
		if len(shares) != 1 || shares[0].ResourceID != second {
			t.Fatalf("after rm, want only %s left, got %+v", second, shares)
		}
		// Removing what is no longer there says so instead of reporting success.
		if err := runSharesRemove("aqt://"+first, false); err == nil {
			t.Fatal("second rm of the same share succeeded")
		}
	})

	// The owner can re-grant: a removal is not a block.
	if err := runShareWith(first, "bob@example.com"); err != nil {
		t.Fatalf("re-share after plain rm: %v", err)
	}

	asProfile("bob", func() {
		if err := runSharesRemove("aqt://"+first, true); err != nil {
			t.Fatalf("shares rm --block: %v", err)
		}
		cl, prof, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		// Knowing who the sender was is what makes a block manageable; pinning them is
		// how a handle becomes an address `aqt shares unblock` accepts.
		if _, err := lookupGrantee(cl, prof, "e2e@example.com"); err != nil {
			t.Fatalf("pin the sender: %v", err)
		}
		listed := captureStdout(t, func() {
			if err := sharesBlockedCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares blocked: %v", err)
			}
		})
		if !strings.Contains(listed, "e2e@example.com") {
			t.Fatalf("blocked listing does not name the sender: %q", listed)
		}
		// Blocking clears every share from that account, not only the named one.
		shares, err := cl.ListShares()
		if err != nil {
			t.Fatal(err)
		}
		if len(shares) != 0 {
			t.Fatalf("block left %d share(s) from the blocked account", len(shares))
		}
		blocks, err := cl.ListShareBlocks()
		if err != nil {
			t.Fatal(err)
		}
		if len(blocks) != 1 {
			t.Fatalf("want one block, got %+v", blocks)
		}
	})

	// A block is a definitive refusal, so the sender is told who declined rather than
	// left with a lost-outcome error suggesting a retry.
	err := runShareWith(first, "bob@example.com")
	if !errors.Is(err, client.ErrSenderBlocked) {
		t.Fatalf("re-grant to a blocked account = %v, want client.ErrSenderBlocked", err)
	}
	if !strings.Contains(err.Error(), "bob@example.com") {
		t.Fatalf("error = %q, want it to name the recipient", err)
	}

	asProfile("bob", func() {
		out := captureStdout(t, func() {
			if err := sharesUnblockCmd().RunE(nil, []string{"e2e@example.com"}); err != nil {
				t.Fatalf("shares unblock: %v", err)
			}
		})
		if !strings.Contains(out, "unblocked") {
			t.Fatalf("unblock output: %q", out)
		}
	})
	if err := runShareWith(first, "bob@example.com"); err != nil {
		t.Fatalf("share after unblock: %v", err)
	}
}

// TestShareRemovalIsGranteeScoped: the delete predicate is the caller's own grantee
// handle, so a third account cannot use it to strip somebody else's access.
func TestShareRemovalIsGranteeScoped(t *testing.T) {
	h := newE2E(t)
	id := pushSecretFile(t, "shared.txt", "hello")
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "mallory@example.com", "mallory", "mallory horse battery staple")
	if err := runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}

	asProfile("mallory", func() {
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.RemoveShare(id, false); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("mallory removing bob's share: got %v, want ErrNotFound", err)
		}
		if _, err := cl.RemoveShare(id, true); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("mallory blocking through bob's share: got %v, want ErrNotFound", err)
		}
	})

	asProfile("bob", func() {
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		shares, err := cl.ListShares()
		if err != nil {
			t.Fatal(err)
		}
		if len(shares) != 1 {
			t.Fatalf("bob's share was removed by another account: %+v", shares)
		}
	})
	// And no block was recorded against the owner by that attempt.
	asProfile("mallory", func() {
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		blocks, err := cl.ListShareBlocks()
		if err != nil {
			t.Fatal(err)
		}
		if len(blocks) != 0 {
			t.Fatalf("a failed removal still recorded a block: %+v", blocks)
		}
	})
}

// TestContactsPinRefusesAWrongFingerprint covers the documented out-of-band
// mitigation: a pin made against a fingerprint the contact read out over another
// channel must fail closed when the server presents anything else.
func TestContactsPinRefusesAWrongFingerprint(t *testing.T) {
	h := newE2E(t)
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := fetchAccountKeys(cl, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}

	pin := contactsPinCmd()
	if err := pin.Flags().Set("fingerprint", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}
	if err := pin.RunE(pin, []string{"bob@example.com"}); err == nil {
		t.Fatal("pinning against a mismatched fingerprint succeeded")
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pins["bob@example.com"]; ok {
		t.Fatal("a refused pin was still written")
	}

	// The real fingerprint pins, with or without the SHA256: prefix.
	pin = contactsPinCmd()
	if err := pin.Flags().Set("fingerprint", strings.TrimPrefix(crypto.KeyFingerprint(keys.PublicKey), "SHA256:")); err != nil {
		t.Fatal(err)
	}
	if err := pin.RunE(pin, []string{"bob@example.com"}); err != nil {
		t.Fatalf("pin with the right fingerprint: %v", err)
	}
	pins, err = identity.LoadContacts(prof.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := pins["bob@example.com"]; !ok || got.Handle != keys.Handle {
		t.Fatalf("pin not stored: %+v", pins)
	}

	// Re-pinning is a no-op, and --json says so in the same shape rather than prose a
	// script would fail to parse.
	flagJSON = true
	defer func() { flagJSON = false }()
	out := captureStdout(t, func() {
		repin := contactsPinCmd()
		if err := repin.RunE(repin, []string{"bob@example.com"}); err != nil {
			t.Fatalf("re-pin: %v", err)
		}
	})
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("re-pin --json emitted %q: %v", out, err)
	}
	if doc["alreadyPinned"] != true || doc["fingerprint"] != crypto.KeyFingerprint(keys.PublicKey) {
		t.Fatalf("re-pin --json = %v", doc)
	}
	flagJSON = false

	// With the contact pinned before any grant, sharing must not re-pin or complain.
	id := pushSecretFile(t, "for-bob.txt", "hello")
	if err := runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share to a pre-pinned contact: %v", err)
	}
}

// TestConfirmPinnedKeysReportsRotationNotSubstitution: the re-wrap path must reach
// its own diagnosis. Routing it through lookupGrantee made this branch dead code and
// reported a grantee's routine root-key rotation as the server swapping keys.
func TestConfirmPinnedKeysReportsRotationNotSubstitution(t *testing.T) {
	h := newE2E(t)
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	pin, err := lookupGrantee(cl, prof, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := confirmPinnedKeys(cl, prof, pin); err != nil {
		t.Fatalf("confirming an unchanged pin: %v", err)
	}

	// Bob rotates his account root key, which republishes his enc key under the new
	// root. Bob owns nothing and holds no grants, so the rotation carries no re-wraps.
	asProfile("bob", func() {
		bobClient, bobProf, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		uk, err := crypto.DeriveUnlockKey("bob horse battery staple", bobProf.Kdf)
		if err != nil {
			t.Fatal(err)
		}
		defer uk.Wipe()
		newRoot, err := crypto.GenerateMasterKey()
		if err != nil {
			t.Fatal(err)
		}
		defer newRoot.Wipe()
		wrappedRoot, err := crypto.WrapRoot(newRoot, uk)
		if err != nil {
			t.Fatal(err)
		}
		signing := crypto.DeriveSigningKey(newRoot)
		encPub := crypto.DeriveEncKey(newRoot).Public()
		if _, err := bobClient.RotateRootKey(api.RootKeyRotationRequest{
			Kdf: bobProf.Kdf, WrappedRoot: wrappedRoot,
			OldAuthVerifier: crypto.DeriveAuthVerifier(uk),
			NewAuthVerifier: crypto.DeriveAuthVerifier(uk),
			ExpectedEpoch:   bobProf.AuthEpoch,
			PublicKey:       signing.Public().(ed25519.PublicKey),
			EncPublicKey:    encPub,
			EncKeySig:       crypto.SignEncKey(signing, encPub),
		}); err != nil {
			t.Fatalf("rotate bob's root key: %v", err)
		}
	})

	err = confirmPinnedKeys(cl, prof, pin)
	if err == nil {
		t.Fatal("confirmPinnedKeys accepted keys that no longer match the pin")
	}
	if !strings.Contains(err.Error(), "rotated") {
		t.Fatalf("want the rotation diagnosis, got %q", err)
	}
	if strings.Contains(err.Error(), "substituting keys") {
		t.Fatalf("a routine rotation was reported as a server attack: %q", err)
	}
}
