// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// grantSignup registers a second account with a published enc key under its own
// profile name, so a test acts as several users by flipping flagProfile.
func grantSignup(t *testing.T, h *e2eHarness, email, profile, pass string) {
	t.Helper()
	kdf := cryptotest.KdfParams(t)
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(pass, kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.New(h.url, "")
	if err != nil {
		t.Fatal(err)
	}
	signing := crypto.DeriveSigningKey(mk)
	encPub := crypto.DeriveEncKey(mk).Public()
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    signing.Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "e2e-grant",
		EncPublicKey: encPub,
		EncKeySig:    crypto.SignEncKey(signing, encPub),
	})
	if err != nil {
		t.Fatalf("grant signup %s: %v", email, err)
	}
	if err := identity.Save(&identity.Profile{
		Name: profile, Server: h.url, Email: email,
		OwnerHandle: resp.OwnerHandle, DeviceID: resp.DeviceID, Token: resp.Token,
		Kdf: kdf, WrappedRoot: wrappedRoot, AuthEpoch: resp.Epoch,
	}); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveSession(profile, mk, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func asProfile(name string, fn func()) {
	old := flagProfile
	flagProfile = name
	defer func() { flagProfile = old }()
	fn()
}

// pushSecretFile pushes one inline file as the current profile and returns its id.
func pushSecretFile(t *testing.T, name, content string) string {
	t.Helper()
	fpath := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(fpath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	rows, err := collectResources(cl, mk)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Name == name {
			return r.ID
		}
	}
	t.Fatalf("pushed file %s not found in listing", name)
	return ""
}

// TestGrantFileShareAndRevoke is the issue #79 file-path acceptance test: grant,
// list, pull as the grantee, strict read-only, then revoke with key rotation.
func TestGrantFileShareAndRevoke(t *testing.T) {
	h := newE2E(t)
	const content = "grant me this"
	id := pushSecretFile(t, "granted.txt", content)
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
		if !strings.Contains(out, id) || !strings.Contains(out, "granted.txt") {
			t.Fatalf("shares output missing the grant: %q", out)
		}

		dest := filepath.Join(t.TempDir(), "out.txt")
		if err := runPull("aqt://"+id, dest, "", false, false); err != nil {
			t.Fatalf("grantee pull: %v", err)
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Fatalf("grantee pulled %q, want %q", got, content)
		}

		// A grant is read-only: every mutation stays owner-scoped and answers 404,
		// indistinguishable from no access at all.
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.SetVisibility(id, api.SetVisibilityRequest{Visibility: api.Public}); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("grantee SetVisibility: got %v, want ErrNotFound", err)
		}
		if err := cl.DeleteResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("grantee DeleteResource: got %v, want ErrNotFound", err)
		}
		if err := cl.CreateGrant(id, api.CreateGrantRequest{GranteeHandle: "mallory", WrappedKey: []byte("x")}); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("grantee CreateGrant: got %v, want ErrNotFound", err)
		}
	})

	if err := runShareRevoke(id, "bob@example.com"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	asProfile("bob", func() {
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.GetResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("revoked grantee GetResource: got %v, want ErrNotFound", err)
		}
		items, err := cl.ListShares()
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 0 {
			t.Fatalf("revoked grantee still lists %d shares", len(items))
		}
	})

	// Revoking a second time reports the missing grant instead of succeeding.
	if err := runShareRevoke(id, "bob@example.com"); err == nil || !strings.Contains(err.Error(), "no grant") {
		t.Fatalf("second revoke: got %v, want a no-grant error", err)
	}
}

// TestGrantFolderCloneRevokeRewrap covers the folder path: a grantee clones and
// subpath-pulls a chunked folder read-only, object reads stay scoped to the granted
// resource, and revoking one grantee rotates the key while re-wrapping the rest.
func TestGrantFolderCloneRevokeRewrap(t *testing.T) {
	h := newE2E(t)
	id, origin := pushSharedFolder(t, h)

	// A second private folder with different content: its objects must not be
	// reachable through the granted folder's object endpoint.
	other := t.TempDir()
	h.init(other)
	writeTree(t, other, "other/secret.txt", "TOP SECRET NEIGHBOR")
	h.sync(other)
	foreignRoot := ownerTreeRootID(t, h.folderID(other))

	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	if err := runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("share --with bob: %v", err)
	}
	if err := runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share --with carol: %v", err)
	}

	cloneAndCheck := func(profile string) {
		dest := filepath.Join(t.TempDir(), "clone")
		asProfile(profile, func() {
			if err := runClone("aqt://"+id, dest, false, ""); err != nil {
				t.Fatalf("%s clone: %v", profile, err)
			}
		})
		for _, rel := range []string{"docs/readme.txt", "data/big.bin"} {
			want, err := os.ReadFile(filepath.Join(origin, rel))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dest, rel))
			if err != nil {
				t.Fatalf("%s clone missing %s: %v", profile, rel, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s clone: %s differs from origin", profile, rel)
			}
		}
		if _, err := os.Stat(filepath.Join(dest, ".aqt")); err == nil {
			t.Fatalf("%s clone wrote tracking state; a granted clone is read-only", profile)
		}
	}
	cloneAndCheck("bob")

	asProfile("bob", func() {
		// Subpath pull through the grant.
		dest := filepath.Join(t.TempDir(), "readme.txt")
		if err := runPull("aqt://"+id+"/docs/readme.txt", dest, "", false, false); err != nil {
			t.Fatalf("grantee subpath pull: %v", err)
		}
		want, _ := os.ReadFile(filepath.Join(origin, "docs/readme.txt"))
		got, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("grantee subpath pull content mismatch (err=%v)", err)
		}

		// Pack-neighbor isolation: an object of the owner's other resource is
		// refused wholesale through the granted resource's object endpoint.
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.ResourceObjects(id, []string{foreignRoot}); err == nil {
			t.Fatal("granted object endpoint served a neighbor resource's object")
		}
	})

	if err := runShareRevoke(id, "carol@example.com"); err != nil {
		t.Fatalf("revoke carol: %v", err)
	}

	asProfile("carol", func() {
		cl, _, err := authedClient()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.GetResource(id); !errors.Is(err, client.ErrNotFound) {
			t.Fatalf("revoked carol GetResource: got %v, want ErrNotFound", err)
		}
	})

	// The rotation re-wrapped bob's grant, so he keeps working access.
	cloneAndCheck("bob")
}

// TestAccountKeysDecoy pins the existence-oracle rule: an unknown email answers with
// a deterministic, correctly self-signed keyset, indistinguishable in shape from a
// real account's.
func TestAccountKeysDecoy(t *testing.T) {
	h := newE2E(t)
	grantSignup(t, h, "real@example.com", "real", "real horse battery staple")
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}

	ghost1, err := cl.AccountKeys("ghost@example.com")
	if err != nil {
		t.Fatalf("decoy lookup: %v", err)
	}
	ghost2, err := cl.AccountKeys("ghost@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ghost1.Handle != ghost2.Handle || !bytes.Equal(ghost1.EncPublicKey, ghost2.EncPublicKey) {
		t.Fatal("decoy keys are not deterministic across lookups")
	}
	real, err := cl.AccountKeys("real@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string]api.AccountKeysResponse{"decoy": ghost1, "real": real} {
		if len(keys.EncPublicKey) != crypto.EncPublicKeySize ||
			len(keys.PublicKey) != ed25519.PublicKeySize ||
			!crypto.VerifyEncKey(keys.PublicKey, keys.EncPublicKey, keys.EncKeySig) {
			t.Fatalf("%s keyset shape/signature invalid", name)
		}
	}
	if ghost1.Handle == real.Handle || bytes.Equal(ghost1.EncPublicKey, real.EncPublicKey) {
		t.Fatal("decoy collided with a real account")
	}
	// An account that never published an enc key gets the decoy too — the lookup
	// must not reveal that the account exists but predates grants.
	legacyKdf := cryptotest.KdfParams(t)
	legacyMK, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	legacyUK, err := crypto.DeriveUnlockKey("legacy horse battery staple", legacyKdf)
	if err != nil {
		t.Fatal(err)
	}
	legacyRoot, err := crypto.WrapRoot(legacyMK, legacyUK)
	if err != nil {
		t.Fatal(err)
	}
	bootCl, err := client.New(h.url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootCl.CreateAccount(api.CreateAccountRequest{
		Email:        "legacy@example.com",
		Kdf:          legacyKdf,
		PublicKey:    crypto.DeriveSigningKey(legacyMK).Public().(ed25519.PublicKey),
		WrappedRoot:  legacyRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(legacyUK),
		DeviceName:   "legacy",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := cl.AccountKeys("legacy@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.VerifyEncKey(got.PublicKey, got.EncPublicKey, got.EncKeySig) {
		t.Fatal("legacy-account decoy is not self-consistent")
	}
}

// Revocation rotates the content key before it deletes the grant, so a rotation that
// fails leaves a state the same command can retry out of. The old order deleted first:
// a rotation that then failed left the revoked account holding a working key, and the
// re-run its own error message told you to make hit the "no grant for ..." early return
// and stopped — so forward secrecy stayed broken with no way back.
func TestRevokeRetriesAfterFailedRotation(t *testing.T) {
	var failRotation atomic.Bool
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if failRotation.Load() && r.Method == http.MethodPut && r.URL.Path == "/v1/resources" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pass(w, r)
	})
	id := pushSecretFile(t, "revoke-retry.txt", "rotate me")
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	if err := runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share --with: %v", err)
	}
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}

	failRotation.Store(true)
	err = runShareRevoke(id, "carol@example.com")
	if err == nil {
		t.Fatal("revoke reported success while the key rotation was failing")
	}
	// The message must not falsely assert an outcome (the atomic PUT's fate is unknown
	// under a lost response) and must point at a recovery that reconciles survivors.
	if !strings.Contains(err.Error(), "may not have taken effect") || !strings.Contains(err.Error(), "aqt unshare") {
		t.Fatalf("revoke error = %v, want it to admit the uncertain outcome and point at `aqt unshare`", err)
	}
	// The grant is still there: the retry has something left to find, and the revoked
	// account's access is unchanged rather than half-removed.
	grants, err := cl.ListGrants(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("grants after the failed revoke = %d, want 1 (the grant must survive a failed rotation)", len(grants))
	}

	// The recovery the error points at actually works.
	failRotation.Store(false)
	if err := runShareRevoke(id, "carol@example.com"); err != nil {
		t.Fatalf("re-run after a failed rotation: %v", err)
	}
	grants, err = cl.ListGrants(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("grants after a successful revoke = %d, want 0", len(grants))
	}
}

// Sharing with someone who has not registered yet pins the decoy the server returns for
// an unknown email — it is self-signed and indistinguishable from a real key on purpose,
// or the lookup would become an account-existence oracle. The grant is accepted and opens
// for nobody, and once they do register their honest key mismatches the pin, so every
// later share fails as if the server were substituting keys. `aqt contacts rm` is the
// way out, and the mismatch error has to say so.
func TestShareBeforeRegistrationPinsDecoyAndRecovers(t *testing.T) {
	h := newE2E(t)
	const (
		email   = "dave@example.com"
		content = "shared too early"
	)
	id := pushSecretFile(t, "early.txt", content)

	// Dave has no account yet: this pins a placeholder.
	if err := runShareWith(id, email); err != nil {
		t.Fatalf("share --with an unregistered email: %v", err)
	}
	grantSignup(t, h, email, "dave", "dave horse battery staple")

	err := runShareWith(id, email)
	if err == nil {
		t.Fatal("re-share after registration should refuse: the real key cannot match the pinned decoy")
	}
	if !strings.Contains(err.Error(), "contacts rm") {
		t.Fatalf("mismatch error = %v, want it to point at `aqt contacts rm`", err)
	}

	cmd := contactsCmd()
	cmd.SetArgs([]string{"rm", email})
	captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("contacts rm: %v", err)
		}
	})

	// With the placeholder dropped, the share re-pins Dave's real key and reaches him.
	if err := runShareWith(id, email); err != nil {
		t.Fatalf("re-share after `aqt contacts rm`: %v", err)
	}
	asProfile("dave", func() {
		dest := filepath.Join(t.TempDir(), "out.txt")
		if err := runPull("aqt://"+id, dest, "", false, false); err != nil {
			t.Fatalf("grantee pull after recovery: %v", err)
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Fatalf("grantee pulled %q, want %q", got, content)
		}
	})
}

// Revocation rotates the key and re-wraps the surviving grantees, and it must not
// re-wrap the revoked one — even if a hostile server ignores the delete and keeps
// listing them. Otherwise the re-wrap hands that server a wrap of the NEW key for the
// revoked account, undoing the rotation the revoke just performed. The proxy here
// injects the revoked grantee back into every grant listing to force the issue.
func TestRevokeDoesNotRewrapRevokedGranteeAgainstHostileServer(t *testing.T) {
	var (
		revoked         atomic.Value // string: the handle a hostile server keeps listing
		recording       atomic.Bool  // gate CreateGrant recording to the revoke, past the setup shares
		createGrantsFor sync.Map     // handle -> true: CreateGrant POSTs seen while recording
	)

	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/grants"):
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var req api.CreateGrantRequest
			if recording.Load() && json.Unmarshal(raw, &req) == nil {
				createGrantsFor.Store(req.GranteeHandle, true)
			}
			pass(w, r)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/grants"):
			rec := httptest.NewRecorder()
			pass(rec, r)
			handle, _ := revoked.Load().(string)
			var body map[string]any
			if handle == "" || json.Unmarshal(rec.Body.Bytes(), &body) != nil {
				copyRecorded(w, rec)
				return
			}
			grants, _ := body["grants"].([]any)
			present := false
			for _, g := range grants {
				if m, ok := g.(map[string]any); ok && m["granteeHandle"] == handle {
					present = true
				}
			}
			if !present {
				body["grants"] = append(grants, map[string]any{"granteeHandle": handle, "createdAt": 1})
			}
			replaceRecorded(w, rec, body)
		default:
			pass(w, r)
		}
	})

	id := pushSecretFile(t, "hostile.txt", "rotate away")
	grantSignup(t, h, "carol@example.com", "carol", "carol horse battery staple")
	grantSignup(t, h, "dave@example.com", "dave", "dave horse battery staple")
	if err := runShareWith(id, "carol@example.com"); err != nil {
		t.Fatalf("share --with carol: %v", err)
	}
	if err := runShareWith(id, "dave@example.com"); err != nil {
		t.Fatalf("share --with dave: %v", err)
	}

	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	carolKeys, err := fetchAccountKeys(cl, "carol@example.com")
	if err != nil {
		t.Fatal(err)
	}
	daveKeys, err := fetchAccountKeys(cl, "dave@example.com")
	if err != nil {
		t.Fatal(err)
	}
	revoked.Store(carolKeys.Handle) // from here the "server" keeps listing carol
	recording.Store(true)           // and from here we watch which re-wraps the client emits

	if err := runShareRevoke(id, "carol@example.com"); err != nil {
		t.Fatalf("revoke carol: %v", err)
	}

	// Dave survives, so the re-wrap must have re-granted him the new key: proof the
	// re-wrap actually ran and iterated the (injected) list.
	if _, ok := createGrantsFor.Load(daveKeys.Handle); !ok {
		t.Fatal("surviving grantee dave was not re-wrapped onto the new key")
	}
	// Carol was revoked. Even though the server kept listing her, the re-wrap must not
	// have handed the server a wrap of the new key for her handle. Recording started
	// after the setup shares, so any hit here is a re-wrap of the revoked account.
	if _, ok := createGrantsFor.Load(carolKeys.Handle); ok {
		t.Fatal("revoked grantee carol was re-wrapped onto the new key against a hostile server")
	}
}

// replaceRecorded forwards a proxied response with a rewritten JSON body, which is
// how a test plays a hostile server. The recorded Content-Length is left behind
// because the rewrite changes the length.
func replaceRecorded(w http.ResponseWriter, rec *httptest.ResponseRecorder, body any) {
	out, _ := json.Marshal(body)
	for k := range rec.Header() {
		if k != "Content-Length" {
			w.Header().Set(k, rec.Header().Get(k))
		}
	}
	w.WriteHeader(rec.Code)
	w.Write(out)
}

func copyRecorded(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k := range rec.Header() {
		w.Header().Set(k, rec.Header().Get(k))
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}
