package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// grantSignup registers a second account with a published enc key under its own
// profile name, so a test acts as several users by flipping flagProfile.
func grantSignup(t *testing.T, h *e2eHarness, email, profile, pass string) {
	t.Helper()
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
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
		if _, err := cl.SetVisibility(id, api.Public, 0, 0); !errors.Is(err, client.ErrNotFound) {
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
	legacyKdf, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
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
