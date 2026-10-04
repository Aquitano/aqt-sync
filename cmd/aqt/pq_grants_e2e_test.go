// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// legacyEncKey re-derives an account's pre-X-Wing grant key the way releases before
// capability 5 did, independently of the crypto package, so the test holds that
// package to the format already stored on servers rather than to itself.
func legacyEncKey(t *testing.T, mk crypto.MasterKey) hpke.PrivateKey {
	t.Helper()
	seed, err := hkdf.Key(sha256.New, mk[:], nil, "aqt-share-x25519-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// legacyWrap seals ck to a pre-X-Wing grant key with the grant binding of that
// format: DHKEM(X25519), and info naming (resource, owner, grantee).
func legacyWrap(t *testing.T, pub hpke.PublicKey, ck crypto.ContentKey, resourceID, owner, grantee string) []byte {
	t.Helper()
	info := []byte("aqt-grant-v1")
	for _, f := range []string{resourceID, owner, grantee} {
		info = binary.BigEndian.AppendUint16(info, uint16(len(f)))
		info = append(info, f...)
	}
	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal([]byte("aqt-grantwrap-v1"), ck[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, ct...)
}

// An account that joined before X-Wing grants keeps its shares across the move: its
// next `aqt login`, on a device it already has or a new one, publishes the X-Wing key
// and re-wraps the X25519 grant it holds, it can still read what was shared with it,
// and the sharer's pin follows the new key instead of failing as a substitution.
func TestLoginMovesPreXWingSharesToXWing(t *testing.T) {
	for _, newDevice := range []bool{false, true} {
		t.Run(map[bool]string{false: "existing device", true: "new device"}[newDevice], func(t *testing.T) {
			loginMovesPreXWingShares(t, newDevice)
		})
	}
}

func loginMovesPreXWingShares(t *testing.T, newDevice bool) {
	t.Helper()
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	const content = "shared before post-quantum grants"
	id := app.pushSecretFile(t, "legacy.txt", content)

	cl, alice, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	aliceMK, ok := identity.LoadSession(alice.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(aliceMK))
	if err != nil {
		t.Fatal(err)
	}

	// Bob as a pre-X-Wing server stored him: an X25519 key, an X25519 grant, and
	// alice's pin of both keys.
	const bobPass = "bob horse battery staple"
	kdf := cryptotest.KdfParams(t)
	bobMK, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(bobPass, kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(bobMK, uk)
	if err != nil {
		t.Fatal(err)
	}
	signing := crypto.DeriveSigningKey(bobMK)
	legacy := legacyEncKey(t, bobMK)
	legacyPub := legacy.PublicKey().Bytes()
	bob, err := h.store.CreateAccount("bob@example.com", kdf, signing.Public().(ed25519.PublicKey), wrappedRoot,
		crypto.DeriveAuthVerifier(uk), legacyPub, crypto.SignEncKey(signing, legacyPub))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.PutGrant(alice.OwnerHandle, id, bob.OwnerHandle, legacyWrap(t, legacy.PublicKey(), ck, id, alice.OwnerHandle, bob.OwnerHandle), nil); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveContacts(alice.Name, map[string]identity.Contact{"bob@example.com": {
		Email: "bob@example.com", Handle: bob.OwnerHandle, PublicKey: signing.Public().(ed25519.PublicKey),
		EncPublicKey: legacyPub, PinnedAt: time.Now().Unix(),
	}}); err != nil {
		t.Fatal(err)
	}
	if newDevice {
		app.server = h.url
	} else {
		deviceID, token, err := h.store.CreateDevice(bob.OwnerHandle, "bob-laptop", 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := identity.Save(&identity.Profile{
			Name: "bob", Server: h.url, Email: "bob@example.com", OwnerHandle: bob.OwnerHandle,
			DeviceID: deviceID, Token: token, Kdf: kdf, WrappedRoot: wrappedRoot, AuthEpoch: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}

	app.asProfile("bob", func() {
		withStdin(t, bobPass+"\n")
		if err := app.runLogin("bob@example.com", time.Hour); err != nil {
			t.Fatalf("bob login: %v", err)
		}
		bobClient, _, err := app.authedClient()
		if err != nil {
			t.Fatal(err)
		}
		shares, err := bobClient.ListShares()
		if err != nil {
			t.Fatal(err)
		}
		if len(shares) != 1 || len(shares[0].WrappedKey) != crypto.GrantWrapSize {
			t.Fatalf("bob's incoming grant was not re-wrapped to X-Wing: %+v", shares)
		}
		dest := filepath.Join(t.TempDir(), "legacy.txt")
		if err := app.runPull("aqt://"+id, dest, "", false, false); err != nil {
			t.Fatalf("bob pull after the move: %v", err)
		}
		if got, err := os.ReadFile(dest); err != nil || string(got) != content {
			t.Fatalf("bob pulled %q (%v), want %q", got, err, content)
		}
	})
	app.server = ""

	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatalf("re-share to bob with his pre-X-Wing pin: %v", err)
	}
	pins, err := identity.LoadContacts(alice.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pins["bob@example.com"].EncPublicKey, crypto.DeriveEncKey(bobMK).Public()) {
		t.Fatal("alice's pin did not follow bob's X-Wing key")
	}
}

// A pin moves only to a key its own account now publishes: the same handle and
// identity key, and only away from a pre-X-Wing key. Anything else stays pinned and
// surfaces as a mismatch.
func TestCarryLegacyPinFollowsOnlyTheSameAccount(t *testing.T) {
	isolateConfigEnv(t, t.TempDir())
	id := make([]byte, ed25519.PublicKeySize)
	otherID := bytes.Repeat([]byte{1}, ed25519.PublicKeySize)
	xwing := crypto.DeriveEncKey(crypto.MasterKey{}).Public()
	legacy := identity.Contact{Email: "bob@example.com", Handle: "bob", PublicKey: id, EncPublicKey: make([]byte, 32)}
	pinnedXWing := legacy
	pinnedXWing.EncPublicKey = crypto.DeriveEncKey(crypto.MasterKey{1}).Public()
	cases := []struct {
		name    string
		pin     identity.Contact
		keys    api.AccountKeysResponse
		carried bool
	}{
		{"same account", legacy, api.AccountKeysResponse{Handle: "bob", PublicKey: id, EncPublicKey: xwing}, true},
		{"another identity key", legacy, api.AccountKeysResponse{Handle: "bob", PublicKey: otherID, EncPublicKey: xwing}, false},
		{"another handle", legacy, api.AccountKeysResponse{Handle: "decoy", PublicKey: id, EncPublicKey: xwing}, false},
		{"pin already on X-Wing", pinnedXWing, api.AccountKeysResponse{Handle: "bob", PublicKey: id, EncPublicKey: xwing}, false},
	}
	for _, c := range cases {
		got, err := carryLegacyPin(identity.DefaultProfile, c.pin, c.keys)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if carried := bytes.Equal(got.EncPublicKey, xwing); carried != c.carried {
			t.Errorf("%s: carried = %v, want %v", c.name, carried, c.carried)
		}
	}
}

// A login signs the server's challenge with the identity key that also signs the
// enc-key binding. A "challenge" that is really a binding for a key the server holds
// must never be signed, or the server could pass that key off as the account's own
// to every contact whose pin follows a binding.
func TestLoginRefusesToSignAnythingButAChallenge(t *testing.T) {
	app := &application{ctx: context.Background()}
	binding := append([]byte("aqt-enc-key-binding-v1\x00"), crypto.DeriveEncKey(crypto.MasterKey{}).Public()...)
	var signed atomic.Bool
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		switch {
		case r.URL.Path == "/v1/auth/challenge":
			rec := httptest.NewRecorder()
			pass(rec, r)
			var ch api.ChallengeResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
				t.Error(err)
			}
			ch.Nonce = binding
			replaceRecorded(w, rec, ch)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/devices":
			signed.Store(true)
			pass(w, r)
		default:
			pass(w, r)
		}
	})
	app.server = h.url
	app.asProfile("second-device", func() {
		withStdin(t, "correct horse battery staple\n")
		if err := app.runLogin("e2e@example.com", time.Hour); err == nil || !strings.Contains(err.Error(), "challenge") {
			t.Fatalf("login with a %d-byte challenge: got %v, want a refusal to sign it", len(binding), err)
		}
	})
	if signed.Load() {
		t.Fatal("a signature over the forged challenge reached the server")
	}
}

func TestRootRotationRetriesChangedIncomingGrant(t *testing.T) {
	app := &application{ctx: context.Background()}
	var replace func()
	var armed atomic.Bool
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/account/root-key" && armed.CompareAndSwap(true, false) {
			replace()
		}
		pass(w, r)
	})
	const bobPass = "bob horse battery staple"
	grantSignup(t, h, "bob@example.com", "bob", bobPass)
	const content = "incoming shares survive a retried root rotation"
	id := app.pushSecretFile(t, "rotation.txt", content)
	if err := app.runShareWith(id, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	cl, alice, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	aliceMK, err := app.unlockMaster(alice)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceMK.Wipe()
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(aliceMK))
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Wipe()
	keys, err := cl.AccountKeys("bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	freshWrap, err := crypto.WrapGrant(ck, keys.EncPublicKey, id, alice.OwnerHandle, keys.Handle)
	if err != nil {
		t.Fatal(err)
	}
	replace = func() {
		if err := h.store.PutGrant(alice.OwnerHandle, id, keys.Handle, freshWrap, nil); err != nil {
			t.Error(err)
		}
	}
	armed.Store(true)
	app.asProfile("bob", func() {
		withStdin(t, bobPass+"\n")
		if err := app.runRootKeyRotation(true); err == nil || !strings.Contains(err.Error(), "re-run") {
			t.Fatalf("stale root rotation = %v, want a retry instruction", err)
		}
		if armed.Load() {
			t.Fatal("the rotation never reached the injected grant replacement")
		}
		withStdin(t, bobPass+"\n")
		if err := app.runRootKeyRotation(true); err != nil {
			t.Fatalf("retry root rotation: %v", err)
		}
		dest := filepath.Join(t.TempDir(), "rotation.txt")
		if err := app.runPull("aqt://"+id, dest, "", false, false); err != nil {
			t.Fatalf("pull after root rotation: %v", err)
		}
		if got, err := os.ReadFile(dest); err != nil || string(got) != content {
			t.Fatalf("pulled %q (%v), want %q", got, err, content)
		}
	})
}

func TestShareWithRefusesChangedResourceKey(t *testing.T) {
	app := &application{ctx: context.Background()}
	var rotate func()
	var armed atomic.Bool
	h := app.newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if r.URL.Path == "/v1/account/keys" && armed.CompareAndSwap(true, false) {
			rotate()
		}
		pass(w, r)
	})
	grantSignup(t, h, "bob@example.com", "bob", "bob horse battery staple")
	id := app.pushSecretFile(t, "rotate-during-share.txt", "sharing must use the current content key")
	cl, prof, err := app.authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Wipe()
	rotate = func() {
		newCK, err := rotateInline(cl, id, res, ck, mk, "")
		newCK.Wipe()
		if err != nil {
			t.Error(err)
		}
	}
	armed.Store(true)
	if err := app.runShareWith(id, "bob@example.com"); !errors.Is(err, client.ErrConflict) {
		t.Fatalf("grant prepared before the resource key rotated = %v, want a conflict", err)
	}
	if armed.Load() {
		t.Fatal("sharing never reached the injected resource rotation")
	}
	grants, err := cl.ListGrants(id)
	if err != nil || len(grants) != 0 {
		t.Fatalf("stale sharing created an unreadable grant: %+v (%v)", grants, err)
	}
}
