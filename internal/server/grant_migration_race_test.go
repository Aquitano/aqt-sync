// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestKeyMigrationRefusesChangedIncomingGrant(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"enc-key", "root-key"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			aliceToken, aliceMK := h.signup("alice@example.com", "alice passphrase here")
			bobToken, bobMK := h.signup("bob@example.com", "bob passphrase here")
			alice, bob := h.handleOf("alice@example.com"), h.handleOf("bob@example.com")
			res, code := h.putSized(aliceToken, aliceMK, "", 16)
			if code != http.StatusCreated {
				t.Fatal(code)
			}
			wrapToBob := func(ck crypto.ContentKey) []byte {
				t.Helper()
				if operation == "enc-key" {
					return legacyMigrationWrap(t, ck, bobMK, res.ID, alice, bob)
				}
				wrap, err := crypto.WrapGrant(ck, crypto.DeriveEncKey(bobMK).Public(), res.ID, alice, bob)
				if err != nil {
					t.Fatal(err)
				}
				return wrap
			}
			contentKey := func() crypto.ContentKey {
				t.Helper()
				stored, err := h.store.GetResource(res.ID, alice)
				if err != nil {
					t.Fatal(err)
				}
				ck, err := crypto.UnwrapKey(*stored.WrappedKey, [crypto.KeySize]byte(aliceMK))
				if err != nil {
					t.Fatal(err)
				}
				return ck
			}
			oldCK := contentKey()
			oldWrap := wrapToBob(oldCK)
			if err := h.store.PutGrant(alice, res.ID, bob, oldWrap, nil); err != nil {
				t.Fatal(err)
			}
			if operation == "enc-key" {
				if _, err := h.store.db.Exec(`UPDATE accounts SET enc_public_key=? WHERE owner_handle=?`, make([]byte, 32), bob); err != nil {
					t.Fatal(err)
				}
			}
			before, err := h.store.AccountByEmail("bob@example.com")
			if err != nil {
				t.Fatal(err)
			}
			_, beforeIdentity, _, beforeEpoch, err := h.store.AccountForAuth("bob@example.com")
			if err != nil {
				t.Fatal(err)
			}
			var beforeEnc []byte
			if err := h.store.rdb.QueryRow(`SELECT enc_public_key FROM accounts WHERE owner_handle=?`, bob).Scan(&beforeEnc); err != nil {
				t.Fatal(err)
			}
			newRoot := bobMK
			if operation == "root-key" {
				newRoot, err = crypto.GenerateMasterKey()
				if err != nil {
					t.Fatal(err)
				}
			}
			newEnc := crypto.DeriveEncKey(newRoot).Public()
			migrated, err := crypto.WrapGrant(oldCK, newEnc, res.ID, alice, bob)
			if err != nil {
				t.Fatal(err)
			}
			grants := []api.GrantKeyMigration{{ResourceID: res.ID, OwnerHandle: alice, WrappedKey: migrated, ExpectedWrappedKey: oldWrap}}

			// The owner rotates the resource's content key after Bob prepares his request.
			if _, code := h.putSized(aliceToken, aliceMK, res.ID, 32); code != http.StatusOK {
				t.Fatal(code)
			}
			currentCK := contentKey()
			currentWrap := wrapToBob(currentCK)
			if err := h.store.PutGrant(alice, res.ID, bob, currentWrap, nil); err != nil {
				t.Fatal(err)
			}
			uk, err := crypto.DeriveUnlockKey("bob passphrase here", before.Kdf)
			if err != nil {
				t.Fatal(err)
			}
			defer uk.Wipe()
			rootWrap, err := crypto.WrapRoot(newRoot, uk)
			if err != nil {
				t.Fatal(err)
			}
			signing := crypto.DeriveSigningKey(newRoot)
			sig := crypto.SignEncKey(signing, newEnc)
			request := func() any {
				if operation == "enc-key" {
					return api.EncKeyUpgradeRequest{EncPublicKey: newEnc, EncKeySig: sig, IncomingGrants: grants}
				}
				return api.RootKeyRotationRequest{
					Kdf: before.Kdf, WrappedRoot: rootWrap, OldAuthVerifier: crypto.DeriveAuthVerifier(uk),
					NewAuthVerifier: crypto.DeriveAuthVerifier(uk), ExpectedEpoch: beforeEpoch,
					PublicKey: signing.Public().(ed25519.PublicKey), EncPublicKey: newEnc, EncKeySig: sig,
					IncomingGrants: grants,
				}
			}
			rec := h.doAt(api.ClientCapability, http.MethodPut, "/v1/account/"+operation, bobToken, request())
			if rec.Code != http.StatusConflict {
				t.Fatalf("stale migration = %d %s, want 409 without overwriting the newer grant", rec.Code, rec.Body)
			}
			_, afterIdentity, _, afterEpoch, err := h.store.AccountForAuth("bob@example.com")
			if err != nil {
				t.Fatal(err)
			}
			var afterEnc []byte
			if err := h.store.rdb.QueryRow(`SELECT enc_public_key FROM accounts WHERE owner_handle=?`, bob).Scan(&afterEnc); err != nil {
				t.Fatal(err)
			}
			if afterEpoch != beforeEpoch || !bytes.Equal(afterIdentity, beforeIdentity) || !bytes.Equal(afterEnc, beforeEnc) {
				t.Fatal("a refused migration changed the account identity")
			}
			stored, ok, err := h.store.grantWrappedKey(res.ID, bob)
			if err != nil || !ok || !bytes.Equal(stored, currentWrap) {
				t.Fatalf("a refused migration changed the current grant: ok=%v err=%v", ok, err)
			}

			grants[0].ExpectedWrappedKey = currentWrap
			grants[0].WrappedKey, err = crypto.WrapGrant(currentCK, newEnc, res.ID, alice, bob)
			if err != nil {
				t.Fatal(err)
			}
			rec = h.doAt(api.ClientCapability, http.MethodPut, "/v1/account/"+operation, bobToken, request())
			if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
				t.Fatalf("fresh migration = %d %s", rec.Code, rec.Body)
			}
			stored, ok, err = h.store.grantWrappedKey(res.ID, bob)
			if err != nil || !ok {
				t.Fatalf("migrated grant: ok=%v err=%v", ok, err)
			}
			opened, err := crypto.UnwrapGrant(stored, newRoot, res.ID, alice, bob)
			if err != nil || opened != currentCK {
				t.Fatalf("fresh migration cannot recover the current content key: %v", err)
			}
			if operation == "root-key" {
				// An owner that looked up Bob before the rotation must not replace his
				// migrated grant with a new wrap to the discarded encryption key.
				rec = h.doAt(api.ClientCapability, http.MethodPost, "/v1/resources/"+res.ID+"/grants", aliceToken, api.CreateGrantRequest{
					GranteeHandle: bob, WrappedKey: currentWrap,
					GranteeEmail: "bob@example.com", GranteeEncPublicKey: beforeEnc,
				})
				if rec.Code != http.StatusConflict {
					t.Fatalf("grant to the discarded enc key = %d %s, want 409", rec.Code, rec.Body)
				}
				stored, ok, err = h.store.grantWrappedKey(res.ID, bob)
				if err != nil || !ok || !bytes.Equal(stored, grants[0].WrappedKey) {
					t.Fatalf("a stale sender replaced the migrated grant: ok=%v err=%v", ok, err)
				}
			}
		})
	}
}

func legacyMigrationWrap(t *testing.T, ck crypto.ContentKey, mk crypto.MasterKey, resourceID, owner, grantee string) []byte {
	t.Helper()
	seed, err := hkdf.Key(sha256.New, mk[:], nil, "aqt-share-x25519-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := hpke.DHKEM(ecdh.X25519()).DeriveKeyPair(seed)
	if err != nil {
		t.Fatal(err)
	}
	var info bytes.Buffer
	info.WriteString("aqt-grant-v1")
	for _, field := range []string{resourceID, owner, grantee} {
		if err := binary.Write(&info, binary.BigEndian, uint16(len(field))); err != nil {
			t.Fatal(err)
		}
		info.WriteString(field)
	}
	enc, sender, err := hpke.NewSender(priv.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sender.Seal([]byte("aqt-grantwrap-v1"), ck[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, sealed...)
}

func TestGrantMigrationAllowsNonGrowingOwnerWrites(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	aliceToken, aliceMK := h.signup("quota-owner@example.com", "alice passphrase here")
	bobToken, bobMK := h.signup("quota-recipient@example.com", "bob passphrase here")
	alice, bob := h.handleOf("quota-owner@example.com"), h.handleOf("quota-recipient@example.com")
	res, code := h.putSized(aliceToken, aliceMK, "", 64)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	stored, err := h.store.GetResource(res.ID, alice)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*stored.WrappedKey, [crypto.KeySize]byte(aliceMK))
	if err != nil {
		t.Fatal(err)
	}
	oldWrap := legacyMigrationWrap(t, ck, bobMK, res.ID, alice, bob)
	if err := h.store.PutGrant(alice, res.ID, bob, oldWrap, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.db.Exec(`UPDATE accounts SET enc_public_key=? WHERE owner_handle=?`, make([]byte, 32), bob); err != nil {
		t.Fatal(err)
	}
	before, err := h.store.AccountUsage(alice)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.cfg.QuotaBytes = before.StorageBytes + 512
	h.srv.cfg.MaxResources = 1
	enc := crypto.DeriveEncKey(bobMK).Public()
	newWrap, err := crypto.WrapGrant(ck, enc, res.ID, alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	req := api.EncKeyUpgradeRequest{EncPublicKey: enc, EncKeySig: crypto.SignEncKey(crypto.DeriveSigningKey(bobMK), enc), IncomingGrants: []api.GrantKeyMigration{{ResourceID: res.ID, OwnerHandle: alice, WrappedKey: newWrap, ExpectedWrappedKey: oldWrap}}}
	if code := h.do(http.MethodPut, "/v1/account/enc-key", bobToken, req, nil); code != http.StatusNoContent {
		t.Fatalf("migration %d", code)
	}
	after, err := h.store.AccountUsage(alice)
	if err != nil {
		t.Fatal(err)
	}
	if after.StorageBytes <= h.srv.cfg.QuotaBytes {
		t.Fatal("migration did not exceed the owner quota")
	}
	var limit *LimitExceededError
	if err := h.srv.checkAccountLimit(alice, "resources", 0); !errors.As(err, &limit) || limit.Kind != "resources" {
		t.Fatalf("zero-byte row addition bypassed the resource cap: %v", err)
	}
	if _, code := h.putSized(aliceToken, aliceMK, res.ID, 65); code != http.StatusInsufficientStorage {
		t.Fatalf("growing update = %d, want 507", code)
	}
	if _, code := h.putSized(aliceToken, aliceMK, "", 1); code != http.StatusInsufficientStorage {
		t.Fatalf("new resource = %d, want 507", code)
	}
	if _, code := h.putSized(aliceToken, aliceMK, res.ID, 64); code != http.StatusOK {
		t.Errorf("same-size content-key rewrite after recipient migration = %d, want 200", code)
	}
	if _, code := h.putSized(aliceToken, aliceMK, res.ID, 8); code != http.StatusOK {
		t.Errorf("shrinking resource after recipient migration = %d, want 200", code)
	}
}
