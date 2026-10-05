// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func TestGrantMigrationAllowsOwnerKeyRotationOverQuota(t *testing.T) {
	for _, operation := range []string{"unshare", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			app := &application{ctx: context.Background()}
			h := app.newE2E(t)
			id := app.pushSecretFile(t, "legacy.txt", "secret content")
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
			bobMK, err := crypto.GenerateMasterKey()
			if err != nil {
				t.Fatal(err)
			}
			defer bobMK.Wipe()
			kdf := cryptotest.KdfParams(t)
			uk, err := crypto.DeriveUnlockKey("bob passphrase here", kdf)
			if err != nil {
				t.Fatal(err)
			}
			defer uk.Wipe()
			wrappedRoot, err := crypto.WrapRoot(bobMK, uk)
			if err != nil {
				t.Fatal(err)
			}
			signing := crypto.DeriveSigningKey(bobMK)
			oldPub := legacyEncKey(t, bobMK).PublicKey()
			bob, err := h.store.CreateAccount("bob@example.com", kdf, signing.Public().(ed25519.PublicKey), wrappedRoot, crypto.DeriveAuthVerifier(uk), oldPub.Bytes(), crypto.SignEncKey(signing, oldPub.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			_, bobToken, err := h.store.CreateDevice(bob.OwnerHandle, "bob", 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			oldWrap := legacyWrap(t, oldPub, ck, id, alice.OwnerHandle, bob.OwnerHandle)
			if err := h.store.PutGrant(alice.OwnerHandle, id, bob.OwnerHandle, oldWrap, nil); err != nil {
				t.Fatal(err)
			}
			if err := identity.SaveContacts(alice.Name, map[string]identity.Contact{bob.Email: {
				Email: bob.Email, Handle: bob.OwnerHandle, PublicKey: signing.Public().(ed25519.PublicKey),
				EncPublicKey: oldPub.Bytes(), PinnedAt: time.Now().Unix(),
			}}); err != nil {
				t.Fatal(err)
			}
			before, err := h.store.AccountUsage(alice.OwnerHandle)
			if err != nil {
				t.Fatal(err)
			}
			quota := before.StorageBytes + 512
			if err := h.store.SetAccountQuota(alice.OwnerHandle, &quota); err != nil {
				t.Fatal(err)
			}
			bobCl, err := client.New(h.url, bobToken)
			if err != nil {
				t.Fatal(err)
			}
			if err := upgradeEncKey(bobCl, bob.Email, bob.OwnerHandle, bobMK); err != nil {
				t.Fatalf("upgrade: %v", err)
			}
			after, err := h.store.AccountUsage(alice.OwnerHandle)
			if err != nil {
				t.Fatal(err)
			}
			if after.StorageBytes <= quota {
				t.Fatal("migration did not exceed the owner quota")
			}
			if operation == "unshare" {
				err = app.runPrivate(id)
			} else {
				err = app.runShareRevoke(id, bob.Email)
			}
			if err != nil {
				t.Fatalf("%s after recipient migration: %v", operation, err)
			}
			updated, err := cl.GetResource(id)
			if err != nil {
				t.Fatal(err)
			}
			newCK, err := crypto.UnwrapKey(*updated.WrappedKey, [crypto.KeySize]byte(aliceMK))
			if err != nil {
				t.Fatal(err)
			}
			if newCK == ck {
				t.Fatal("owner operation did not rotate the resource content key")
			}
			grants, err := cl.ListGrants(id)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "revoke" {
				if len(grants) != 0 {
					t.Fatalf("revoked grant remains: %v", grants)
				}
			} else {
				shared, err := bobCl.GetResource(id)
				if err != nil {
					t.Fatal(err)
				}
				granteeCK, err := crypto.UnwrapGrant(shared.GrantKey, bobMK, id, alice.OwnerHandle, bob.OwnerHandle)
				if err != nil || granteeCK != newCK {
					t.Fatalf("remaining grant does not open the rotated key: %v", err)
				}
			}
		})
	}
}
