// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// shareResignCmd shares again, in one go, every grant this account has not signed over
// its resource's current key. Those are the shares made before grants were signed, and
// each otherwise takes its own `aqt share <id> --with <email>`.
//
// The server chooses which grants it lists, and an unsigned row may be one it added to
// have a resource handed to a pinned contact. Signing what it lists unseen would undo
// what the signature is for, so the command shows every share it would make and only a
// person can accept them: there is no --yes.
func (app *application) shareResignCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resign",
		Short: "Share again every grant made before grants were signed, after showing them",
		Long: "Lists every grant on your resources that carries no signature of yours over the\n" +
			"resource's current key, asks, and shares each one again: wrapped to the keys you\n" +
			"pinned for the grantee and signed. Read the list before accepting it. The server\n" +
			"chooses what it lists, so a share you never made does not belong on it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.json {
				return errors.New("`aqt share resign` asks before it shares anything and has no --json form")
			}
			return app.runShareResign()
		},
	}
}

// unsignedShare is one grant `aqt share resign` can share again: the resource, by id
// and decrypted name, and the pinned contact the grant names.
type unsignedShare struct {
	resource grantedResource
	contact  identity.Contact
}

// confirmResign asks before the listed shares are made again; cliutil.ErrNotConfirmable
// means no terminal can answer. A variable so tests can answer for one.
var confirmResign = func(prompt string) error { return confirmDestructive(prompt, false) }

func (app *application) runShareResign() error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	shares, left, err := unsignedShares(cl, prof, mk)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		fmt.Fprintln(os.Stderr, "these unsigned grants cannot be shared again from this device:")
		for _, g := range left {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", g.grantee, g.reason)
		}
	}
	if len(shares) == 0 {
		fmt.Println("no unsigned grants to share again")
		return nil
	}
	var list strings.Builder
	for _, s := range shares {
		fmt.Fprintf(&list, "  aqt://%s  %q  with %s\n", s.resource.id, s.resource.name,
			pinnedLabel(s.contact.Email, crypto.KeyFingerprint(s.contact.PublicKey), s.contact.Verified))
	}
	prompt := fmt.Sprintf("the server lists these grants without a signature of yours:\n%s"+
		"the server chooses this list, so check that you made each of these shares.\nShare all %d again? [y/N] ", list.String(), len(shares))
	switch err := confirmResign(prompt); {
	case errors.Is(err, cliutil.ErrNotConfirmable):
		return fmt.Errorf("`aqt share resign` shares again what the server lists, so it only runs on a terminal where you can read that list first; %d grant(s) are waiting", len(shares))
	case errors.Is(err, cliutil.ErrAborted):
		return errors.New("shared nothing")
	case err != nil:
		return err
	}
	var failed error
	done := 0
	for _, s := range shares {
		if err := regrantOwned(cl, prof, mk, s.resource.id, s.contact); err != nil {
			failed = errors.Join(failed, fmt.Errorf("share aqt://%s with %s: %w", s.resource.id, s.contact.Email, err))
			continue
		}
		done++
	}
	fmt.Printf("shared %d of %d grant(s) again\n", done, len(shares))
	return failed
}

// unsignedShares walks the caller's resources for grants it has not signed over the
// current key. A grant is shareable again when exactly one pin holds its handle, this
// device has not revoked it, and the server still publishes the pinned keys; every
// other one comes back in left with why.
func unsignedShares(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey) ([]unsignedShare, []unfollowedGrant, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, nil, err
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return nil, nil, err
	}
	revoked, err := identity.LoadRevokedGrants(prof.Name)
	if err != nil {
		return nil, nil, err
	}
	byHandle := map[string][]identity.Contact{}
	for _, c := range pins {
		byHandle[c.Handle] = append(byHandle[c.Handle], c)
	}
	self := crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey)
	confirmed := map[string]identity.Contact{}
	var (
		shares []unsignedShare
		left   []unfollowedGrant
	)
	for _, it := range items {
		if it.GrantCount == 0 || it.Reclaimed || it.WrappedKey == nil {
			continue
		}
		grants, err := cl.ListGrants(it.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("list grants of %s: %w", it.ID, err)
		}
		ck, err := crypto.UnwrapKey(*it.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return nil, nil, fmt.Errorf("open the key of %s: %w", it.ID, err)
		}
		res := grantedResource{id: it.ID, name: "(unreadable)"}
		if meta, err := decodeMeta(it.EncryptedMeta, ck, it.ID); err == nil {
			res.name = meta.Name
		}
		for _, g := range grants {
			if crypto.VerifyGrant(self, g.Signature, ck, it.ID, prof.OwnerHandle, g.GranteeHandle) {
				continue
			}
			where := fmt.Sprintf("%s on aqt://%s %q", foreignText(g.GranteeHandle), it.ID, res.name)
			holders := byHandle[g.GranteeHandle]
			switch {
			case slices.Contains(revoked, identity.RevokedGrant{ResourceID: it.ID, GranteeHandle: g.GranteeHandle}):
				left = append(left, unfollowedGrant{where, "revoked from this device"})
				continue
			case len(holders) == 0:
				left = append(left, unfollowedGrant{where, "not pinned on this device; share it again by email with `aqt share " + it.ID + " --with <email>`"})
				continue
			case len(holders) > 1:
				left = append(left, unfollowedGrant{where, "more than one pinned contact holds this account handle; unpin the wrong one with `aqt contacts rm <email>`"})
				continue
			}
			contact, ok := confirmed[g.GranteeHandle]
			if !ok {
				if contact, err = confirmPinnedKeys(cl, prof.Name, holders[0]); err != nil {
					left = append(left, unfollowedGrant{where, err.Error()})
					continue
				}
				confirmed[g.GranteeHandle] = contact
			}
			shares = append(shares, unsignedShare{resource: res, contact: contact})
		}
		ck.Wipe()
	}
	return shares, left, nil
}
