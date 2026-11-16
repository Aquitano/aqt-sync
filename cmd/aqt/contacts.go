// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// fetchAccountKeys looks up an email's published keys and verifies the Ed25519
// self-signature over the enc key. The server answers unknown emails with a
// deterministic decoy, so a lookup never confirms account existence; a wrap to a
// decoy key simply never decrypts for anyone.
func fetchAccountKeys(cl *client.Client, email string) (api.AccountKeysResponse, error) {
	keys, err := cl.AccountKeys(email)
	if errors.Is(err, client.ErrNotFound) {
		return keys, errors.New("this server does not support account-to-account sharing (upgrade it)")
	}
	if err != nil {
		return keys, err
	}
	if len(keys.EncPublicKey) != crypto.EncPublicKeySize ||
		!crypto.VerifyEncKey(keys.PublicKey, keys.EncPublicKey, keys.EncKeySig) {
		return keys, fmt.Errorf("the server returned an invalid key binding for %s; refusing to share to it", email)
	}
	return keys, nil
}

// confirmPinnedKeys re-checks a stored pin against the server's current keys for
// that contact. Used on the re-wrap path, where the alternative — trusting the pin
// blindly — silently produces a wrap the grantee cannot open if they have rotated
// their root key since. A lookup failure is reported rather than swallowed: not
// re-wrapping leaves the grantee on the old key, which still works, whereas
// re-wrapping to a stale key does not.
//
// The comparison runs against a raw lookup, not through lookupGrantee: that one
// answers a disagreement by offering to replace the pin, a decision for a share the
// user asked for, not for a re-wrap that runs as a side effect of a revoke.
//
// It returns the pin to wrap to, which carryLegacyPin may have moved onto the
// contact's X-Wing key.
func confirmPinnedKeys(cl *client.Client, profile string, pin identity.Contact) (identity.Contact, error) {
	keys, err := fetchAccountKeys(cl, pin.Email)
	if err != nil {
		return pin, err
	}
	pin, err = carryLegacyPin(profile, pin, keys)
	if err != nil {
		return pin, err
	}
	if len(pin.EncPublicKey) != crypto.EncPublicKeySize {
		return pin, fmt.Errorf(
			"%s has not run `aqt login` since shares moved to post-quantum keys, so their grant cannot follow the new key yet; once they have, share it with them again",
			pin.Email)
	}
	if !pinMatches(pin, keys) {
		return pin, fmt.Errorf(
			"the keys published for %s no longer match the ones pinned here — most often because they rotated their account root key. "+
				"Compare fingerprints out-of-band with `aqt contacts verify %s`, then share with them again to re-pin",
			pin.Email, pin.Email)
	}
	return pin, nil
}

// carryLegacyPin moves a pin made while grants were X25519 onto the X-Wing key its
// account now publishes, so moving to post-quantum keys does not break every pin at
// once. The handle and identity key must still match the pin byte for byte, and
// fetchAccountKeys has already checked that this identity signed the new key: it is
// the same account, not a substitute. A pin that already holds an X-Wing key is
// never replaced here, so after the move enc keys are compared byte for byte again,
// not trusted on an Ed25519 signature a quantum adversary could one day forge.
func carryLegacyPin(profile string, pin identity.Contact, keys api.AccountKeysResponse) (identity.Contact, error) {
	if len(pin.EncPublicKey) == crypto.EncPublicKeySize || pin.Handle != keys.Handle || !bytes.Equal(pin.PublicKey, keys.PublicKey) {
		return pin, nil
	}
	pins, err := identity.LoadContacts(profile)
	if err != nil {
		return pin, err
	}
	pin.EncPublicKey = keys.EncPublicKey
	pins[pin.Email] = pin
	return pin, identity.SaveContacts(profile, pins)
}

func pinMatches(pin identity.Contact, keys api.AccountKeysResponse) bool {
	return pin.Handle == keys.Handle && bytes.Equal(pin.PublicKey, keys.PublicKey) &&
		bytes.Equal(pin.EncPublicKey, keys.EncPublicKey)
}

func pinFromKeys(email string, keys api.AccountKeysResponse, verified bool) identity.Contact {
	return identity.Contact{
		Email:        email,
		Handle:       keys.Handle,
		PublicKey:    keys.PublicKey,
		EncPublicKey: keys.EncPublicKey,
		PinnedAt:     time.Now().Unix(),
		Verified:     verified,
	}
}

// refuseSharedHandle refuses keys the server reports for email under a handle that a
// pin for another email already holds. An account has one handle and a grant is signed
// to a handle, so two pins on one handle would let a rotation re-wrap what one contact
// was given to the other's key. Only a server misreporting handles produces that.
func refuseSharedHandle(pins map[string]identity.Contact, email string, keys api.AccountKeysResponse) error {
	for _, pin := range pins {
		if pin.Handle == keys.Handle && pin.Email != email {
			return fmt.Errorf("the server reports for %s the account handle you pinned for %s, and an account has only one, so nothing was pinned or shared: the server is misreporting one of them. Compare keys with `aqt contacts verify %s`",
				displayEmail(email), displayEmail(pin.Email), pin.Email)
		}
	}
	return nil
}

// lookupGrantee resolves a grant target with trust-on-first-use pinning: the first
// lookup pins (handle, identity key, enc key) locally, and a later lookup that
// disagrees with the pin never silently re-routes grants to whoever holds the new key.
//
// A first-use pin cannot tell a real account from the decoy the server returns for an
// email that has no published key yet (that indistinguishability is the point: the
// lookup must not become an account-existence oracle). Granting to someone who has not
// registered therefore pins a key nobody holds, and once they register their honest key
// mismatches it. So an unverified pin that mismatches can be replaced after the user
// confirms the new key (askRepin); only a pin verified against a fingerprint is refused
// outright. Pinning deliberately, ahead of the first grant, is `aqt contacts pin`.
//
// A replacement is returned unsaved, with the pinRepair that settles it: the caller
// grants first and then calls repin, so a failed grant leaves the old pin in place and
// the next attempt asks again. mk finds the grants that move with a replacement.
func lookupGrantee(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey, email string) (identity.Contact, *pinRepair, error) {
	keys, err := fetchAccountKeys(cl, email)
	if err != nil {
		return identity.Contact{}, nil, err
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return identity.Contact{}, nil, err
	}
	if err := refuseSharedHandle(pins, email, keys); err != nil {
		return identity.Contact{}, nil, err
	}
	if pin, ok := pins[email]; ok {
		pin, err := carryLegacyPin(prof.Name, pin, keys)
		if err != nil {
			return identity.Contact{}, nil, err
		}
		if pinMatches(pin, keys) {
			return pin, nil, nil
		}
		repair, err := askRepin(cl, prof, mk, pin, keys)
		if err != nil {
			return identity.Contact{}, nil, err
		}
		return pinFromKeys(email, keys, false), repair, nil
	}
	pin := pinFromKeys(email, keys, false)
	pins[email] = pin
	if err := identity.SaveContacts(prof.Name, pins); err != nil {
		return identity.Contact{}, nil, err
	}
	fmt.Fprintf(os.Stderr, "pinned %s on first use (%s); confirm out-of-band with `aqt contacts verify %s`\n",
		email, crypto.KeyFingerprint(pin.PublicKey), email)
	fmt.Fprintf(os.Stderr, "if %s has not registered on this server yet, this pin is a placeholder and the grant will not open for them; once they have, share with them again to re-pin and re-send it\n",
		email)
	return pin, nil, nil
}

// confirmRepin asks before an unverified pin is replaced; cliutil.ErrNotConfirmable
// means no terminal can answer. A variable so tests can answer for one.
var confirmRepin = func(prompt string) error { return confirmDestructive(prompt, false) }

// askRepin decides whether a pin the server's keys disagree with may be replaced, and
// collects the grants that move with it. Only a person comparing fingerprints can make
// that call — the new key is exactly what a key-substituting server would present — so
// a run without a terminal refuses, and no flag accepts the change in advance.
func askRepin(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey, pin identity.Contact, keys api.AccountKeysResponse) (*pinRepair, error) {
	email := pin.Email
	pinnedFP, serverFP := crypto.KeyFingerprint(pin.PublicKey), crypto.KeyFingerprint(keys.PublicKey)
	if pin.Verified {
		return nil, fmt.Errorf("the server's keys for %s (%s) no longer match the pin you verified against their fingerprint (%s). "+
			"Do not share with them until the difference is explained: `aqt contacts verify %s` shows both, and if they confirm new keys, `aqt contacts rm %s` and pin again",
			email, serverFP, pinnedFP, email, email)
	}
	// The server answers an account that has not published an X-Wing key with a decoy,
	// so a pin from before that move mismatches until its owner logs in once. Replacing
	// it would hand their working grants to the decoy.
	if len(pin.EncPublicKey) != crypto.EncPublicKeySize {
		return nil, fmt.Errorf("the server's keys for %s (%s) do not match a pin made before shares moved to post-quantum keys (%s). "+
			"Most often they have not run `aqt login` since: ask them to, then share again. "+
			"If they registered only after your first share, compare %s with them and run `aqt contacts pin %s --fingerprint <fingerprint>`",
			email, serverFP, pinnedFP, serverFP, email)
	}
	granted, err := grantedTo(cl, prof, mk, pin.Handle)
	if err != nil {
		return nil, err
	}
	cause := "most often they registered after your first share: the pin is the placeholder an unknown email gets, and shares made against it never opened"
	if pin.Handle == keys.Handle {
		cause = "the same account now publishes new keys, most often because they rotated their account root key"
	}
	question := fmt.Sprintf("Re-pin %s to the server's keys? [y/N] ", email)
	if len(granted) > 0 {
		question = fmt.Sprintf("Re-pin %s and re-send these earlier share(s):\n%s? [y/N] ", email, granted.list())
	}
	prompt := fmt.Sprintf("the server's keys for %s do not match your pin:\n  pinned  %s  (%s, never verified)\n  server  %s\n%s.\ncompare %s with %s over a separate channel before accepting it.\n%s",
		email, pinnedFP, time.Unix(pin.PinnedAt, 0).Format("2006-01-02"), serverFP, cause, serverFP, email, question)
	switch err := confirmRepin(prompt); {
	case errors.Is(err, cliutil.ErrNotConfirmable):
		return nil, fmt.Errorf("the server's keys for %s (%s) do not match the unverified pin made on %s (%s); "+
			"re-run on a terminal to re-pin, or compare %s with them and run `aqt contacts pin %s --fingerprint <fingerprint>`",
			email, serverFP, time.Unix(pin.PinnedAt, 0).Format("2006-01-02"), pinnedFP, serverFP, email)
	case errors.Is(err, cliutil.ErrAborted):
		return nil, fmt.Errorf("kept the existing pin for %s; nothing was shared", email)
	case err != nil:
		return nil, err
	}
	return &pinRepair{old: pin, granted: granted}, nil
}

// pinRepair is an unverified pin being replaced, and the caller's resources that still
// hold a grant made against it.
type pinRepair struct {
	old     identity.Contact
	granted grantedResources
}

// grantedResource is one of the caller's resources, by id and decrypted name.
type grantedResource struct{ id, name string }

type grantedResources []grantedResource

func (rs grantedResources) list() string {
	lines := make([]string, len(rs))
	for i, r := range rs {
		lines[i] = fmt.Sprintf("  aqt://%s  %q", r.id, r.name)
	}
	return strings.Join(lines, "\n")
}

// grantedTo lists the caller's resources that hold a grant to handle, counting only a
// grant this account signed over the resource's current content key and this device
// has not revoked. The server
// chooses which handles it lists, so a row without that signature may be one it made
// up to have a resource re-sent to whoever holds handle; a share made before grants
// were signed looks the same, and is left for its owner to share again. The listing
// echoes each resource's grant count, so only granted resources cost a fetch.
func grantedTo(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey, handle string) (grantedResources, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, err
	}
	revoked, err := identity.LoadRevokedGrants(prof.Name)
	if err != nil {
		return nil, err
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return nil, err
	}
	holders := 0
	for _, pin := range pins {
		if pin.Handle == handle {
			holders++
		}
	}
	if holders > 1 {
		return nil, errors.New("more than one pinned contact holds this account handle, so its grants cannot be told apart and nothing was moved; unpin the wrong one with `aqt contacts rm <email>` first")
	}
	self := crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey)
	var granted grantedResources
	unsigned := 0
	for _, it := range items {
		if it.GrantCount == 0 || it.Reclaimed || it.WrappedKey == nil || slices.Contains(revoked, identity.RevokedGrant{ResourceID: it.ID, GranteeHandle: handle}) {
			continue
		}
		grants, err := cl.ListGrants(it.ID)
		if err != nil {
			return nil, fmt.Errorf("list grants of %s: %w", it.ID, err)
		}
		i := slices.IndexFunc(grants, func(g api.GrantEntry) bool { return g.GranteeHandle == handle })
		if i < 0 {
			continue
		}
		ck, err := crypto.UnwrapKey(*it.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return nil, fmt.Errorf("open the key of %s: %w", it.ID, err)
		}
		signed := crypto.VerifyGrant(self, grants[i].Signature, ck, it.ID, prof.OwnerHandle, handle)
		meta, metaErr := decodeMeta(it.EncryptedMeta, ck, it.ID)
		ck.Wipe()
		if !signed {
			unsigned++
			continue
		}
		name := "(unreadable)"
		if metaErr == nil {
			name = meta.Name
		}
		granted = append(granted, grantedResource{id: it.ID, name: name})
	}
	if unsigned > 0 {
		fmt.Fprintf(os.Stderr, "warning: left %d grant(s) to the old pin alone: they carry no signature of yours, so they are either shares from before grants were signed or rows the server added; share any you made again with `aqt share <id> --with <email>`\n", unsigned)
	}
	return granted, nil
}

// repin settles a pin replacement: it moves every grant made against the old pin onto
// next, then saves next. Saving last keeps an interrupted run repeatable, since the
// next lookup still sees the old pin, asks again, and finds the grants that did not
// move. done names a resource the caller has already granted to next.
//
// When the handle changed, the old grant is wrapped to keys nobody answering to this
// email holds — most often the decoy an unregistered email gets — so its row is
// deleted without rotating the content key: there is no reader to cut off. When it did
// not, the new grant's upsert has already replaced the old row.
func repin(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey, r pinRepair, next identity.Contact, done string) error {
	var moved grantedResources
	var repairErr error
	for _, g := range r.granted {
		if g.id != done {
			if err := regrantOwned(cl, prof, mk, g.id, next); err != nil {
				repairErr = errors.Join(repairErr, fmt.Errorf("re-send aqt://%s: %w", g.id, err))
				continue
			}
		}
		if r.old.Handle != next.Handle {
			if err := cl.RevokeGrant(g.id, r.old.Handle); err != nil && !errors.Is(err, client.ErrNotFound) {
				repairErr = errors.Join(repairErr, fmt.Errorf("delete the old grant on aqt://%s: %w", g.id, err))
				continue
			}
		}
		moved = append(moved, g)
	}
	if len(moved) > 0 {
		fmt.Fprintf(os.Stderr, "re-sent %d earlier share(s) to %s:\n%s\n", len(moved), next.Email, moved.list())
	}
	if repairErr != nil {
		return fmt.Errorf("pin repair incomplete; kept the old pin for %s so re-running the command retries the remaining shares: %w", next.Email, repairErr)
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return err
	}
	pins[next.Email] = next
	return identity.SaveContacts(prof.Name, pins)
}

// replacePin is repin outside a share. The unlock and the walk run first, so a failure
// in either leaves the old pin and nothing moved.
func (app *application) replacePin(cl *client.Client, prof *identity.Profile, old, next identity.Contact) error {
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	granted, err := grantedTo(cl, prof, mk, old.Handle)
	if err != nil {
		return err
	}
	return repin(cl, prof, mk, pinRepair{old: old, granted: granted}, next, "")
}

// contactsPinCmd pins a contact's keys before any grant is made. The threat model
// names out-of-band pinning as the mitigation for the placeholder-key hole (granting
// to an email that has not registered pins whatever the server serves, decoy
// included), but until this command the only way to create a pin was to make that
// first grant — after the moment the mitigation is supposed to precede.
//
// --fingerprint is the mitigation proper: the pin only lands if the server presents
// the key the contact read out to you over a separate channel, and it is recorded as
// verified. That is stronger evidence than an unverified pin, so it replaces one that
// disagrees, re-sending the grants made against it. Without --fingerprint the command
// still pins deliberately, but it can only show you the fingerprint and ask.
func (app *application) contactsPinCmd() *cobra.Command {
	var (
		fingerprint string
		yes         bool
	)
	cmd := &cobra.Command{
		Use:   "pin <email>",
		Short: "Pin an account's keys before sharing with it, ideally against a fingerprint you were given",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := app.authedClient()
			if err != nil {
				return err
			}
			email := api.NormalizeEmail(args[0])
			keys, err := fetchAccountKeys(cl, email)
			if err != nil {
				return err
			}
			identityFP := crypto.KeyFingerprint(keys.PublicKey)
			encFP := crypto.KeyFingerprint(keys.EncPublicKey)
			// Every success path reports the same shape, so re-running a pin is a stable
			// no-op for a script rather than a different document.
			pinned := func(already, verified bool) error {
				return printJSON(map[string]any{
					"email": email, "fingerprint": identityFP, "encFingerprint": encFP, "alreadyPinned": already, "verified": verified,
				})
			}

			// Fail closed on anything but the exact fingerprint that was verified
			// out-of-band. This is the one check a hostile server (or a decoy for an
			// unregistered email) cannot talk its way past, and it runs before the
			// already-pinned branches below: answering "already pinned" to a command that
			// named a fingerprint the server does not present would be a false all-clear.
			if fingerprint != "" && !fingerprintMatches(fingerprint, identityFP) {
				return fmt.Errorf("the server presents %s for %s, not %s — if they have not registered yet, this is the decoy an unknown email always gets (retry once they have); otherwise do not share with this account until the difference is explained",
					identityFP, email, fingerprint)
			}
			pins, err := identity.LoadContacts(prof.Name)
			if err != nil {
				return err
			}
			if err := refuseSharedHandle(pins, email, keys); err != nil {
				return err
			}
			if pin, ok := pins[email]; ok {
				pin, err := carryLegacyPin(prof.Name, pin, keys)
				if err != nil {
					return err
				}
				pinnedFP := crypto.KeyFingerprint(pin.PublicKey)
				switch {
				case pinMatches(pin, keys):
					newlyVerified := fingerprint != "" && !pin.Verified
					if newlyVerified {
						pin.Verified = true
						pins[email] = pin
						if err := identity.SaveContacts(prof.Name, pins); err != nil {
							return err
						}
					}
					if app.json {
						return pinned(true, pin.Verified)
					}
					if newlyVerified {
						fmt.Printf("%s is already pinned to these keys (%s), now marked verified\n", email, identityFP)
					} else {
						fmt.Printf("%s is already pinned to these keys (%s)\n", email, identityFP)
					}
					return nil
				case pin.Verified:
					return fmt.Errorf("%s is pinned to different keys (%s) that you verified against a fingerprint; compare both with `aqt contacts verify %s`, and if they confirm new keys, `aqt contacts rm %s` and pin again",
						email, pinnedFP, email, email)
				case fingerprint == "":
					return fmt.Errorf("%s is pinned to different keys (%s, never verified); compare the server's %s with them, then re-run with --fingerprint to replace the pin",
						email, pinnedFP, identityFP)
				}
				if err := app.replacePin(cl, prof, pin, pinFromKeys(email, keys, true)); err != nil {
					return err
				}
				if app.json {
					return pinned(false, true)
				}
				fmt.Printf("pinned %s (%s), replacing the unverified pin %s\n", email, identityFP, pinnedFP)
				return nil
			}
			if fingerprint == "" {
				// Advisory, so stderr: stdout carries the result, and under --json it
				// carries a document a prompt preamble would corrupt.
				fmt.Fprintf(os.Stderr, "server reports for %s:\n  identity  %s\n  enc key   %s\n", email, identityFP, encFP)
				fmt.Fprintln(os.Stderr, "an unregistered email gets an indistinguishable decoy, so a pin made without comparing this fingerprint out-of-band proves nothing")
				if err := confirmDestructive(fmt.Sprintf("Pin these keys for %s? [y/N] ", email), yes); err != nil {
					return err
				}
			}
			verified := fingerprint != ""
			pins[email] = pinFromKeys(email, keys, verified)
			if err := identity.SaveContacts(prof.Name, pins); err != nil {
				return err
			}
			if app.json {
				return pinned(false, verified)
			}
			fmt.Printf("pinned %s (%s)\n", email, identityFP)
			return nil
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "only pin if the server's identity key matches this fingerprint; replaces an unverified pin")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt asked when no --fingerprint is given")
	markJSONSupported(cmd)
	return cmd
}

// fingerprintMatches compares a user-supplied fingerprint against a computed one,
// tolerating a missing "SHA256:" prefix and surrounding whitespace — the shapes a
// fingerprint arrives in when it has been read aloud, pasted from a chat, or copied
// out of `aqt contacts verify`. Everything after that must match exactly.
func fingerprintMatches(supplied, computed string) bool {
	trim := func(s string) string {
		return strings.TrimPrefix(strings.TrimSpace(s), "SHA256:")
	}
	return trim(supplied) == trim(computed)
}

func (app *application) contactsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contacts",
		Short: "List accounts pinned for sharing",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := app.loadProfile()
			if err != nil {
				return err
			}
			pins, err := identity.LoadContacts(prof.Name)
			if err != nil {
				return err
			}
			emails := make([]string, 0, len(pins))
			for e := range pins {
				emails = append(emails, e)
			}
			sort.Strings(emails)
			if app.json {
				type contactRow struct {
					Email       string `json:"email"`
					Fingerprint string `json:"fingerprint"`
					PinnedAt    string `json:"pinnedAt"`
					Verified    bool   `json:"verified"`
				}
				rows := make([]contactRow, 0, len(emails))
				for _, e := range emails {
					p := pins[e]
					rows = append(rows, contactRow{
						Email:       e,
						Fingerprint: crypto.KeyFingerprint(p.PublicKey),
						PinnedAt:    time.Unix(p.PinnedAt, 0).Format("2006-01-02"),
						Verified:    p.Verified,
					})
				}
				return printJSON(rows)
			}
			if len(pins) == 0 {
				fmt.Println("no pinned contacts; `aqt share <id> --with <email>` pins on first use")
				return nil
			}
			for _, e := range emails {
				p := pins[e]
				state := "never verified"
				if p.Verified {
					state = "verified"
				}
				fmt.Printf("%s  %s  pinned %s, %s\n", displayEmail(e), crypto.KeyFingerprint(p.PublicKey),
					time.Unix(p.PinnedAt, 0).Format("2006-01-02"), state)
			}
			return nil
		},
	}
	markJSONSupported(cmd)
	cmd.AddCommand(&cobra.Command{
		Use:     "rm <email>",
		Aliases: []string{"remove"},
		Short:   "Drop an account's pinned keys, so the next share re-pins whatever the server serves",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := app.loadProfile()
			if err != nil {
				return err
			}
			email := api.NormalizeEmail(args[0])
			pins, err := identity.LoadContacts(prof.Name)
			if err != nil {
				return err
			}
			if _, ok := pins[email]; !ok {
				return fmt.Errorf("%s is not pinned", email)
			}
			delete(pins, email)
			if err := identity.SaveContacts(prof.Name, pins); err != nil {
				return err
			}
			fmt.Printf("removed the pin for %s\n", email)
			fmt.Fprintln(os.Stderr, "the next `aqt share --with` re-pins on first use: verify the new fingerprint out-of-band before trusting it")
			return nil
		},
	})
	cmd.AddCommand(app.contactsPinCmd())
	cmd.AddCommand(&cobra.Command{
		Use:   "verify <email>",
		Short: "Print pinned and server-reported key fingerprints for out-of-band comparison",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := app.authedClient()
			if err != nil {
				return err
			}
			email := api.NormalizeEmail(args[0])
			keys, err := fetchAccountKeys(cl, email)
			if err != nil {
				return err
			}
			fmt.Printf("server reports for %s:\n  identity  %s\n  enc key   %s\n",
				email, crypto.KeyFingerprint(keys.PublicKey), crypto.KeyFingerprint(keys.EncPublicKey))
			pins, err := identity.LoadContacts(prof.Name)
			if err != nil {
				return err
			}
			pin, ok := pins[email]
			if !ok {
				fmt.Println("not pinned yet; the first `aqt share --with` to this email pins these keys")
				return nil
			}
			if pin, err = carryLegacyPin(prof.Name, pin, keys); err != nil {
				return err
			}
			label := "pinned on first use, never verified"
			if pin.Verified {
				label = "pinned and verified against a fingerprint"
			}
			fmt.Printf("%s:\n  identity  %s\n  enc key   %s\n",
				label, crypto.KeyFingerprint(pin.PublicKey), crypto.KeyFingerprint(pin.EncPublicKey))
			if bytes.Equal(pin.PublicKey, keys.PublicKey) && bytes.Equal(pin.EncPublicKey, keys.EncPublicKey) {
				fmt.Println("MATCH — compare either fingerprint with the contact over a separate channel")
			} else {
				fmt.Println("MISMATCH — the server is presenting different keys than the ones pinned; do not share until this is resolved")
			}
			return nil
		},
	})
	return cmd
}
