package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
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
// errors on any disagreement with the pin before returning, so routing through it
// would make the check below dead code and report a grantee's own root-key rotation —
// a routine event on this path — in the words of a server substituting keys.
func confirmPinnedKeys(cl *client.Client, prof *identity.Profile, pin identity.Contact) error {
	keys, err := fetchAccountKeys(cl, pin.Email)
	if err != nil {
		return err
	}
	if keys.Handle != pin.Handle || !bytes.Equal(keys.PublicKey, pin.PublicKey) ||
		!bytes.Equal(keys.EncPublicKey, pin.EncPublicKey) {
		return fmt.Errorf(
			"the keys published for %s no longer match the ones pinned here — most often because they rotated their account root key. "+
				"Compare fingerprints out-of-band with `aqt contacts verify %s`, then `aqt contacts rm %s` and re-share",
			pin.Email, pin.Email, pin.Email)
	}
	return nil
}

// lookupGrantee resolves a grant target with trust-on-first-use pinning: the first
// lookup pins (handle, identity key, enc key) locally; any later lookup that
// disagrees with the pin is a hard error, since a silently swapped key would
// re-route every future grant to whoever holds it.
//
// A first-use pin cannot tell a real account from the decoy the server returns for an
// email that has no published key yet (that indistinguishability is the point: the
// lookup must not become an account-existence oracle). Granting to someone who has not
// registered therefore pins a key nobody holds — the grant is accepted and simply never
// opens — and once they do register, the honest key mismatches the pinned decoy and
// every later share fails as if the server were attacking. So the mismatch is never
// treated as proof of an attack, and both paths point at `aqt contacts rm`. Pinning
// deliberately, ahead of the first grant, is `aqt contacts pin`.
func lookupGrantee(cl *client.Client, prof *identity.Profile, email string) (identity.Contact, error) {
	keys, err := fetchAccountKeys(cl, email)
	if err != nil {
		return identity.Contact{}, err
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return identity.Contact{}, err
	}
	if pin, ok := pins[email]; ok {
		if pin.Handle != keys.Handle ||
			!bytes.Equal(pin.PublicKey, keys.PublicKey) ||
			!bytes.Equal(pin.EncPublicKey, keys.EncPublicKey) {
			return identity.Contact{}, fmt.Errorf(
				"the server's keys for %s no longer match the ones pinned on first use. Either they had not registered when you first shared (the pin is a placeholder and any grant made against it never opened), the account was re-created — or the server is substituting keys. "+
					"Compare fingerprints out-of-band with `aqt contacts verify %s`, then `aqt contacts rm %s` and re-share",
				email, email, email)
		}
		return pin, nil
	}
	pin := identity.Contact{
		Email:        email,
		Handle:       keys.Handle,
		PublicKey:    keys.PublicKey,
		EncPublicKey: keys.EncPublicKey,
		PinnedAt:     time.Now().Unix(),
	}
	pins[email] = pin
	if err := identity.SaveContacts(prof.Name, pins); err != nil {
		return identity.Contact{}, err
	}
	fmt.Fprintf(os.Stderr, "pinned %s on first use (%s); confirm out-of-band with `aqt contacts verify %s`\n",
		email, crypto.KeyFingerprint(pin.PublicKey), email)
	fmt.Fprintf(os.Stderr, "if %s has not registered on this server yet, this pin is a placeholder and the grant will not open for them: `aqt contacts rm %s` and re-share once they have an account\n",
		email, email)
	return pin, nil
}

// contactsPinCmd pins a contact's keys before any grant is made. The threat model
// names out-of-band pinning as the mitigation for the placeholder-key hole (granting
// to an email that has not registered pins whatever the server serves, decoy
// included), but until this command the only way to create a pin was to make that
// first grant — after the moment the mitigation is supposed to precede.
//
// --fingerprint is the mitigation proper: the pin only lands if the server presents
// the key the contact read out to you over a separate channel. Without it the command
// still pins deliberately, but it can only show you the fingerprint and ask.
func contactsPinCmd() *cobra.Command {
	var (
		fingerprint string
		yes         bool
	)
	cmd := &cobra.Command{
		Use:   "pin <email>",
		Short: "Pin an account's keys before sharing with it, ideally against a fingerprint you were given",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			email := args[0]
			keys, err := fetchAccountKeys(cl, email)
			if err != nil {
				return err
			}
			identityFP := crypto.KeyFingerprint(keys.PublicKey)
			encFP := crypto.KeyFingerprint(keys.EncPublicKey)
			// Both success paths report the same shape, so re-running a pin is a stable
			// no-op for a script rather than a different document.
			pinned := func(already bool) error {
				return printJSON(map[string]any{
					"email": email, "fingerprint": identityFP, "encFingerprint": encFP, "alreadyPinned": already,
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
			if pin, ok := pins[email]; ok {
				if pin.Handle == keys.Handle && bytes.Equal(pin.PublicKey, keys.PublicKey) &&
					bytes.Equal(pin.EncPublicKey, keys.EncPublicKey) {
					if flagJSON {
						return pinned(true)
					}
					fmt.Printf("%s is already pinned to these keys (%s)\n", email, identityFP)
					return nil
				}
				return fmt.Errorf("%s is already pinned to different keys (%s); compare both with `aqt contacts verify %s`, then `aqt contacts rm %s` if you mean to re-pin",
					email, crypto.KeyFingerprint(pin.PublicKey), email, email)
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
			pins[email] = identity.Contact{
				Email:        email,
				Handle:       keys.Handle,
				PublicKey:    keys.PublicKey,
				EncPublicKey: keys.EncPublicKey,
				PinnedAt:     time.Now().Unix(),
			}
			if err := identity.SaveContacts(prof.Name, pins); err != nil {
				return err
			}
			if flagJSON {
				return pinned(false)
			}
			fmt.Printf("pinned %s (%s)\n", email, identityFP)
			return nil
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "only pin if the server's identity key matches this fingerprint")
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

func contactsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contacts",
		Short: "List accounts pinned for sharing",
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := loadProfile()
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
			if flagJSON {
				type contactRow struct {
					Email       string `json:"email"`
					Fingerprint string `json:"fingerprint"`
					PinnedAt    string `json:"pinnedAt"`
				}
				rows := make([]contactRow, 0, len(emails))
				for _, e := range emails {
					p := pins[e]
					rows = append(rows, contactRow{
						Email:       e,
						Fingerprint: crypto.KeyFingerprint(p.PublicKey),
						PinnedAt:    time.Unix(p.PinnedAt, 0).Format("2006-01-02"),
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
				fmt.Printf("%s  %s  pinned %s\n", e, crypto.KeyFingerprint(p.PublicKey),
					time.Unix(p.PinnedAt, 0).Format("2006-01-02"))
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
			prof, err := loadProfile()
			if err != nil {
				return err
			}
			email := args[0]
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
	cmd.AddCommand(contactsPinCmd())
	cmd.AddCommand(&cobra.Command{
		Use:   "verify <email>",
		Short: "Print pinned and server-reported key fingerprints for out-of-band comparison",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			email := args[0]
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
			fmt.Printf("pinned on first use:\n  identity  %s\n  enc key   %s\n",
				crypto.KeyFingerprint(pin.PublicKey), crypto.KeyFingerprint(pin.EncPublicKey))
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
