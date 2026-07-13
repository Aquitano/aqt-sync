package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
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
// treated as proof of an attack, and both paths point at `aqt contacts remove`.
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
					"Compare fingerprints out-of-band with `aqt contacts verify %s`, then `aqt contacts remove %s` and re-share",
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
	fmt.Fprintf(os.Stderr, "if %s has not registered on this server yet, this pin is a placeholder and the grant will not open for them: `aqt contacts remove %s` and re-share once they have an account\n",
		email, email)
	return pin, nil
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
			if len(pins) == 0 {
				fmt.Println("no pinned contacts; `aqt share <id> --with <email>` pins on first use")
				return nil
			}
			emails := make([]string, 0, len(pins))
			for e := range pins {
				emails = append(emails, e)
			}
			sort.Strings(emails)
			for _, e := range emails {
				p := pins[e]
				fmt.Printf("%s  %s  pinned %s\n", e, crypto.KeyFingerprint(p.PublicKey),
					time.Unix(p.PinnedAt, 0).Format("2006-01-02"))
			}
			return nil
		},
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "remove <email>",
		Short: "Drop an account's pinned keys, so the next share re-pins whatever the server serves",
		Args:  cobra.ExactArgs(1),
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
