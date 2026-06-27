package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func loginCmd() *cobra.Command {
	var (
		email string
		ttl   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Create an account or attach this device, caching the unlocked key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(email, ttl)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "account email")
	cmd.Flags().DurationVar(&ttl, "ttl", defaultSessionTTL, "how long to cache the unlocked key (0 = until logout)")
	return cmd
}

// errNoUnlock is returned when the bootstrap's wrapped root will not open with the
// entered passphrase. Because the bootstrap endpoint returns an indistinguishable
// decoy for an unknown email, this is genuinely ambiguous: either no account exists
// for the email or the passphrase is wrong.
var errNoUnlock = errors.New("could not unlock: no account exists for this email, or the passphrase is wrong")

func runLogin(email string, ttl time.Duration) error {
	if email == "" {
		entered, err := promptLine("email: ")
		if err != nil {
			return fmt.Errorf("read email: %w", err)
		}
		email = entered
	}
	server := serverURL()
	cl := client.New(server, "")

	boot, err := cl.Bootstrap(email)
	if err != nil {
		return err
	}
	pass, err := promptPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	if pass == "" {
		return errSessionRequired
	}
	uk, err := crypto.DeriveUnlockKey(pass, boot.Kdf)
	if err != nil {
		return err
	}
	rk, err := crypto.UnwrapRoot(boot.WrappedRoot, uk)
	if err != nil {
		// The wrapped root did not open: no account, or wrong passphrase. Offer to
		// create an account with this passphrase (a real account would 409).
		uk.Wipe()
		return confirmAndCreate(cl, server, email, pass, ttl)
	}
	defer rk.Wipe()
	defer uk.Wipe()
	return attachDevice(cl, server, email, boot, rk, uk, ttl)
}

func logoutCmd() *cobra.Command {
	var allDevices bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear the cached session key (the passphrase is needed again next time)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// --all-devices revokes every *other* device first; this device stays
			// attached but locked (its local key material is dropped below).
			if allDevices {
				if err := revokeOtherDevices(); err != nil {
					return err
				}
			}
			name := firstNonEmpty(flagProfile, identity.DefaultProfile)
			if err := identity.ClearSession(name); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "session cleared")
			return nil
		},
	}
	cmd.Flags().BoolVar(&allDevices, "all-devices", false, "also revoke every other device on the account")
	return cmd
}

func revokeOtherDevices() error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	devices, err := cl.ListDevices()
	if err != nil {
		return err
	}
	revoked := 0
	for _, d := range devices {
		if d.ID == prof.DeviceID {
			continue
		}
		if err := cl.DeleteDevice(d.ID); err != nil {
			return fmt.Errorf("revoke device %s: %w", d.ID, err)
		}
		revoked++
	}
	fmt.Fprintf(os.Stderr, "revoked %d other device(s)\n", revoked)
	return nil
}

// confirmAndCreate runs first-run signup after an unlock attempt failed. A typo'd
// passphrase becomes the account passphrase with no recovery path, so on a terminal
// we confirm it and warn explicitly; without a terminal we proceed (a scripted
// signup), relying on the server's 409 to catch "account already exists".
func confirmAndCreate(cl *client.Client, server, email, pass string, ttl time.Duration) error {
	if interactiveStdin() {
		create, err := promptYesNo(fmt.Sprintf("No account unlocked for %s. Create a new one? (cannot be reset) [y/N] ", email), false)
		if err != nil {
			return err
		}
		if !create {
			return errNoUnlock
		}
		confirm, err := promptPassphrase("Confirm passphrase: ")
		if err != nil {
			return err
		}
		if confirm != pass {
			return errors.New("passphrases do not match")
		}
	}
	return createAccount(cl, server, email, pass, ttl)
}

// createAccount mints a random root key, wraps it under the passphrase-derived
// unlock key, and registers the account with the wrapped root, the verifier, and the
// signing public key. The root key never leaves this machine; the passphrase change
// later re-wraps it without touching any data.
func createAccount(cl *client.Client, server, email, pass string, ttl time.Duration) error {
	fmt.Fprintln(os.Stderr, "Your passphrase wraps your encryption key. We never see it and it CANNOT be reset.")

	kdf, err := crypto.NewKdfParams()
	if err != nil {
		return err
	}
	rk, err := crypto.GenerateMasterKey()
	if err != nil {
		return err
	}
	defer rk.Wipe()
	uk, err := crypto.DeriveUnlockKey(pass, kdf)
	if err != nil {
		return err
	}
	defer uk.Wipe()
	wrappedRoot, err := crypto.WrapRoot(rk, uk)
	if err != nil {
		return err
	}
	signing := crypto.DeriveSigningKey(rk)
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    signing.Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   deviceName(),
	})
	if errors.Is(err, client.ErrConflict) {
		return errors.New("an account already exists for this email; the passphrase was incorrect")
	}
	if err != nil {
		return err
	}
	fingerprint := crypto.KeyFingerprint(signing.Public().(ed25519.PublicKey))
	if err := saveProfile(server, email, fingerprint, kdf, wrappedRoot, resp); err != nil {
		return err
	}
	return cacheSession(rk, ttl)
}

// attachDevice logs this device in to an existing account. The root key (rk) and
// unlock key (uk) were already recovered from the bootstrap during login; here it
// signs the challenge with the signing key and presents the passphrase verifier, so
// both the master key and the current passphrase are proven.
func attachDevice(cl *client.Client, server, email string, boot api.SaltResponse, rk crypto.MasterKey, uk crypto.UnlockKey, ttl time.Duration) error {
	signing := crypto.DeriveSigningKey(rk)
	ch, err := cl.Challenge(email)
	if err != nil {
		return err
	}
	resp, err := cl.AttachDevice(api.AttachDeviceRequest{
		Email:        email,
		ChallengeID:  ch.ChallengeID,
		Signature:    ed25519.Sign(signing, ch.Nonce),
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   deviceName(),
	})
	if err != nil {
		return err
	}
	fingerprint := crypto.KeyFingerprint(signing.Public().(ed25519.PublicKey))
	if err := saveProfile(server, email, fingerprint, boot.Kdf, boot.WrappedRoot, resp); err != nil {
		return err
	}
	return cacheSession(rk, ttl)
}

// cacheSession stores the freshly recovered root key for the active profile.
func cacheSession(rk crypto.MasterKey, ttl time.Duration) error {
	return identity.SaveSession(firstNonEmpty(flagProfile, identity.DefaultProfile), rk, ttl)
}

func saveProfile(server, email, fingerprint string, kdf crypto.KdfParams, wrappedRoot crypto.SealedBlob, resp api.AuthResponse) error {
	p := &identity.Profile{
		Name:        firstNonEmpty(flagProfile, identity.DefaultProfile),
		Server:      server,
		Email:       email,
		OwnerHandle: resp.OwnerHandle,
		DeviceID:    resp.DeviceID,
		Token:       resp.Token,
		Fingerprint: fingerprint,
		Kdf:         kdf,
		WrappedRoot: wrappedRoot,
		AuthEpoch:   resp.Epoch,
	}
	if err := identity.Save(p); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "logged in as %s · device %s · %s\n", email, resp.DeviceID, server)
	return nil
}

func whoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the current account and device",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := loadProfile()
			if err != nil {
				return err
			}
			fingerprint := p.Fingerprint
			if fingerprint == "" {
				fingerprint = "key unknown (re-login to populate)"
			}
			fmt.Printf("%s · device %s · %s · %s\n", p.Email, p.DeviceID, fingerprint, p.Server)
			return nil
		},
	}
}

func passphraseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passphrase",
		Short: "Manage your account passphrase",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "change",
		Short: "Re-wrap your encryption key under a new passphrase (other devices must re-login)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runPassphraseChange() },
	})
	return cmd
}

// runPassphraseChange re-wraps the account's root key under a new passphrase. The
// root key is unchanged, so nothing is re-encrypted; the server bumps the account's
// auth epoch, so every other device's token stops working until it re-logs in with
// the new passphrase. This device keeps its session.
func runPassphraseChange() error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}

	oldPass, err := promptPassphrase("Current passphrase: ")
	if err != nil {
		return err
	}
	oldUK, err := crypto.DeriveUnlockKey(oldPass, prof.Kdf)
	if err != nil {
		return err
	}
	defer oldUK.Wipe()
	// Unwrapping the local wrapped root both proves the current passphrase and
	// recovers the root key to re-wrap.
	rk, err := crypto.UnwrapRoot(prof.WrappedRoot, oldUK)
	if err != nil {
		return errors.New("current passphrase is incorrect")
	}
	defer rk.Wipe()

	newPass, err := promptPassphrase("New passphrase: ")
	if err != nil {
		return err
	}
	if newPass == "" {
		return errors.New("new passphrase must not be empty")
	}
	if newPass == oldPass {
		return errors.New("new passphrase is the same as the current one")
	}
	confirm, err := promptPassphrase("Confirm new passphrase: ")
	if err != nil {
		return err
	}
	if newPass != confirm {
		return errors.New("passphrases do not match")
	}

	newKdf, err := crypto.NewKdfParams()
	if err != nil {
		return err
	}
	newUK, err := crypto.DeriveUnlockKey(newPass, newKdf)
	if err != nil {
		return err
	}
	defer newUK.Wipe()
	newWrapped, err := crypto.WrapRoot(rk, newUK)
	if err != nil {
		return err
	}

	resp, err := cl.ChangePassphrase(api.PassphraseChangeRequest{
		Kdf:             newKdf,
		WrappedRoot:     newWrapped,
		OldAuthVerifier: crypto.DeriveAuthVerifier(oldUK),
		NewAuthVerifier: crypto.DeriveAuthVerifier(newUK),
		ExpectedEpoch:   prof.AuthEpoch,
	})
	if err != nil {
		return err
	}

	// The root key (and so the cached session) is unchanged; only the wrap and its
	// params move. Persist them with the new epoch so this device's token stays valid.
	prof.Kdf = newKdf
	prof.WrappedRoot = newWrapped
	prof.AuthEpoch = resp.Epoch
	if err := identity.Save(prof); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "passphrase changed; other devices must re-login with the new passphrase")
	return nil
}

func deviceName() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unnamed-device"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
