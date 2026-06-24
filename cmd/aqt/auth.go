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
			if email == "" {
				entered, err := promptLine("email: ")
				if err != nil {
					return fmt.Errorf("read email: %w", err)
				}
				email = entered
			}
			server := serverURL()
			cl := client.New(server, "")

			kdf, exists, err := cl.Salt(email)
			if err != nil {
				return err
			}
			if exists {
				return attachDevice(cl, server, email, kdf, ttl)
			}
			return createAccount(cl, server, email, ttl)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "account email")
	cmd.Flags().DurationVar(&ttl, "ttl", defaultSessionTTL, "how long to cache the unlocked key (0 = until logout)")
	return cmd
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

// createAccount runs first-run signup. A typo'd passphrase becomes the account
// passphrase with no recovery path, so we confirm it and warn explicitly.
func createAccount(cl *client.Client, server, email string, ttl time.Duration) error {
	fmt.Fprintln(os.Stderr, "No account found for", email+". Creating one.")
	fmt.Fprintln(os.Stderr, "Your passphrase derives your encryption key. We never see it and it CANNOT be reset.")

	pass, err := promptPassphrase("Choose a passphrase: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassphrase("Confirm passphrase: ")
	if err != nil {
		return err
	}
	if pass != confirm {
		return errors.New("passphrases do not match")
	}

	kdf, err := crypto.NewKdfParams()
	if err != nil {
		return err
	}
	mk, err := crypto.DeriveMasterKey(pass, kdf)
	if err != nil {
		return err
	}
	signing := crypto.DeriveSigningKey(mk)
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:      email,
		Kdf:        kdf,
		PublicKey:  signing.Public().(ed25519.PublicKey),
		DeviceName: deviceName(),
	})
	if err != nil {
		return err
	}
	if err := saveProfile(server, email, kdf, resp); err != nil {
		return err
	}
	return cacheSession(mk, ttl)
}

func attachDevice(cl *client.Client, server, email string, kdf crypto.KdfParams, ttl time.Duration) error {
	pass, err := promptPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	mk, err := crypto.DeriveMasterKey(pass, kdf)
	if err != nil {
		return err
	}
	signing := crypto.DeriveSigningKey(mk)

	// Prove possession of the signing key by signing a server challenge; the
	// key itself never leaves this machine.
	ch, err := cl.Challenge(email)
	if err != nil {
		return err
	}
	resp, err := cl.AttachDevice(api.AttachDeviceRequest{
		Email:       email,
		ChallengeID: ch.ChallengeID,
		Signature:   ed25519.Sign(signing, ch.Nonce),
		DeviceName:  deviceName(),
	})
	if err != nil {
		return err
	}
	if err := saveProfile(server, email, kdf, resp); err != nil {
		return err
	}
	return cacheSession(mk, ttl)
}

// cacheSession stores the freshly derived master key for the active profile.
func cacheSession(mk crypto.MasterKey, ttl time.Duration) error {
	return identity.SaveSession(firstNonEmpty(flagProfile, identity.DefaultProfile), mk, ttl)
}

func saveProfile(server, email string, kdf crypto.KdfParams, resp api.AuthResponse) error {
	p := &identity.Profile{
		Name:        firstNonEmpty(flagProfile, identity.DefaultProfile),
		Server:      server,
		Email:       email,
		OwnerHandle: resp.OwnerHandle,
		DeviceID:    resp.DeviceID,
		Token:       resp.Token,
		Kdf:         kdf,
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
			fmt.Printf("%s · device %s · %s\n", p.Email, p.DeviceID, p.Server)
			return nil
		},
	}
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
