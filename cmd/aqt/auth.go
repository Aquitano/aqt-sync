package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func loginCmd() *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Create an account or attach this device",
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				fmt.Fprint(os.Stderr, "email: ")
				if _, err := fmt.Scanln(&email); err != nil {
					return fmt.Errorf("read email: %w", err)
				}
			}
			server := serverURL()
			cl := client.New(server, "")

			kdf, exists, err := cl.Salt(email)
			if err != nil {
				return err
			}
			if exists {
				return attachDevice(cl, server, email, kdf)
			}
			return createAccount(cl, server, email)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "account email")
	return cmd
}

// createAccount runs first-run signup. A typo'd passphrase becomes the account
// passphrase with no recovery path, so we confirm it and warn explicitly.
func createAccount(cl *client.Client, server, email string) error {
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
	return saveProfile(server, email, kdf, resp)
}

func attachDevice(cl *client.Client, server, email string, kdf crypto.KdfParams) error {
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
	return saveProfile(server, email, kdf, resp)
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
