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
		email  string
		ttl    time.Duration
		invite string
		kc     kdfChoice
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Create an account or attach this device, caching the unlocked key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(email, firstNonEmpty(invite, os.Getenv("AQT_INVITE_TOKEN")), ttl, kc)
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "account email")
	cmd.Flags().DurationVar(&ttl, "ttl", defaultSessionTTL, "how long to cache the unlocked key (0 = until logout)")
	cmd.Flags().StringVar(&invite, "invite", "", "invite token, if the server requires one to register (or set AQT_INVITE_TOKEN)")
	addKdfFlags(cmd, &kc) // only consulted when this login creates a new account
	return cmd
}

// kdfChoice holds the Argon2id tuning a command exposes. With no manual override
// it calibrates iterations to the preset's target unlock time on this machine;
// any explicit cost flag switches to exact, reproducible params instead.
type kdfChoice struct {
	preset    string
	timeCost  uint32
	memoryMiB uint32
	threads   uint8
}

func addKdfFlags(cmd *cobra.Command, k *kdfChoice) {
	cmd.Flags().StringVar(&k.preset, "kdf-preset", string(crypto.DefaultPreset), "Argon2id calibration target: interactive|moderate|sensitive")
	cmd.Flags().Uint32Var(&k.timeCost, "kdf-time", 0, "Argon2id iterations (manual override; skips calibration)")
	cmd.Flags().Uint32Var(&k.memoryMiB, "kdf-memory", 0, "Argon2id memory in MiB (manual override; skips calibration)")
	cmd.Flags().Uint8Var(&k.threads, "kdf-threads", 0, "Argon2id lanes (0 = auto: cores capped at 4)")
}

func (k kdfChoice) resolve() (crypto.KdfParams, error) {
	if k.timeCost != 0 || k.memoryMiB != 0 {
		return crypto.ManualKdfParams(k.timeCost, k.memoryMiB*1024, k.threads)
	}
	preset := crypto.KdfPreset(k.preset)
	fmt.Fprintf(os.Stderr, "calibrating Argon2id (%s target)...\n", preset)
	return crypto.CalibrateKdf(preset, k.threads)
}

// errNoUnlock is returned when the bootstrap's wrapped root will not open with the
// entered passphrase. Because the bootstrap endpoint returns an indistinguishable
// decoy for an unknown email, this is genuinely ambiguous: either no account exists
// for the email or the passphrase is wrong.
var errNoUnlock = errors.New("could not unlock: no account exists for this email, or the passphrase is wrong")

func runLogin(email, invite string, ttl time.Duration, kc kdfChoice) error {
	if email == "" {
		entered, err := promptLine("email: ")
		if err != nil {
			return fmt.Errorf("read email: %w", err)
		}
		email = entered
	}
	server := serverURL()
	cl, err := client.New(server, "")
	if err != nil {
		return err
	}

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
		return confirmAndCreate(cl, server, email, pass, invite, ttl, kc)
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
func confirmAndCreate(cl *client.Client, server, email, pass, invite string, ttl time.Duration, kc kdfChoice) error {
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
	return createAccount(cl, server, email, pass, invite, ttl, kc)
}

// createAccount mints a random root key, wraps it under the passphrase-derived
// unlock key, and registers the account with the wrapped root, the verifier, and the
// signing public key. The root key never leaves this machine; the passphrase change
// later re-wraps it without touching any data.
func createAccount(cl *client.Client, server, email, pass, invite string, ttl time.Duration, kc kdfChoice) error {
	fmt.Fprintln(os.Stderr, "Your passphrase wraps your encryption key. We never see it and it CANNOT be reset.")

	kdf, err := kc.resolve()
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
	encPub := crypto.DeriveEncKey(rk).Public()
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    signing.Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   deviceName(),
		InviteToken:  invite,
		EncPublicKey: encPub,
		EncKeySig:    crypto.SignEncKey(signing, encPub),
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
	// Lazy enc-key backfill for accounts created before grants existed. Best
	// effort: an old server without the endpoint must not fail the login.
	if authed, err := client.New(server, resp.Token); err == nil {
		encPub := crypto.DeriveEncKey(rk).Public()
		_ = authed.PublishEncKey(api.PublishEncKeyRequest{
			EncPublicKey: encPub,
			EncKeySig:    crypto.SignEncKey(signing, encPub),
		})
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

	var changeKc kdfChoice
	change := &cobra.Command{
		Use:   "change",
		Short: "Re-wrap your encryption key under a new passphrase (other devices must re-login)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runPassphraseChange(changeKc) },
	}
	addKdfFlags(change, &changeKc)
	cmd.AddCommand(change)

	var calibrateKc kdfChoice
	calibrate := &cobra.Command{
		Use:   "calibrate",
		Short: "Re-tune Argon2id cost for this account, keeping the passphrase (other devices must re-login)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runPassphraseCalibrate(calibrateKc) },
	}
	addKdfFlags(calibrate, &calibrateKc)
	cmd.AddCommand(calibrate)

	var rotateYes bool
	rotateRoot := &cobra.Command{
		Use:   "rotate-root",
		Short: "Replace the account root key after compromise (revokes every other device)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runRootKeyRotation(rotateYes) },
	}
	rotateRoot.Flags().BoolVarP(&rotateYes, "yes", "y", false, "skip the confirmation prompt")
	cmd.AddCommand(rotateRoot)

	return cmd
}

// rewrapRoot re-wraps the account root key under newPass with newKdf and uploads
// the new wrap. The root key is unchanged, so nothing is re-encrypted; the server
// bumps the auth epoch, so every other device's token stops working until it
// re-logs in. oldUK proves the current passphrase. This device keeps its session
// (the root key, and so the cached master key, is untouched).
func rewrapRoot(cl *client.Client, prof *identity.Profile, rk crypto.MasterKey, oldUK crypto.UnlockKey, newPass string, newKdf crypto.KdfParams) error {
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
	prof.Kdf = newKdf
	prof.WrappedRoot = newWrapped
	prof.AuthEpoch = resp.Epoch
	return identity.Save(prof)
}

// runPassphraseChange re-wraps the account's root key under a new passphrase, with
// KDF params calibrated (or overridden) for this machine so the change never
// silently downgrades the cost.
func runPassphraseChange(kc kdfChoice) error {
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

	newKdf, err := kc.resolve()
	if err != nil {
		return err
	}
	if err := rewrapRoot(cl, prof, rk, oldUK, newPass, newKdf); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "passphrase changed; other devices must re-login with the new passphrase")
	return nil
}

// runPassphraseCalibrate re-tunes the account's Argon2id params without changing
// the passphrase: it re-wraps the same root key under the same passphrase with
// freshly calibrated params. Because the wrap and verifier change, the server
// bumps the auth epoch, so other devices must re-login (they fetch the new params).
func runPassphraseCalibrate(kc kdfChoice) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	pass, err := promptPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	oldUK, err := crypto.DeriveUnlockKey(pass, prof.Kdf)
	if err != nil {
		return err
	}
	defer oldUK.Wipe()
	rk, err := crypto.UnwrapRoot(prof.WrappedRoot, oldUK)
	if err != nil {
		return errors.New("passphrase is incorrect")
	}
	defer rk.Wipe()

	newKdf, err := kc.resolve()
	if err != nil {
		return err
	}
	if err := rewrapRoot(cl, prof, rk, oldUK, pass, newKdf); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "argon2id re-tuned (time=%d memory=%dMiB threads=%d); other devices must re-login\n",
		newKdf.Time, newKdf.Memory/1024, newKdf.Threads)
	return nil
}

// runRootKeyRotation recovers every content key with the current root, wraps each
// under a newly generated root, and asks the server to switch the full account
// identity in one transaction. Existing convergent objects remain readable because
// their per-object keys live in the sealed roots; future writes derive convergence
// from the new root.
func runRootKeyRotation(assumeYes bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	pass, err := promptPassphrase("Current passphrase: ")
	if err != nil {
		return err
	}
	uk, err := crypto.DeriveUnlockKey(pass, prof.Kdf)
	if err != nil {
		return err
	}
	defer uk.Wipe()
	oldRoot, err := crypto.UnwrapRoot(prof.WrappedRoot, uk)
	if err != nil {
		return errors.New("current passphrase is incorrect")
	}
	defer oldRoot.Wipe()
	// A piped invocation must not silently revoke every other device: without a
	// terminal to confirm on, the rotation requires an explicit -y.
	if !assumeYes {
		if !interactiveStdin() {
			return errors.New("root-key rotation revokes every other device; confirmation required (pass -y to proceed non-interactively)")
		}
		ok, err := promptYesNo("Rotate the account root key and revoke every other device? [y/N] ", false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("root-key rotation cancelled")
		}
	}
	newRoot, err := crypto.GenerateMasterKey()
	if err != nil {
		return err
	}
	defer newRoot.Wipe()
	newWrapped, err := crypto.WrapRoot(newRoot, uk)
	if err != nil {
		return err
	}
	resources, err := cl.ListResources()
	if err != nil {
		return err
	}
	resourceMigrations := make([]api.KeyWrapMigration, 0, len(resources))
	for _, r := range resources {
		if r.WrappedKey == nil {
			continue
		}
		ck, err := crypto.UnwrapKey(*r.WrappedKey, [crypto.KeySize]byte(oldRoot))
		if err != nil {
			return fmt.Errorf("unwrap resource %s: %w", r.ID, err)
		}
		wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(newRoot))
		ck.Wipe()
		if err != nil {
			return fmt.Errorf("rewrap resource %s: %w", r.ID, err)
		}
		resourceMigrations = append(resourceMigrations, api.KeyWrapMigration{ID: r.ID, WrappedKey: wrapped, ExpectedVersion: r.Version})
	}
	snaps, err := cl.ListSnapshots("")
	if err != nil {
		return err
	}
	snapshotMigrations := make([]api.KeyWrapMigration, 0, len(snaps))
	for _, snap := range snaps {
		if snap.WrappedKey == nil {
			continue
		}
		ck, err := crypto.UnwrapKey(*snap.WrappedKey, [crypto.KeySize]byte(oldRoot))
		if err != nil {
			return fmt.Errorf("unwrap snapshot %s: %w", snap.ID, err)
		}
		wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(newRoot))
		ck.Wipe()
		if err != nil {
			return fmt.Errorf("rewrap snapshot %s: %w", snap.ID, err)
		}
		snapshotMigrations = append(snapshotMigrations, api.KeyWrapMigration{ID: snap.ID, WrappedKey: wrapped})
	}
	shares, err := cl.ListShares()
	if err != nil {
		return err
	}
	newEnc := crypto.DeriveEncKey(newRoot).Public()
	grantMigrations := make([]api.GrantKeyMigration, 0, len(shares))
	for _, share := range shares {
		ck, err := crypto.UnwrapGrant(share.WrappedKey, oldRoot, share.ResourceID, share.OwnerHandle, prof.OwnerHandle)
		if err != nil {
			return fmt.Errorf("unwrap incoming grant %s: %w", share.ResourceID, err)
		}
		wrapped, err := crypto.WrapGrant(ck, newEnc, share.ResourceID, share.OwnerHandle, prof.OwnerHandle)
		ck.Wipe()
		if err != nil {
			return fmt.Errorf("rewrap incoming grant %s: %w", share.ResourceID, err)
		}
		grantMigrations = append(grantMigrations, api.GrantKeyMigration{ResourceID: share.ResourceID, OwnerHandle: share.OwnerHandle, WrappedKey: wrapped})
	}
	signing := crypto.DeriveSigningKey(newRoot)
	resp, err := cl.RotateRootKey(api.RootKeyRotationRequest{
		Kdf: prof.Kdf, WrappedRoot: newWrapped, OldAuthVerifier: crypto.DeriveAuthVerifier(uk), NewAuthVerifier: crypto.DeriveAuthVerifier(uk), ExpectedEpoch: prof.AuthEpoch,
		PublicKey: signing.Public().(ed25519.PublicKey), EncPublicKey: newEnc, EncKeySig: crypto.SignEncKey(signing, newEnc),
		Resources: resourceMigrations, Snapshots: snapshotMigrations, IncomingGrants: grantMigrations,
	})
	if errors.Is(err, client.ErrConflict) {
		return errors.New("account data changed while preparing root-key rotation; re-run it")
	}
	if err != nil {
		return err
	}
	prof.Token, prof.WrappedRoot, prof.AuthEpoch = resp.Token, newWrapped, resp.Epoch
	prof.Fingerprint = crypto.KeyFingerprint(signing.Public().(ed25519.PublicKey))
	if err := identity.Save(prof); err != nil {
		return err
	}
	if err := cacheSession(newRoot, defaultSessionTTL); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "account root key rotated; all other devices were revoked and must re-login")
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
