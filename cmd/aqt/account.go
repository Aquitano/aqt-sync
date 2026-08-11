package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func accountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Manage your account on the server",
	}

	var yes bool
	del := &cobra.Command{
		Use:     "delete",
		Aliases: []string{"unregister"},
		Short:   "Erase your account and everything stored under it (cannot be undone)",
		Args:    cobra.NoArgs,
		RunE:    func(cmd *cobra.Command, args []string) error { return runAccountDelete(yes, flagJSON) },
	}
	del.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(del)
	cmd.AddCommand(del)

	return cmd
}

// accountDeleteClient is the server surface an erasure touches: the usage summary
// shown before the confirmation, and the erasure itself.
type accountDeleteClient interface {
	Usage() (api.UsageResponse, error)
	DeleteAccount(api.DeleteAccountRequest) (api.DeleteAccountResponse, error)
}

// runAccountDelete erases the account this profile belongs to. The passphrase is
// checked locally against the stored wrapped root before anything is sent, so a
// typo fails without a round trip, and the verifier derived from it is what
// actually authorizes the erasure server-side.
func runAccountDelete(assumeYes, asJSON bool) error {
	// Fail before any auth or network work if a confirmation could never be answered.
	if err := requireConfirmable(assumeYes); err != nil {
		return err
	}
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	verifier, err := accountDeleteProof(prof, assumeYes, cl)
	if err != nil {
		return err
	}
	receipt, err := cl.DeleteAccount(api.DeleteAccountRequest{AuthVerifier: verifier})
	if errors.Is(err, client.ErrNotFound) {
		return errors.New("this server does not support self-service account deletion; ask its operator to erase the account")
	}
	if err != nil {
		return err
	}
	// The account is gone server-side; the local profile now names nothing. Remove it
	// even though the caller may be scripting, since leaving it strands a dead token.
	if err := identity.Delete(prof.Name); err != nil {
		return fmt.Errorf("account deleted, but removing the local profile failed: %w", err)
	}
	return printAccountDeleteReceipt(receipt, prof.Email, asJSON)
}

// accountDeleteProof runs the confirmation and returns the auth verifier that
// authorizes the erasure.
func accountDeleteProof(prof *identity.Profile, assumeYes bool, cl accountDeleteClient) ([]byte, error) {
	if !assumeYes {
		if err := confirmAccountDelete(prof.Email, cl); err != nil {
			return nil, err
		}
	}
	pass, err := promptPassphrase("Passphrase: ")
	if err != nil {
		return nil, err
	}
	uk, err := crypto.DeriveUnlockKey(pass, prof.Kdf)
	if err != nil {
		return nil, err
	}
	defer uk.Wipe()
	// Unwrapping the local wrapped root proves the passphrase without a round trip,
	// so a typo cannot reach an endpoint whose failure mode is irreversible.
	rk, err := crypto.UnwrapRoot(prof.WrappedRoot, uk)
	if err != nil {
		return nil, errors.New("passphrase is incorrect")
	}
	rk.Wipe()
	return crypto.DeriveAuthVerifier(uk), nil
}

// confirmAccountDelete shows what the account currently holds and requires the
// email to be typed back. A y/N prompt is too easy to answer on reflex for the one
// operation with nothing behind it: the server holds no plaintext and keeps no
// copy, so nothing survives this.
func confirmAccountDelete(email string, cl accountDeleteClient) error {
	if u, err := cl.Usage(); err == nil {
		fmt.Fprintf(os.Stderr, "%s holds %s across %d resources and %d snapshots on %d devices.\n",
			email, humanBytes(u.StorageBytes), u.Resources, u.Snapshots, u.Devices)
	}
	fmt.Fprintln(os.Stderr, "Deleting the account erases all of it. There is no backup and no undo.")
	fmt.Fprintln(os.Stderr, "Shares you granted stop resolving, and grants others made to you are dropped.")
	fmt.Fprintln(os.Stderr, "Files already on this machine stay; folders you sync keep their local copies.")
	typed, err := promptLine(fmt.Sprintf("Type %s to confirm: ", email))
	if err != nil {
		return err
	}
	if typed != email {
		return errors.New("aborted")
	}
	return nil
}

func printAccountDeleteReceipt(r api.DeleteAccountResponse, email string, asJSON bool) error {
	if asJSON {
		return printJSON(r)
	}
	fmt.Fprintf(os.Stderr, "%s deleted; local profile and cached key removed\n", email)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "storage freed\t%s\n", humanBytes(r.Bytes))
	fmt.Fprintf(w, "resources\t%d\n", r.Resources)
	fmt.Fprintf(w, "snapshots\t%d\n", r.Snapshots)
	fmt.Fprintf(w, "packs\t%d\n", r.Packs)
	fmt.Fprintf(w, "objects\t%d\n", r.Objects)
	fmt.Fprintf(w, "grants\t%d\n", r.Grants)
	fmt.Fprintf(w, "devices\t%d\n", r.Devices)
	return w.Flush()
}
