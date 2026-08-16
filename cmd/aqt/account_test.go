// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// fakeAccountClient records whether the erasure was actually reached, so a test
// can assert that a refused confirmation or a bad passphrase stops before it.
type fakeAccountClient struct {
	usage   api.UsageResponse
	deletes int
}

func (f *fakeAccountClient) Usage() (api.UsageResponse, error) { return f.usage, nil }

func (f *fakeAccountClient) DeleteAccount(api.DeleteAccountRequest) (api.DeleteAccountResponse, error) {
	f.deletes++
	return api.DeleteAccountResponse{}, nil
}

// accountProfile builds a profile whose wrapped root really opens with pass, which
// is what the local passphrase check reads.
func accountProfile(t *testing.T, email, pass string) *identity.Profile {
	t.Helper()
	kdf := cryptotest.KdfParams(t)
	uk, err := crypto.DeriveUnlockKey(pass, kdf)
	if err != nil {
		t.Fatal(err)
	}
	defer uk.Wipe()
	rk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	defer rk.Wipe()
	wrapped, err := crypto.WrapRoot(rk, uk)
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Profile{Name: identity.DefaultProfile, Email: email, Kdf: kdf, WrappedRoot: wrapped}
}

func TestAccountDeleteConfirmationRequiresTypedEmail(t *testing.T) {
	cl := &fakeAccountClient{usage: api.UsageResponse{StorageBytes: 4096, Resources: 3}}

	withStdin(t, "y\n")
	if err := confirmAccountDelete("owner@example.com", cl); err == nil || err.Error() != "aborted" {
		t.Fatalf("a bare yes confirmed the deletion: %v", err)
	}

	withStdin(t, "owner@example.com\n")
	if err := confirmAccountDelete("owner@example.com", cl); err != nil {
		t.Fatalf("typing the email did not confirm: %v", err)
	}
}

// A mistyped passphrase must fail against the local wrapped root, so the request
// that cannot be undone is never sent on the strength of a typo.
func TestAccountDeleteProofRejectsWrongPassphrase(t *testing.T) {
	const email, pass = "owner@example.com", "correct horse battery staple"
	prof := accountProfile(t, email, pass)
	cl := &fakeAccountClient{}

	withStdin(t, "not the passphrase\n")
	if _, err := accountDeleteProof(prof, true, cl); err == nil {
		t.Fatal("a wrong passphrase produced a proof")
	}
	if cl.deletes != 0 {
		t.Fatalf("erasure reached the server %d times on a wrong passphrase", cl.deletes)
	}
}

// A piped run with nothing on stdin supplied no passphrase; reporting it as an
// incorrect one sends the caller hunting for a typo instead of the missing input.
func TestAccountDeleteProofRejectsEmptyPassphrase(t *testing.T) {
	prof := accountProfile(t, "owner@example.com", "correct horse battery staple")

	withStdin(t, "")
	_, err := accountDeleteProof(prof, true, &fakeAccountClient{})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("empty passphrase err = %v, want a missing-passphrase error", err)
	}
}

func TestAccountDeleteProofDerivesTheAuthVerifier(t *testing.T) {
	const email, pass = "owner@example.com", "correct horse battery staple"
	prof := accountProfile(t, email, pass)

	withStdin(t, email+"\n"+pass+"\n")
	got, err := accountDeleteProof(prof, false, &fakeAccountClient{})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	uk, err := crypto.DeriveUnlockKey(pass, prof.Kdf)
	if err != nil {
		t.Fatal(err)
	}
	defer uk.Wipe()
	if want := crypto.DeriveAuthVerifier(uk); !bytes.Equal(got, want) {
		t.Fatal("proof is not the account's auth verifier")
	}
}

// --yes exists for scripts, but it must not also skip the passphrase: that would
// make a leaked token sufficient to erase the account.
func TestAccountDeleteYesStillRequiresThePassphrase(t *testing.T) {
	const email, pass = "owner@example.com", "correct horse battery staple"
	prof := accountProfile(t, email, pass)

	withStdin(t, pass+"\n")
	got, err := accountDeleteProof(prof, true, &fakeAccountClient{})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("--yes produced an empty proof")
	}
}

// The byte total is the number the user confirmed against. When the server could
// not read one it sends none, and the receipt has to stay silent rather than print
// a 0 the server never claimed.
func TestAccountDeleteReceiptOmitsAnUnknownTotal(t *testing.T) {
	var out, errOut bytes.Buffer
	r := api.DeleteAccountResponse{Resources: 2, Devices: 1}
	if err := printAccountDeleteReceipt(&out, &errOut, r, "owner@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "storage") {
		t.Fatalf("receipt invented a storage total:\n%s", out.String())
	}

	total := int64(4096)
	out.Reset()
	r.Bytes = &total
	if err := printAccountDeleteReceipt(&out, &errOut, r, "owner@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "4.0 KB") {
		t.Fatalf("receipt did not report the total it was given:\n%s", out.String())
	}
}

// Ciphertext left on the server outlives the account, so a clean-looking receipt
// would be the one place this could hide.
func TestAccountDeleteReceiptWarnsAboutFilesLeftBehind(t *testing.T) {
	var out, errOut bytes.Buffer
	r := api.DeleteAccountResponse{Resources: 1, FileErrors: 3}
	if err := printAccountDeleteReceipt(&out, &errOut, r, "owner@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	warning := errOut.String()
	if !strings.Contains(warning, "3 stored files could not be removed") {
		t.Fatalf("no warning about files left on the server:\n%s", warning)
	}
	if !strings.Contains(warning, "operator") {
		t.Fatalf("warning does not say who to ask:\n%s", warning)
	}

	errOut.Reset()
	r.FileErrors = 0
	if err := printAccountDeleteReceipt(&out, &errOut, r, "owner@example.com", true, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errOut.String(), "warning") {
		t.Fatalf("clean erasure warned anyway:\n%s", errOut.String())
	}
}

// A failed local cleanup must not swallow the receipt: the erasure already happened
// and cannot be repeated, so its file warning has nowhere else to be reported. The
// line claiming the local profile went too has to drop instead, since that is the
// one part of the receipt this client is the authority on.
func TestAccountDeleteReceiptSurvivesAFailedLocalCleanup(t *testing.T) {
	var out, errOut bytes.Buffer
	r := api.DeleteAccountResponse{Resources: 1, FileErrors: 2}
	if err := printAccountDeleteReceipt(&out, &errOut, r, "owner@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "2 stored files could not be removed") {
		t.Fatalf("file warning lost when the local profile stayed:\n%s", errOut.String())
	}
	if strings.Contains(errOut.String(), "local profile") {
		t.Fatalf("receipt claimed a local removal that failed:\n%s", errOut.String())
	}
}

// Without a terminal and without --yes there is no way to answer the prompt, so
// the command must say so rather than block or delete unconfirmed.
func TestAccountDeleteRefusesUnconfirmableRun(t *testing.T) {
	withStdin(t, "")
	err := runAccountDelete(false, false)
	if err == nil {
		t.Fatal("a non-interactive run without --yes was allowed to proceed")
	}
	if !errors.Is(err, cliutil.ErrNotConfirmable) {
		t.Fatalf("error = %v, want the not-confirmable refusal", err)
	}
}
