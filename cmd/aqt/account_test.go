package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
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
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		t.Fatal(err)
	}
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

// Without a terminal and without --yes there is no way to answer the prompt, so
// the command must say so rather than block or delete unconfirmed.
func TestAccountDeleteRefusesUnconfirmableRun(t *testing.T) {
	withStdin(t, "")
	err := runAccountDelete(false, false)
	if err == nil {
		t.Fatal("a non-interactive run without --yes was allowed to proceed")
	}
	if !errors.Is(err, errNotConfirmable) {
		t.Fatalf("error = %v, want the not-confirmable refusal", err)
	}
}
