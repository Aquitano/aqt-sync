// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"net/http"
	"os"
	"runtime"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// authVerifier re-derives the passphrase proof for an account the way a client
// does: from the KDF params the bootstrap endpoint publishes.
func (h *harness) authVerifier(email, passphrase string) []byte {
	h.t.Helper()
	boot := h.bootstrap(email)
	uk, err := crypto.DeriveUnlockKey(passphrase, boot.Kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	defer uk.Wipe()
	return crypto.DeriveAuthVerifier(uk)
}

// A device token is not authority to destroy the account it belongs to. A token can
// leak — from a stolen laptop, a backup, a CI secret — and this is the one operation
// no restore undoes, so it takes the passphrase as well.
func TestAccountDeleteRequiresPassphraseProof(t *testing.T) {
	t.Parallel()
	const email, pass = "erase@example.com", "correct horse battery staple"
	h := newHarness(t)
	token, mk := h.signup(email, pass)
	if _, code := h.putSized(token, mk, "", 32); code != http.StatusCreated {
		t.Fatalf("seed resource = %d, want 201", code)
	}

	if code := h.do(http.MethodDelete, "/v1/account", token, api.DeleteAccountRequest{}, nil); code != http.StatusBadRequest {
		t.Fatalf("delete with no proof = %d, want 400", code)
	}
	wrong := h.authVerifier(email, "not the passphrase")
	if code := h.do(http.MethodDelete, "/v1/account", token, api.DeleteAccountRequest{AuthVerifier: wrong}, nil); code != http.StatusForbidden {
		t.Fatalf("delete with a wrong proof = %d, want 403", code)
	}

	// Both refusals must leave the account entirely intact, not partly erased.
	var usage api.UsageResponse
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, &usage); code != http.StatusOK {
		t.Fatalf("usage after refused deletes = %d, want 200", code)
	}
	if usage.Resources != 1 {
		t.Fatalf("resources = %d after refused deletes, want 1", usage.Resources)
	}
}

func TestAccountDeleteErasesAccountAndRevokesToken(t *testing.T) {
	t.Parallel()
	const email, pass = "gone@example.com", "correct horse battery staple"
	h := newHarness(t)
	token, mk := h.signup(email, pass)
	if _, code := h.putSized(token, mk, "", 128); code != http.StatusCreated {
		t.Fatalf("seed resource = %d, want 201", code)
	}

	var usage api.UsageResponse
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, &usage); code != http.StatusOK {
		t.Fatalf("usage = %d, want 200", code)
	}

	var receipt api.DeleteAccountResponse
	code := h.do(http.MethodDelete, "/v1/account", token,
		api.DeleteAccountRequest{AuthVerifier: h.authVerifier(email, pass)}, &receipt)
	if code != http.StatusOK {
		t.Fatalf("delete = %d, want 200", code)
	}
	if receipt.Resources != 1 || receipt.Devices != 1 {
		t.Fatalf("receipt = %+v, want 1 resource and 1 device", receipt)
	}
	// The receipt must quote the same total `aqt usage` did a moment earlier, not
	// just the unlinked ciphertext files: a user who confirmed against one number
	// and is shown a much smaller one has been told the account partly survived.
	if receipt.Bytes == nil {
		t.Fatal("receipt omits the storage total after a readable usage query")
	}
	if *receipt.Bytes != usage.StorageBytes {
		t.Fatalf("receipt freed %d bytes, usage reported %d", *receipt.Bytes, usage.StorageBytes)
	}
	if receipt.FileErrors != 0 {
		t.Fatalf("receipt reports %d file errors on a clean erasure", receipt.FileErrors)
	}

	// The token authenticated a moment ago and must stop now, not at the auth
	// cache's TTL.
	if code := h.do(http.MethodGet, "/v1/account/usage", token, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("usage with the deleted account's token = %d, want 401", code)
	}
	if _, err := h.store.AccountByEmail(email); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AccountByEmail after deletion = %v, want ErrNotFound", err)
	}
	// The email is free again, which is what makes this a deletion rather than a
	// suspension.
	h.signup(email, "a different passphrase")
}

// The proof is checked against the account being deleted, so one account's
// passphrase cannot erase another's.
func TestAccountDeleteRejectsAnotherAccountsProof(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	victimToken, _ := h.signup("victim@example.com", "victim passphrase here")
	h.signup("attacker@example.com", "attacker passphrase here")

	stolen := h.authVerifier("attacker@example.com", "attacker passphrase here")
	if code := h.do(http.MethodDelete, "/v1/account", victimToken, api.DeleteAccountRequest{AuthVerifier: stolen}, nil); code != http.StatusForbidden {
		t.Fatalf("delete with another account's proof = %d, want 403", code)
	}
	if _, err := h.store.AccountByEmail("victim@example.com"); err != nil {
		t.Fatalf("victim account after the refused delete: %v", err)
	}
}

// A file the server could not unlink means the account's ciphertext is still on the
// operator's disk. The rows are gone either way, so the deletion still succeeds —
// but the person who asked to be erased is the one who needs to know, and the count
// is the part of it that is theirs (the paths are the operator's).
func TestAccountDeleteReportsUnremovableFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows Chmod carries only the write bit, so a directory that denies unlink is not representable")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not apply")
	}
	const email, pass = "stuck@example.com", "correct horse battery staple"
	h := newHarness(t)
	token, mk := h.signup(email, pass)
	res, code := h.putSized(token, mk, "", 64)
	if code != http.StatusCreated {
		t.Fatalf("seed resource = %d, want 201", code)
	}

	// Removing a file needs write permission on its directory, not the file.
	dir := h.store.blobDir(res.ID)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod blob dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var receipt api.DeleteAccountResponse
	if code := h.do(http.MethodDelete, "/v1/account", token,
		api.DeleteAccountRequest{AuthVerifier: h.authVerifier(email, pass)}, &receipt); code != http.StatusOK {
		t.Fatalf("delete = %d, want 200", code)
	}
	if receipt.FileErrors == 0 {
		t.Fatal("receipt reports a clean erasure while a blob could not be removed")
	}
	// Prove the scenario is real rather than just the counter moving: the ciphertext
	// is still there, which is exactly what the warning exists to tell the user.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) == 0 {
		t.Fatalf("blob dir has %d entries (err=%v); the removal did not actually fail", len(entries), err)
	}
	if _, err := h.store.AccountByEmail(email); !errors.Is(err, ErrNotFound) {
		t.Fatalf("account survived an erasure that could not unlink a file: %v", err)
	}
}

// Suspension is how an operator holds an account (legal hold, billing dispute), so
// it has to hold against the account's own erasure too, not just its writes.
func TestSuspendedAccountCannotSelfDelete(t *testing.T) {
	t.Parallel()
	const email, pass = "held@example.com", "correct horse battery staple"
	h := newHarness(t)
	token, _ := h.signup(email, pass)
	verifier := h.authVerifier(email, pass)

	owner, err := h.store.OwnerByToken(token)
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	if err := h.store.SetAccountDisabled(owner, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if code := h.do(http.MethodDelete, "/v1/account", token, api.DeleteAccountRequest{AuthVerifier: verifier}, nil); code != http.StatusForbidden {
		t.Fatalf("suspended self-delete = %d, want 403", code)
	}
	if _, err := h.store.AccountByEmail(email); err != nil {
		t.Fatalf("suspended account after the refused delete: %v", err)
	}
}

// The middleware's suspension check answers from a cache an operator suspending in
// another process cannot invalidate, so for up to suspensionTTL a held account still
// reaches the handler. Every other route survives that window; an erasure would not,
// so the store re-reads the flag in the deleting transaction. Calling the store
// directly is the window: it is what a request that passed a stale cache reaches.
func TestSuspendedSelfDeleteIsRefusedBelowTheAuthCache(t *testing.T) {
	t.Parallel()
	const email, pass = "stale-cache@example.com", "correct horse battery staple"
	h := newHarness(t)
	token, _ := h.signup(email, pass)
	verifier := h.authVerifier(email, pass)

	owner, err := h.store.OwnerByToken(token)
	if err != nil {
		t.Fatalf("resolve owner: %v", err)
	}
	if err := h.store.SetAccountDisabled(owner, true); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := h.store.DeleteAccountWithProof(owner, verifier); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("suspended self-delete = %v, want ErrAccountDisabled", err)
	}
	if _, err := h.store.AccountByEmail(email); err != nil {
		t.Fatalf("suspended account after the refused delete: %v", err)
	}
	// The operator path carries no proof and must still erase a suspended account:
	// suspending before deleting is the usual order of those two commands.
	if _, err := h.store.DeleteAccount(owner); err != nil {
		t.Fatalf("operator delete of a suspended account: %v", err)
	}
	if _, err := h.store.AccountByEmail(email); !errors.Is(err, ErrNotFound) {
		t.Fatalf("account survived the operator deletion: %v", err)
	}
}

// DeleteAccountWithProof is the only erasure path a request handler may reach, so
// an empty verifier must refuse rather than fall through to the operator path.
func TestDeleteAccountWithProofRefusesEmptyVerifier(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "empty-proof@example.com")

	if _, err := s.DeleteAccountWithProof(owner, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil verifier = %v, want ErrNotFound", err)
	}
	if _, err := s.DeleteAccountWithProof(owner, []byte{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty verifier = %v, want ErrNotFound", err)
	}
	if _, err := s.AccountByEmail("empty-proof@example.com"); err != nil {
		t.Fatalf("account after refused deletes: %v", err)
	}
}
