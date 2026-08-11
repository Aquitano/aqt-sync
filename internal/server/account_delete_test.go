package server

import (
	"errors"
	"net/http"
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
	if receipt.Bytes != usage.StorageBytes {
		t.Fatalf("receipt freed %d bytes, usage reported %d", receipt.Bytes, usage.StorageBytes)
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

// Suspension is how an operator holds an account (legal hold, billing dispute), so
// it has to hold against the account's own erasure too, not just its writes.
func TestSuspendedAccountCannotSelfDelete(t *testing.T) {
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

// DeleteAccountWithProof is the only erasure path a request handler may reach, so
// an empty verifier must refuse rather than fall through to the operator path.
func TestDeleteAccountWithProofRefusesEmptyVerifier(t *testing.T) {
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
