// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Email casing must select the same account and salt and prevent duplicate signup.
func TestEmailLookupsFoldCase(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.signup("case@example.com", "a passphrase for case folding")

	real, err := h.store.AccountByEmail("case@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cased, err := h.store.AccountByEmail("CaSe@Example.COM")
	if err != nil {
		t.Fatalf("cased lookup got the decoy path: %v", err)
	}
	if cased.OwnerHandle != real.OwnerHandle {
		t.Fatalf("cased lookup resolved a different account: %s != %s", cased.OwnerHandle, real.OwnerHandle)
	}
	if owner, _, _, _, err := h.store.AccountForAuth("CASE@EXAMPLE.COM"); err != nil || owner != real.OwnerHandle {
		t.Fatalf("AccountForAuth cased: %v owner=%s", err, owner)
	}

	// The salt endpoint answers any casing with the real account's wrap.
	var upper, lower api.SaltResponse
	if code := h.do(http.MethodGet, "/v1/account/salt?email=case@example.com", "", nil, &lower); code != http.StatusOK {
		t.Fatalf("salt lower: %d", code)
	}
	if code := h.do(http.MethodGet, "/v1/account/salt?email=Case@EXAMPLE.com", "", nil, &upper); code != http.StatusOK {
		t.Fatalf("salt upper: %d", code)
	}
	if string(upper.WrappedRoot.Ciphertext) != string(lower.WrappedRoot.Ciphertext) {
		t.Fatal("salt response differs by email casing")
	}

	// A mixed-case twin of the same mailbox must be refused.
	kdf := lower.Kdf
	if _, err := h.store.CreateAccount("CASE@example.com", kdf, make([]byte, 32),
		crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)}, make([]byte, 32), nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("mixed-case twin signup: err = %v, want ErrConflict", err)
	}
}

// Unknown emails keep one stable decoy per mailbox: if the decoy varied by casing
// while real accounts answered any casing identically, case-stable salts would out
// an email as registered.
func TestDecoySaltStableAcrossCase(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	var a, b api.SaltResponse
	if code := h.do(http.MethodGet, "/v1/account/salt?email=nobody@example.com", "", nil, &a); code != http.StatusOK {
		t.Fatalf("decoy lower: %d", code)
	}
	if code := h.do(http.MethodGet, "/v1/account/salt?email=NoBody@Example.com", "", nil, &b); code != http.StatusOK {
		t.Fatalf("decoy upper: %d", code)
	}
	if string(a.WrappedRoot.Ciphertext) != string(b.WrappedRoot.Ciphertext) {
		t.Fatal("decoy salt differs by email casing")
	}
}

// The signup decoy exists so a duplicate signup does not confirm an address. It must
// still tell the account's actual owner what happened, since someone presenting the
// account's own passphrase verifier already has everything the answer would leak.
func TestDuplicateSignupConfirmsOnlyToTheOwner(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	req := createReq(t, "dup@example.com", "a passphrase here")
	var first api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", req, &first); code != http.StatusCreated {
		t.Fatalf("signup = %d", code)
	}

	// Same passphrase: the caller owns the account, so it is named plainly.
	var owned api.ErrorResponse
	if code := h.do(http.MethodPost, "/v1/account", "", req, &owned); code != http.StatusConflict {
		t.Fatalf("duplicate signup with the right passphrase = %d, want 409", code)
	}
	if owned.Code != api.ErrCodeAccountExists {
		t.Fatalf("error code = %q, want %q", owned.Code, api.ErrCodeAccountExists)
	}

	// Different passphrase: indistinguishable from a fresh signup.
	other := createReq(t, "dup@example.com", "a different passphrase")
	var decoy api.AuthResponse
	if code := h.do(http.MethodPost, "/v1/account", "", other, &decoy); code != http.StatusCreated {
		t.Fatalf("duplicate signup with the wrong passphrase = %d, want the 201 decoy", code)
	}
	if decoy.Token == first.Token || decoy.OwnerHandle == first.OwnerHandle {
		t.Fatal("the decoy leaked the real account's credentials")
	}
	if len(decoy.OwnerHandle) != len(first.OwnerHandle) || len(decoy.Token) != len(first.Token) {
		t.Fatal("the decoy is distinguishable from a real response by field length")
	}
}
