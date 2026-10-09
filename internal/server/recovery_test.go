// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
)

// The server side of a recovery end to end: storing a recovery key needs the
// passphrase proof, the bootstrap serves its wrap, and recovering with it resets the
// passphrase and signs out every earlier device.
func TestRecoveryKeyResetsPassphrase(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	const email = "recover@example.com"
	oldToken, mk := h.signup(email, "forgotten passphrase")
	oldUK, err := crypto.DeriveUnlockKey("forgotten passphrase", h.bootstrap(email).Kdf)
	if err != nil {
		t.Fatal(err)
	}

	key, err := crypto.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	ruk := key.UnlockKey()
	recoveryWrap, err := crypto.WrapRoot(mk, ruk)
	if err != nil {
		t.Fatal(err)
	}
	set := api.RecoveryKeyRequest{WrappedRoot: recoveryWrap, RecoveryVerifier: crypto.DeriveAuthVerifier(ruk), AuthVerifier: make([]byte, 32)}
	if code := h.do(http.MethodPut, "/v1/account/recovery", oldToken, set, nil); code != http.StatusForbidden {
		t.Fatalf("setting a recovery key without the passphrase proof: status %d, want 403", code)
	}
	set.AuthVerifier = crypto.DeriveAuthVerifier(oldUK)
	if code := h.do(http.MethodPut, "/v1/account/recovery", oldToken, set, nil); code != http.StatusNoContent {
		t.Fatalf("set recovery key: status %d, want 204", code)
	}
	boot := h.bootstrap(email)
	if boot.RecoveryWrappedRoot == nil {
		t.Fatal("bootstrap carries no recovery wrap")
	}
	if got, err := crypto.UnwrapRoot(*boot.RecoveryWrappedRoot, ruk); err != nil || got != mk {
		t.Fatalf("the served recovery wrap does not open to the root key: %v", err)
	}

	newKdf := cryptotest.KdfParams(t)
	newUK, err := crypto.DeriveUnlockKey("new passphrase", newKdf)
	if err != nil {
		t.Fatal(err)
	}
	newWrap, err := crypto.WrapRoot(mk, newUK)
	if err != nil {
		t.Fatal(err)
	}
	recoverWith := func(recoveryVerifier []byte) (api.AuthResponse, int) {
		var ch api.ChallengeResponse
		if code := h.do(http.MethodPost, "/v1/auth/challenge", "", api.ChallengeRequest{Email: email}, &ch); code != http.StatusOK {
			t.Fatalf("challenge: status %d", code)
		}
		var resp api.AuthResponse
		code := h.do(http.MethodPost, "/v1/account/recover", "", api.RecoverRequest{
			Email: email, ChallengeID: ch.ChallengeID,
			Signature:        ed25519.Sign(crypto.DeriveSigningKey(mk), ch.Nonce),
			RecoveryVerifier: recoveryVerifier, DeviceName: "rescued",
			Kdf: newKdf, WrappedRoot: newWrap, AuthVerifier: crypto.DeriveAuthVerifier(newUK),
		}, &resp)
		return resp, code
	}
	if _, code := recoverWith(make([]byte, 32)); code != http.StatusUnauthorized {
		t.Fatalf("recovery with a wrong recovery proof: status %d, want 401", code)
	}
	resp, code := recoverWith(crypto.DeriveAuthVerifier(ruk))
	if code != http.StatusCreated {
		t.Fatalf("recovery: status %d, want 201", code)
	}

	if code := h.do(http.MethodGet, "/v1/devices", oldToken, nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("a device from before the recovery still authenticates: status %d", code)
	}
	var devices api.ListDevicesResponse
	if code := h.do(http.MethodGet, "/v1/devices", resp.Token, nil, &devices); code != http.StatusOK || len(devices.Devices) != 1 {
		t.Fatalf("after recovery: status %d, devices %+v; want only the recovered one", code, devices.Devices)
	}
	if boot := h.bootstrap(email); !bytes.Equal(boot.Kdf.Salt, newKdf.Salt) {
		t.Fatal("the bootstrap does not serve the new passphrase's params")
	}
}

// The recovery wrap must not say which accounts exist or which have a recovery key:
// an unknown email and an account without one both get a stable decoy shaped like a
// real wrap.
func TestRecoveryWrapDecoys(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.signup("no-recovery@example.com", "passphrase")
	for _, email := range []string{"no-recovery@example.com", "nobody@example.com"} {
		a, b := h.bootstrap(email), h.bootstrap(email)
		if a.RecoveryWrappedRoot == nil || len(a.RecoveryWrappedRoot.Nonce) != crypto.NonceSize || len(a.RecoveryWrappedRoot.Ciphertext) != crypto.KeySize+16 {
			t.Fatalf("%s: recovery wrap %+v is not shaped like a real one", email, a.RecoveryWrappedRoot)
		}
		if !bytes.Equal(a.RecoveryWrappedRoot.Ciphertext, b.RecoveryWrappedRoot.Ciphertext) {
			t.Fatalf("%s: the decoy changes between requests", email)
		}
	}
}

// Root-key rotation retires the root key a recovery wrap holds, so the wrap must go
// with it rather than later reset the passphrase onto a dead root.
func TestRotateRootKeyClearsRecoveryKey(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "rotate-recovery@example.com")
	deviceID, _, err := s.CreateDevice(owner, "laptop", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	verifier := []byte("recovery proof")
	if err := s.SetRecoveryKey(owner, sealedTestBlob(t, "recovery wrap"), verifier, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RotateRootKey(owner, deviceID, rotateReq(nil)); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	acc, err := s.AccountByEmail("rotate-recovery@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if acc.RecoveryWrappedRoot != nil {
		t.Fatal("the recovery wrap survived root-key rotation")
	}
	if _, _, _, err := s.RecoverAccount(owner, verifier, cryptotest.KdfParams(t), sealedTestBlob(t, "x"), make([]byte, 32), "d"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery after rotation: err = %v, want ErrNotFound", err)
	}
}
