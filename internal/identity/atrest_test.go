// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"bytes"
	"errors"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestSealBaseRoundTripKeychain(t *testing.T) {
	isolateConfigDir(t)
	plain := []byte("base-manifest-bytes-with-secrets")
	blob, err := SealBase("default", plain)
	if err != nil {
		t.Fatalf("SealBase: %v", err)
	}
	got, err := OpenBase("default", blob)
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestSealBaseRoundTripMachineBound(t *testing.T) {
	isolateConfigDir(t)
	forceNoKeychain(t)
	plain := []byte("base-manifest-no-keychain")
	blob, err := SealBase("default", plain)
	if err != nil {
		t.Fatalf("SealBase: %v", err)
	}
	got, err := OpenBase("default", blob)
	if err != nil {
		t.Fatalf("OpenBase: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestOpenBaseRejectsForeignProfile(t *testing.T) {
	isolateConfigDir(t)
	blob, err := SealBase("alice", []byte("alice-base"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBase("bob", blob); !errors.Is(err, ErrBaseSeal) {
		t.Fatalf("OpenBase under a foreign profile = %v, want ErrBaseSeal", err)
	}
}

// A base blob and a session blob share the sealing key, so the AAD is the only
// thing separating them; OpenBase must reject a session-domain ciphertext.
func TestOpenBaseRejectsSessionDomainBlob(t *testing.T) {
	isolateConfigDir(t)
	key := saveSealingKey("default")
	sessionBlob, err := crypto.Seal([]byte("cached master key"), key, []byte(sessionAAD))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBase("default", sessionBlob); !errors.Is(err, ErrBaseSeal) {
		t.Fatalf("OpenBase on a session-domain blob = %v, want ErrBaseSeal", err)
	}
}
