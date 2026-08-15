// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// rotateReq builds a root-key rotation request migrating the given resources, with
// the verifier mustAccount registered and no snapshots or grants.
func rotateReq(migrations []api.KeyWrapMigration) api.RootKeyRotationRequest {
	return api.RootKeyRotationRequest{
		OldAuthVerifier: make([]byte, 32),
		NewAuthVerifier: make([]byte, 32),
		ExpectedEpoch:   1,
		PublicKey:       make([]byte, 32),
		EncPublicKey:    make([]byte, 32),
		EncKeySig:       make([]byte, 64),
		Resources:       migrations,
	}
}

// A resource write that read its version before a root-key rotation must lose the
// race, not commit a wrapped_key sealed under the destroyed old root (issue #178).
// Rotation bumps every migrated resource's version inside its transaction, so the
// stale writer's version predicate fails with ErrVersionConflict.
func TestRotationDefeatsInFlightResourceWrite(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "rotate@example.com")
	deviceID, _, err := s.CreateDevice(owner, "laptop", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, nil)

	// An in-flight writer reads version 1 here, then stalls while the rotation
	// commits. Its later commit must fail the version predicate.
	staleVersion := 1

	if _, _, err := s.RotateRootKey(owner, deviceID, rotateReq([]api.KeyWrapMigration{
		{ID: rid, WrappedKey: wrappedTestKey(t), ExpectedVersion: 1},
	})); err != nil {
		t.Fatalf("rotation: %v", err)
	}

	staleWrap := wrappedTestKey(t)
	_, _, err = s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		ID: rid, ExpectedVersion: staleVersion, Visibility: api.Private,
		Blob:          sealedTestBlob(t, "post-rotation write"),
		EncryptedMeta: sealedTestBlob(t, `{"name":"folder","size":0}`),
		WrappedKey:    &staleWrap,
	})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale-epoch write after rotation: err = %v, want ErrVersionConflict", err)
	}

	// The migrated wrap survived and the bumped version is what readers see.
	res, err := s.GetResource(rid, owner)
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != 2 {
		t.Errorf("post-rotation version = %d, want 2", res.Version)
	}
}

// The reverse interleaving: a write that commits before the rotation invalidates
// the rotation's enumerated versions, so the rotation must fail (and be re-run
// against fresh state) rather than overwrite the newer wrap.
func TestRotationLosesToCommittedWrite(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "rotate-loses@example.com")
	deviceID, _, err := s.CreateDevice(owner, "laptop", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	rid := s.rootResource(t, owner, nil)

	// The rotation enumerated version 1; this write bumps it to 2 first.
	newWrap := wrappedTestKey(t)
	if _, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		ID: rid, ExpectedVersion: 1, Visibility: api.Private,
		Blob:          sealedTestBlob(t, "concurrent reseal"),
		EncryptedMeta: sealedTestBlob(t, `{"name":"folder","size":0}`),
		WrappedKey:    &newWrap,
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err = s.RotateRootKey(owner, deviceID, rotateReq([]api.KeyWrapMigration{
		{ID: rid, WrappedKey: wrappedTestKey(t), ExpectedVersion: 1},
	}))
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("rotation over a newer write: err = %v, want ErrVersionConflict", err)
	}
}

func wrappedTestKey(t *testing.T) crypto.WrappedKey {
	t.Helper()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func sealedTestBlob(t *testing.T, plaintext string) crypto.SealedBlob {
	t.Helper()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.Seal([]byte(plaintext), ck, crypto.AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}
