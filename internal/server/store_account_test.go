// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"testing"
	"time"
)

// A reclaimed tombstone holds no ciphertext, so it must stop counting toward
// the modeled quota; otherwise a delete-heavy account sits over quota with no
// way to recover.
func TestAccountUsageExcludesReclaimedTombstones(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "tombstone@example.com")
	base, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("public body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"p","size":11}`), ck, crypto.AADMeta)
	if _, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Public, Blob: blob, EncryptedMeta: meta, ExpireSeconds: 1}); err != nil {
		t.Fatal(err)
	}
	live, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	if live.StorageBytes <= base.StorageBytes {
		t.Fatalf("live usage %d not above baseline %d", live.StorageBytes, base.StorageBytes)
	}
	if _, err := s.SweepExpired(owner, time.Now().Unix()+2); err != nil {
		t.Fatal(err)
	}
	after, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatal(err)
	}
	if after.StorageBytes != base.StorageBytes {
		t.Fatalf("usage after reclaim = %d, want baseline %d", after.StorageBytes, base.StorageBytes)
	}
}

// A share block is the store-level guarantee behind `aqt shares rm --block`:
// registration is open, so without it the account that appended a row to someone's
// share list is also the only one able to keep it out.
func TestShareBlockRefusesFurtherGrants(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "sender@example.com")
	grantee := s.mustAccount(t, "recipient@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	put := func(name string) string {
		blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"`+name+`","size":4}`), ck, crypto.AADMeta)
		id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first, second := put("first"), put("second")
	for _, id := range []string{first, second} {
		if err := s.PutGrant(owner, id, grantee, []byte("wrap"), nil); err != nil {
			t.Fatal(err)
		}
	}

	// A removal without a block takes one row and leaves the sender free to re-grant.
	if _, removed, err := s.DeleteShare(grantee, first, false); err != nil || removed != 1 {
		t.Fatalf("DeleteShare = (%d, %v), want (1, nil)", removed, err)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); err != nil {
		t.Fatalf("re-grant after a plain removal: %v", err)
	}

	gotOwner, removed, err := s.DeleteShare(grantee, first, true)
	if err != nil {
		t.Fatalf("DeleteShare with block: %v", err)
	}
	if gotOwner != owner {
		t.Fatalf("blocked owner = %q, want %q", gotOwner, owner)
	}
	// Blocking clears the sender's other shares too, not only the named one.
	if removed != 2 {
		t.Fatalf("removed = %d, want both of the sender's shares", removed)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); !errors.Is(err, ErrSenderBlocked) {
		t.Fatalf("grant from a blocked sender = %v, want ErrSenderBlocked", err)
	}
	// The block is per-pair: another account is unaffected.
	third := s.mustAccount(t, "someone-else@example.com")
	if err := s.PutGrant(owner, first, third, []byte("wrap"), nil); err != nil {
		t.Fatalf("grant to an unrelated account: %v", err)
	}

	blocks, _, err := s.ListShareBlocks(grantee, pageParams{})
	if err != nil || len(blocks) != 1 || blocks[0].OwnerHandle != owner {
		t.Fatalf("ListShareBlocks = (%+v, %v), want one block on %s", blocks, err, owner)
	}
	if err := s.DeleteShareBlock(grantee, owner); err != nil {
		t.Fatalf("DeleteShareBlock: %v", err)
	}
	if err := s.DeleteShareBlock(grantee, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lifting a lifted block = %v, want ErrNotFound", err)
	}
	if err := s.PutGrant(owner, first, grantee, []byte("wrap"), nil); err != nil {
		t.Fatalf("grant after the block was lifted: %v", err)
	}
}

// The delete predicate is the caller's own grantee handle: a third account must not
// be able to strip somebody else's access (or block a sender on their behalf).
func TestDeleteShareIsGranteeScoped(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "owner@example.com")
	grantee := s.mustAccount(t, "grantee@example.com")
	stranger := s.mustAccount(t, "stranger@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	blob, _ := crypto.Seal([]byte("body"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutGrant(owner, id, grantee, []byte("wrap"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DeleteShare(stranger, id, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger removing another account's share = %v, want ErrNotFound", err)
	}
	shares, _, err := s.ListShares(grantee, pageParams{})
	if err != nil || len(shares) != 1 {
		t.Fatalf("ListShares = (%+v, %v), want the grant intact", shares, err)
	}
	blocks, _, err := s.ListShareBlocks(stranger, pageParams{})
	if err != nil || len(blocks) != 0 {
		t.Fatalf("ListShareBlocks = (%+v, %v), want no block recorded", blocks, err)
	}
}
