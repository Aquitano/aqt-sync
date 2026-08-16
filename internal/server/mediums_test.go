// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Emails are one mailbox regardless of casing. The server used to binary-collate,
// so `User@X.com` got the decoy salt (and a "wrong passphrase" dead end) and
// mixed-case twins of one mailbox could coexist (issue #183, email case).
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

// A row whose blob file is missing is an internal inconsistency, not a 404: the
// read path retries once (covering the update-unlink race) and then surfaces a
// distinct error for a resource whose row plainly exists (issue #183, transient 404).
func TestMissingBlobIsNotA404(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	owner := h.store.mustAccount(t, "staleblob@example.com")
	rid := h.store.rootResource(t, owner, nil)

	res, err := h.store.GetResource(rid, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.store.blobPath(rid, res.Blob.Nonce)); err != nil {
		t.Fatal(err)
	}
	_, err = h.store.GetResource(rid, owner)
	if err == nil {
		t.Fatal("read of a blobless row succeeded")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("blobless row surfaced as 404: %v", err)
	}
}

// A reclaimed tombstone must be visible on the wire (Reclaimed flag in the list)
// and immutable except for rm/re-push: SetVisibility used to lack the reclaimed
// guard its sibling mutations have, resetting read counters over a corpse.
func TestReclaimedTombstoneVisibleAndGuarded(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	owner := h.store.mustAccount(t, "tombstone@example.com")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("sealed"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	rid, _, err := h.store.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ExpireSeconds: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sweep well past expiry and grace so the link is reclaimed.
	if n, err := h.store.SweepExpired(owner, time.Now().Add(24*time.Hour).Unix()); err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}

	items, _, err := h.store.ListResources(owner, pageParams{})
	if err != nil {
		t.Fatal(err)
	}
	var found *api.ResourceListItem
	for i := range items {
		if items[i].ID == rid {
			found = &items[i]
		}
	}
	if found == nil {
		t.Fatal("tombstone missing from the owner's list")
	}
	if !found.Reclaimed {
		t.Fatal("tombstone not marked reclaimed on the wire")
	}

	if _, err := h.store.SetVisibility(owner, rid, api.SetVisibilityRequest{Visibility: api.Public}); !errors.Is(err, ErrGone) {
		t.Fatalf("SetVisibility on a tombstone: err = %v, want ErrGone", err)
	}
	// rm still works: the one mutation a tombstone supports.
	if err := h.store.DeleteResource(owner, rid); err != nil {
		t.Fatalf("rm of a tombstone: %v", err)
	}
}
