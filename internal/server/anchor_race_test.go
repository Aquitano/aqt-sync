// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"sync"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// The #76 guarantee: once SetSnapshotAnchor succeeds, no retention path may delete
// the snapshot — including a prune-style delete racing the anchor. The anchored
// check used to run outside the delete transaction with an unpredicated DELETE, so
// this interleaving destroyed freshly anchored snapshots (issue #179).
func TestAnchorRacingDeleteNeverLosesAnchoredSnapshot(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "anchor-race@example.com")
	rid := s.rootResource(t, owner, nil)

	for i := range 100 {
		snap, err := s.CreateSnapshotIdempotent(owner, api.CreateSnapshotRequest{ResourceID: rid, Automatic: true})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		var anchorErr, deleteErr error
		go func() {
			defer wg.Done()
			_, anchorErr = s.SetSnapshotAnchor(owner, snap.ID, true)
		}()
		go func() {
			defer wg.Done()
			deleteErr = s.DeleteSnapshot(owner, snap.ID)
		}()
		wg.Wait()

		if anchorErr == nil {
			// The anchor won: the snapshot must survive and the delete must have
			// refused (or still be refusable).
			if _, err := s.GetSnapshot(owner, snap.ID); err != nil {
				t.Fatalf("iteration %d: anchored snapshot deleted (delete err: %v, get err: %v)", i, deleteErr, err)
			}
			if !errors.Is(deleteErr, ErrSnapshotAnchored) {
				t.Fatalf("iteration %d: delete of anchored snapshot returned %v, want ErrSnapshotAnchored", i, deleteErr)
			}
			if err := s.DeleteSnapshot(owner, snap.ID); !errors.Is(err, ErrSnapshotAnchored) {
				t.Fatalf("iteration %d: re-delete of anchored snapshot returned %v", i, err)
			}
			// Unanchor so the next iteration starts clean and the delete really works.
			if _, err := s.SetSnapshotAnchor(owner, snap.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.DeleteSnapshot(owner, snap.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("iteration %d: cleanup delete: %v", i, err)
		}
	}
}

// The retention path itself: anchoring a due snapshot while PruneAutoSnapshots
// runs must never destroy it, and a snapshot that becomes anchored (or vanishes)
// between the prune's enumeration and its delete is "no longer due", not a prune
// failure.
func TestAnchorRacingAutoPrune(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "anchor-prune@example.com")
	rid := s.rootResource(t, owner, nil)

	for i := range 30 {
		older, err := s.CreateSnapshotIdempotent(owner, api.CreateSnapshotRequest{ResourceID: rid, Automatic: true})
		if err != nil {
			t.Fatal(err)
		}
		newer, err := s.CreateSnapshotIdempotent(owner, api.CreateSnapshotRequest{ResourceID: rid, Automatic: true})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		var anchorErr, pruneErr error
		go func() {
			defer wg.Done()
			_, anchorErr = s.SetSnapshotAnchor(owner, older.ID, true)
		}()
		go func() {
			defer wg.Done()
			_, pruneErr = s.PruneAutoSnapshots(1)
		}()
		wg.Wait()

		if pruneErr != nil {
			t.Fatalf("iteration %d: prune error: %v", i, pruneErr)
		}
		if anchorErr == nil {
			if _, err := s.GetSnapshot(owner, older.ID); err != nil {
				t.Fatalf("iteration %d: anchored snapshot pruned: %v", i, err)
			}
			if _, err := s.SetSnapshotAnchor(owner, older.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []string{older.ID, newer.ID} {
			if err := s.DeleteSnapshot(owner, id); err != nil && !errors.Is(err, ErrNotFound) {
				t.Fatalf("iteration %d: cleanup: %v", i, err)
			}
		}
	}
}
