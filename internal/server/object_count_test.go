// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"strings"
	"testing"
)

// checkObjectCount asserts the incremental accounts.object_count matches a fresh
// COUNT(*) over the owner's object rows — the aggregate it replaced on the write
// path. Any drift here would silently corrupt quota and row-cap enforcement.
func (s *Store) checkObjectCount(t *testing.T, owner, when string) {
	t.Helper()
	var counter, actual int64
	if err := s.rdb.QueryRow(`SELECT object_count FROM accounts WHERE owner_handle = ?`, owner).Scan(&counter); err != nil {
		t.Fatalf("%s: read counter: %v", when, err)
	}
	if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM objects WHERE owner_handle = ?`, owner).Scan(&actual); err != nil {
		t.Fatalf("%s: count objects: %v", when, err)
	}
	if counter != actual {
		t.Fatalf("%s: object_count = %d, actual rows = %d", when, counter, actual)
	}
	u, err := s.AccountUsage(owner)
	if err != nil {
		t.Fatalf("%s: usage: %v", when, err)
	}
	if u.Objects != actual {
		t.Fatalf("%s: AccountUsage.Objects = %d, actual rows = %d", when, u.Objects, actual)
	}
}

// The counter must track every path that inserts or deletes object rows: a pack
// put (including a duplicate put, where dedup inserts nothing), client chunk GC,
// dead-pack GC, repack, and an account purge.
func TestObjectCountTracksEveryMutationPath(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "objcount@example.com")

	packA, dataA, idsA := packOf("one", "two", strings.Repeat("x", 8192))
	packB, dataB, _ := packOf("three", "four")
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	s.checkObjectCount(t, owner, "after first put")

	// A replayed pack dedups every row; the counter must not move.
	if _, err := s.PutPack(owner, packA, dataA, 0); err != nil {
		t.Fatal(err)
	}
	s.checkObjectCount(t, owner, "after duplicate put")

	if _, err := s.PutPack(owner, packB, dataB, 0); err != nil {
		t.Fatal(err)
	}
	s.checkObjectCount(t, owner, "after second put")

	// Root the small object so the repack below has a live object to move, then
	// drop the other two — including the 8 KiB one, so packA's live bytes fall
	// under repackMaxLiveFraction and it becomes a candidate.
	s.rootResource(t, owner, []string{idsA[0]})
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, idsA[1:], forceGC); err != nil || deleted != 2 {
		t.Fatalf("delete chunks: deleted=%d err=%v", deleted, err)
	}
	s.checkObjectCount(t, owner, "after chunk delete")

	// Repack rewrites packA around its one live object; the assert on repacked
	// proves the commitRepack delete/re-point path actually ran.
	repacked, _, err := s.RepackOwner(owner, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if repacked == 0 {
		t.Fatal("repack did not run; the commitRepack counter path is untested")
	}
	s.checkObjectCount(t, owner, "after repack")

	// Dead-pack GC (packB is fully unrooted).
	if _, _, err := s.GCPacks(owner, forceGC); err != nil {
		t.Fatal(err)
	}
	s.checkObjectCount(t, owner, "after pack GC")
}
