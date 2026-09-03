// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"fmt"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPackStoreRoundTripAndGC(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "packs@example.com")
	packA, dataA, idsA := packOf("alpha chunk", "beta chunk")
	packB, dataB, idsB := packOf("gamma chunk")

	all := append(append([]string{}, idsA...), idsB...)
	if missing, err := s.MissingChunks(owner, all); err != nil || len(missing) != 3 {
		t.Fatalf("missing before upload = %v err=%v, want 3", missing, err)
	}
	if n, err := s.PutPack(owner, packA, dataA, 0); err != nil || n != 2 {
		t.Fatalf("put pack A: n=%d err=%v, want 2", n, err)
	}
	if n, err := s.PutPack(owner, packB, dataB, 0); err != nil || n != 1 {
		t.Fatalf("put pack B: n=%d err=%v, want 1", n, err)
	}
	if missing, _ := s.MissingChunks(owner, all); len(missing) != 0 {
		t.Fatalf("missing after upload = %d, want 0", len(missing))
	}

	// Locate resolves an object to its pack and byte range; the range decrypts to
	// the original ciphertext.
	locs, err := s.LocateObjects(owner, []string{idsA[1]})
	if err != nil || len(locs) != 1 {
		t.Fatalf("locate: %+v err=%v", locs, err)
	}
	loc := locs[0]
	if loc.PackID != packA {
		t.Fatalf("object located in pack %s, want %s", loc.PackID, packA)
	}
	if got := dataA[loc.Off : loc.Off+loc.Len]; string(got) != "beta chunk" {
		t.Fatalf("located slice = %q, want beta chunk", got)
	}

	// A poisoned pack (an object's bytes do not hash to its id) is rejected.
	_, bad, _ := packOf("honest")
	bad[0] ^= 0xff // corrupt an object byte; pack id no longer matches either
	if _, err := s.PutPack(owner, packA, bad, 0); !errors.Is(err, ErrBadPack) {
		t.Fatalf("corrupt pack: got %v, want ErrBadPack", err)
	}

	// A prune that names pack B's object empties and sweeps that pack; pack A's
	// objects are untouched.
	s.rootResource(t, owner, []string{idsA[0]})
	deleted, _, freed, err := s.DeleteOwnerChunks(owner, idsB, forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || freed != int64(len(dataB)) {
		t.Fatalf("prune deleted %d freed %d, want 1 object / %d bytes", deleted, freed, len(dataB))
	}
	if missing, _ := s.MissingChunks(owner, idsA); len(missing) != 0 {
		t.Fatal("pack A objects must survive the prune")
	}
	if missing, _ := s.MissingChunks(owner, idsB); len(missing) != 1 {
		t.Fatal("pruned pack B object must be gone")
	}
}

// Repack honors the same age guard as the sweep, so a pack uploaded moments ago (its
// manifest may still be committing) is left untouched.
func TestRepackHonorsAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "young@example.com")
	packID, data, ids := packOf("keep", strings.Repeat("dead", 64))
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]})

	if repacked, _, err := s.RepackOwner(owner, gcMinAge); err != nil || repacked != 0 {
		t.Fatalf("repack = %d err=%v, want 0 (pack younger than the guard)", repacked, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("young pack must be left intact: %v", err)
	}
}

// Uploads racing a concurrent sweep must not lose data: every pack uploaded in the
// race window is fresh, so the age guard spares it even though the sweep runs
// against it. This is the pack analogue of the chunk-store upload/GC race.
func TestConcurrentUploadAndGCKeepsFreshPacks(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "uploadrace@example.com")

	const uploaders = 24
	var wg sync.WaitGroup
	errs := make(chan error, uploaders*2)
	packIDs := make([]string, uploaders)
	for i := range uploaders {
		packID, data, _ := packOf(fmt.Sprintf("racing object %d", i))
		packIDs[i] = packID
		wg.Add(2)
		go func(id string, d []byte) {
			defer wg.Done()
			_, err := s.PutPack(owner, id, d, 0)
			errs <- err
		}(packID, data)
		go func() {
			defer wg.Done()
			// A sweep at the real guard must never reap a pack uploaded in this window.
			_, _, err := s.GCPacks(owner, gcMinAge)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent upload/gc errored: %v", err)
		}
	}
	// Every freshly uploaded pack must still be present.
	for _, id := range packIDs {
		if _, err := os.Stat(s.packPath(owner, id)); err != nil {
			t.Fatalf("fresh pack %s lost to a concurrent sweep: %v", id, err)
		}
	}
}

func testRearmsGCAgeGuard(t *testing.T, email, payload string, touch func(*Store, string, []string) error) {
	t.Helper()
	s := newStore(t)
	owner := s.mustAccount(t, email)
	packID, data, ids := packOf(payload)
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), owner, packID,
	); err != nil {
		t.Fatal(err)
	}
	if err := touch(s, owner, ids); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 after the read re-armed the pack", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("pack reaped despite the read: %v", err)
	}
}

// An object that has aged past the guard and lost its last reference must survive a
// sweep if a concurrent sync checks it (dedup hit) before referencing it: the check
// re-arms the age guard on the pack holding it.
func TestDedupCheckReArmsGCAgeGuard(t *testing.T) {
	t.Parallel()
	testRearmsGCAgeGuard(t, "race@example.com", "dedup target", func(s *Store, owner string, ids []string) error {
		missing, err := s.MissingChunks(owner, ids)
		if err != nil {
			return err
		}
		if len(missing) != 0 {
			return fmt.Errorf("missing = %v, want the object present", missing)
		}
		return nil
	})
}

// A freshly uploaded pack must survive both the sweep and a prune's delete at the
// real age guard: it is what keeps an in-flight push's packs alive until its
// manifest PUT roots their objects. Only once aged does a prune reclaim it.
func TestFreshPackSurvivesAgeGuard(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "ageguard@example.com")
	packID, data, ids := packOf("in flight")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	if deleted, _, err := s.GCPacks(owner, gcMinAge); err != nil || deleted != 0 {
		t.Fatalf("gc deleted %d err=%v, want 0 (young pack must survive the age guard)", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); err != nil {
		t.Fatalf("young pack reaped: %v", err)
	}
	// Bypassing the guard, a prune naming its object empties and sweeps it.
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids, forceGC); err != nil || deleted != 1 {
		t.Fatalf("forced prune deleted %d err=%v, want 1", deleted, err)
	}
	if _, err := os.Stat(s.packPath(owner, packID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("emptied pack file should be gone, stat err=%v", err)
	}
}

// Locating an object re-arms the age guard on its pack, so a concurrent GC cannot
// reap a pack a download is mid-read of (the read-path analogue of the dedup touch).
func TestLocateRearmsAgeGuard(t *testing.T) {
	t.Parallel()
	testRearmsGCAgeGuard(t, "locaterace@example.com", "download target", func(s *Store, owner string, ids []string) error {
		locs, err := s.LocateObjects(owner, ids)
		if err != nil {
			return err
		}
		if len(locs) != 1 {
			return fmt.Errorf("locate returned %d objects, want 1", len(locs))
		}
		return nil
	})
}

func TestGCDoesNotCrossOwners(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "mine@example.com")
	other := s.mustAccount(t, "theirs@example.com")

	packID, data, ids := packOf("only mine")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	// Another owner's sweep must not touch my packs.
	if deleted, _, err := s.GCPacks(other, forceGC); err != nil || deleted != 0 {
		t.Fatalf("cross-owner gc deleted %d err=%v, want 0", deleted, err)
	}
	if missing, _ := s.MissingChunks(owner, ids); len(missing) != 0 {
		t.Fatal("my pack must survive another owner's gc")
	}
}

// Two GC passes for one owner race in production (two folders syncing at once, two
// devices, or a manual sync racing the watch daemon — each triggers a GC). Without
// the per-owner lock both would pick the same repack candidate, write the same
// content-addressed new pack, and the loser's stale-plan branch would delete the
// now-live new pack file, losing the live object. With it, the live object always
// survives a burst of concurrent GCs.
func TestConcurrentGCKeepsLivePack(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "racegc@example.com")
	livePayload := "live-object-keep"
	deadPayload := strings.Repeat("dead", 64) // enough dead space to make a repack candidate
	packID, data, ids := packOf(livePayload, deadPayload)
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	s.rootResource(t, owner, []string{ids[0]}) // only the first object is live

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = s.GC(owner, forceGC)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent GC %d: %v", i, err)
		}
	}

	// The live object survived the burst and still decrypts to its original bytes.
	if got := s.readLocated(t, owner, ids[0]); string(got) != livePayload {
		t.Fatalf("live object after concurrent GC = %q, want %q", got, livePayload)
	}
	if missing, _ := s.MissingChunks(owner, []string{ids[0]}); len(missing) != 0 {
		t.Fatal("rooted object must survive concurrent GC")
	}
}

// RunGCAll (the scheduled sweep's tick body) covers every owner, so packs a prune
// left sparse get compacted even on an account whose devices stopped syncing.
func TestRunGCAllRepacksAllOwners(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	a := s.mustAccount(t, "idle-a@example.com")
	b := s.mustAccount(t, "idle-b@example.com")
	for _, owner := range []string{a, b} {
		packID, data, ids := packOf(strings.Repeat("pruned", 64), "tiny survivor")
		if _, err := s.PutPack(owner, packID, data, 0); err != nil {
			t.Fatal(err)
		}
		if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids[:1], forceGC); err != nil || deleted != 1 {
			t.Fatalf("prune for %s deleted %d err=%v, want 1", owner, deleted, err)
		}
	}

	res, err := s.RunGCAll(forceGC)
	if err != nil {
		t.Fatal(err)
	}
	if res.RepackedPacks != 2 || res.ReclaimedBytes <= 0 {
		t.Fatalf("RunGCAll = %+v, want both owners' sparse packs compacted", res)
	}
}

// StartGC's timer path end-to-end: a pack a prune left sparse is compacted without
// any client triggering POST /v1/gc.
func TestStartGCRepacksOnTimer(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "sched-gc@example.com")
	packID, data, ids := packOf(strings.Repeat("pruned", 64), "tiny survivor")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.BackdatePacksForTest(owner, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if deleted, _, _, err := s.DeleteOwnerChunks(owner, ids[:1], gcMinAge); err != nil || deleted != 1 {
		t.Fatalf("prune deleted %d err=%v, want 1", deleted, err)
	}

	stop := make(chan struct{})
	defer close(stop)
	NewWithConfig(s, Config{}).StartGC(5*time.Millisecond, stop)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(s.packPath(owner, packID)); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("scheduled gc never compacted the sparse pack")
}

// Recorded idempotency responses only matter for short-lived retries; GC must
// reap rows past the TTL or the table grows without bound.
func TestGCSweepsStaleIdempotencyKeys(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "idemgc@example.com")
	ck, _ := crypto.GenerateContentKey()
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	for _, key := range []string{"stale-key", "fresh-key"} {
		blob, _ := crypto.Seal([]byte("body "+key), ck, crypto.AADBlob)
		meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
		if _, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, IdempotencyKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`UPDATE idempotency_keys SET created_at = ? WHERE key = 'stale-key'`,
		time.Now().Add(-idempotencyTTL-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GC(owner, time.Hour); err != nil {
		t.Fatal(err)
	}
	var keys []string
	rows, err := s.rdb.Query(`SELECT key FROM idempotency_keys WHERE owner_handle = ?`, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	if len(keys) != 1 || keys[0] != "fresh-key" {
		t.Fatalf("keys after gc = %v, want [fresh-key]", keys)
	}
}
