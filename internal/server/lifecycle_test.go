package server

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// putPublic creates a public inline resource with an optional lifecycle policy and
// returns its id. Zero policy fields mean no limit.
func (s *Store) putPublic(t *testing.T, owner, body string, expireSeconds, maxReads int64) string {
	t.Helper()
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	id, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
		ExpireSeconds: expireSeconds, MaxReads: maxReads,
	})
	if err != nil {
		t.Fatalf("put public resource: %v", err)
	}
	return id
}

func (s *Store) pokeExpiry(t *testing.T, id string, ts int64) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE resources SET expires_at = ? WHERE id = ?`, ts, id); err != nil {
		t.Fatalf("poke expires_at: %v", err)
	}
}

// A create carries the policy through to the stored columns.
func TestPutResourceStoresPolicy(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "policy@example.com")
	id := s.putPublic(t, owner, "hello", 3600, 5)

	var (
		expiresAt, maxReads int64
	)
	if err := s.db.QueryRow(`SELECT expires_at, max_reads FROM resources WHERE id = ?`, id).
		Scan(&expiresAt, &maxReads); err != nil {
		t.Fatal(err)
	}
	if maxReads != 5 {
		t.Fatalf("max_reads = %d, want 5", maxReads)
	}
	if now := time.Now().Unix(); expiresAt < now+3500 || expiresAt > now+3700 {
		t.Fatalf("expires_at = %d, want near now+3600", expiresAt)
	}
}

// A lifecycle policy is legal only on a public resource; a private put with one is a
// client bug.
func TestPutResourceRejectsPolicyOnPrivate(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "priv@example.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("x"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	_, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, MaxReads: 1,
	})
	if !errors.Is(err, ErrPolicyOnPrivate) {
		t.Fatalf("got %v, want ErrPolicyOnPrivate", err)
	}
}

// Negative policy values are rejected before anything is stored.
func TestPutResourceRejectsNegativePolicy(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "neg@example.com")
	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("x"), ck, crypto.AADBlob)
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":0}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	_, _, err := s.PutResource(owner, api.CapabilityIDBinding, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped, ExpireSeconds: -1,
	})
	if !errors.Is(err, ErrBadPolicy) {
		t.Fatalf("got %v, want ErrBadPolicy", err)
	}
}

// An expired link is gone to a non-owner but still readable by the owner (who reaches
// it to delete it); expiry is not counted against the read limit.
func TestGetResourceExpiryEnforced(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "expiry@example.com")
	id := s.putPublic(t, owner, "secret", 3600, 0)

	// Before expiry, a public read succeeds.
	if _, err := s.GetResource(id, ""); err != nil {
		t.Fatalf("pre-expiry read: %v", err)
	}
	// Poke the stored expiry into the past (the established direct-UPDATE pattern).
	s.pokeExpiry(t, id, time.Now().Add(-time.Minute).Unix())

	if _, err := s.GetResource(id, ""); !errors.Is(err, ErrGone) {
		t.Fatalf("expired non-owner read: got %v, want ErrGone", err)
	}
	if _, err := s.GetResource(id, owner); err != nil {
		t.Fatalf("owner read of expired link must still work: %v", err)
	}
}

// max_reads counts only non-owner serves: the Nth read succeeds, the (N+1)th is gone,
// and interleaved owner reads never consume a permit.
func TestGetResourceMaxReadsCounting(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "maxreads@example.com")
	id := s.putPublic(t, owner, "burnme", 0, 2)

	// An owner read is free and does not consume a permit.
	if _, err := s.GetResource(id, owner); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if _, err := s.GetResource(id, ""); err != nil {
		t.Fatalf("read 1: %v", err)
	}
	// Another owner read between the two permitted reads still does not count.
	if _, err := s.GetResource(id, owner); err != nil {
		t.Fatalf("owner read 2: %v", err)
	}
	if _, err := s.GetResource(id, ""); err != nil {
		t.Fatalf("read 2: %v", err)
	}
	if _, err := s.GetResource(id, ""); !errors.Is(err, ErrGone) {
		t.Fatalf("read 3: got %v, want ErrGone", err)
	}
	// The owner can still read after exhaustion.
	if _, err := s.GetResource(id, owner); err != nil {
		t.Fatalf("owner read after exhaustion: %v", err)
	}

	var exhaustedAt int64
	if err := s.db.QueryRow(`SELECT COALESCE(exhausted_at, 0) FROM resources WHERE id = ?`, id).
		Scan(&exhaustedAt); err != nil {
		t.Fatal(err)
	}
	if exhaustedAt == 0 {
		t.Fatal("exhausted_at should be stamped once the limit is reached")
	}
}

// Concurrent non-owner reads of a max_reads-limited link must never over-serve: exactly
// max_reads succeed no matter how many race.
func TestGetResourceMaxReadsNoOverServe(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "concurrent@example.com")
	const limit = 5
	id := s.putPublic(t, owner, "limited", 0, limit)

	const readers = 40
	var wg sync.WaitGroup
	results := make(chan error, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.GetResource(id, "")
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var served, gone int
	for err := range results {
		switch {
		case err == nil:
			served++
		case errors.Is(err, ErrGone):
			gone++
		default:
			t.Fatalf("unexpected read error: %v", err)
		}
	}
	if served != limit {
		t.Fatalf("served %d reads, want exactly %d", served, limit)
	}
	if gone != readers-limit {
		t.Fatalf("gone %d reads, want %d", gone, readers-limit)
	}
}

// SetVisibility applies a policy, a fresh policy resets the read counter, and the flip
// back to private clears the policy entirely.
func TestSetVisibilityPolicyLifecycle(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "setvis@example.com")
	id := s.putPublic(t, owner, "data", 0, 1)

	// Exhaust the initial burn.
	if _, err := s.GetResource(id, ""); err != nil {
		t.Fatalf("burn read: %v", err)
	}
	if _, err := s.GetResource(id, ""); !errors.Is(err, ErrGone) {
		t.Fatalf("post-burn read: got %v, want ErrGone", err)
	}
	// Re-sharing with a new policy resets the counter, so reads flow again.
	if _, err := s.SetVisibility(owner, id, api.Public, 0, 2); err != nil {
		t.Fatalf("set visibility public with policy: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.GetResource(id, ""); err != nil {
			t.Fatalf("read after reset %d: %v", i, err)
		}
	}
	if _, err := s.GetResource(id, ""); !errors.Is(err, ErrGone) {
		t.Fatalf("read past new limit: got %v, want ErrGone", err)
	}
	// Flipping private clears the policy columns.
	if _, err := s.SetVisibility(owner, id, api.Private, 0, 0); err != nil {
		t.Fatalf("set visibility private: %v", err)
	}
	var expiresAt, maxReads *int64
	if err := s.db.QueryRow(`SELECT expires_at, max_reads FROM resources WHERE id = ?`, id).
		Scan(&expiresAt, &maxReads); err != nil {
		t.Fatal(err)
	}
	if expiresAt != nil || maxReads != nil {
		t.Fatalf("private flip left policy set: expires=%v max=%v", expiresAt, maxReads)
	}
}

// SweepExpired reclaims an expired link: its blob files are deleted, its objects
// unrooted, and it leaves a tombstone that keeps returning ErrGone (never 404).
func TestSweepExpiredReclaimsAndTombstones(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "sweep@example.com")
	packID, data, ids := packOf("streamed object bytes")
	if _, err := s.PutPack(owner, packID, data, 0); err != nil {
		t.Fatal(err)
	}
	id := s.publicResource(t, owner, ids)
	// Attach an expiry and push it into the past.
	s.pokeExpiry(t, id, time.Now().Add(-time.Minute).Unix())

	// A blob file exists before the sweep.
	if matches, _ := filepath.Glob(filepath.Join(s.blobDir(id), id+".*.bin")); len(matches) == 0 {
		t.Fatal("expected a blob file before reclaim")
	}

	swept, err := s.SweepExpired(owner, time.Now().Unix())
	if err != nil || swept != 1 {
		t.Fatalf("sweep = %d err = %v, want 1", swept, err)
	}
	// Blob files are gone from disk.
	if matches, _ := filepath.Glob(filepath.Join(s.blobDir(id), id+".*.bin")); len(matches) != 0 {
		t.Fatalf("blob files survived reclaim: %v", matches)
	}
	// The objects are unrooted, so the pack becomes collectable.
	var rooted int
	if err := s.db.QueryRow(`SELECT count(*) FROM resource_chunks WHERE resource_id = ?`, id).
		Scan(&rooted); err != nil {
		t.Fatal(err)
	}
	if rooted != 0 {
		t.Fatalf("resource still roots %d chunks after reclaim", rooted)
	}
	// The tombstone remains and returns ErrGone to both non-owner and owner.
	if _, err := s.GetResource(id, ""); !errors.Is(err, ErrGone) {
		t.Fatalf("reclaimed non-owner read: got %v, want ErrGone", err)
	}
	if _, err := s.GetResource(id, owner); !errors.Is(err, ErrGone) {
		t.Fatalf("reclaimed owner read: got %v, want ErrGone", err)
	}
	// A second sweep is a no-op (already reclaimed).
	if swept, err := s.SweepExpired(owner, time.Now().Unix()); err != nil || swept != 0 {
		t.Fatalf("second sweep = %d err = %v, want 0", swept, err)
	}
}

// An exhausted link gets a grace window (gcMinAge) before it is reclaimed, so an
// in-flight permitted streamed pull can finish fetching its objects.
func TestSweepExhaustedGrace(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "grace@example.com")
	id := s.putPublic(t, owner, "burned", 0, 1)
	if _, err := s.GetResource(id, ""); err != nil {
		t.Fatalf("burn read: %v", err)
	}

	// Just exhausted (exhausted_at ~ now): still within the grace window, not swept.
	if swept, err := s.SweepExpired(owner, time.Now().Unix()); err != nil || swept != 0 {
		t.Fatalf("sweep within grace = %d err = %v, want 0", swept, err)
	}
	if _, err := s.GetResource(id, owner); err != nil {
		t.Fatalf("owner read within grace must still work: %v", err)
	}

	// Poke exhausted_at past the grace window; now it sweeps.
	past := time.Now().Add(-2 * gcMinAge).Unix()
	if _, err := s.db.Exec(`UPDATE resources SET exhausted_at = ? WHERE id = ?`, past, id); err != nil {
		t.Fatal(err)
	}
	if swept, err := s.SweepExpired(owner, time.Now().Unix()); err != nil || swept != 1 {
		t.Fatalf("sweep past grace = %d err = %v, want 1", swept, err)
	}
	if _, err := s.GetResource(id, owner); !errors.Is(err, ErrGone) {
		t.Fatalf("post-grace read: got %v, want ErrGone", err)
	}
}

// GC runs the expiry sweep, so a manual POST /v1/gc (or the scheduled RunGCAll)
// reclaims expired links, not only the direct SweepExpired call.
func TestGCTriggersExpirySweep(t *testing.T) {
	s := newStore(t)
	owner := s.mustAccount(t, "gcsweep@example.com")
	id := s.putPublic(t, owner, "gc me", 3600, 0)
	s.pokeExpiry(t, id, time.Now().Add(-time.Minute).Unix())

	if _, err := s.GC(owner, gcMinAge); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if _, err := s.GetResource(id, owner); !errors.Is(err, ErrGone) {
		t.Fatalf("resource not reclaimed by GC: got %v, want ErrGone", err)
	}
}
