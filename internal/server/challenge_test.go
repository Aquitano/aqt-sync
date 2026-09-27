// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCreateChallengeSweepsExpired(t *testing.T) {
	t.Parallel()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = s.Close() }()

	// An unconsumed, already-expired challenge sitting in the table.
	if _, err := s.db.Exec(
		`INSERT INTO challenges(id, email, nonce, expires_at) VALUES(?,?,?,?)`,
		"stale", "a@example.com", []byte("nonce"), time.Now().Add(-time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	// Issuing a fresh challenge sweeps expired rows.
	if _, _, err := s.CreateChallenge("b@example.com"); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	var stale int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM challenges WHERE id = 'stale'`).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("expired challenge was not swept: %d rows remain", stale)
	}
}

// A challenge is single-use even when two attaches race on it: only one consume may
// hand back the nonce, or a captured attach request could be replayed alongside the
// original.
func TestConcurrentConsumesSpendChallengeOnce(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	for range 20 {
		id, _, err := s.CreateChallenge("race@example.com")
		if err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, err := s.ConsumeChallenge(id, "race@example.com"); err == nil {
					wins.Add(1)
				}
			})
		}
		wg.Wait()
		if n := wins.Load(); n != 1 {
			t.Fatalf("challenge consumed %d times, want once", n)
		}
	}
}
