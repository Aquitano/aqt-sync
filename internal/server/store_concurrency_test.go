// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"testing"
	"time"
)

func TestStoreConcurrencyConfig(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if got := s.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1 (concurrent writers would hit SQLITE_BUSY)", got)
	}
	var fk int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1 (the dangling-reference backstop is off)", fk)
	}
	var busy int
	if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if busy == 0 {
		t.Error("busy_timeout = 0, want a positive timeout")
	}
}

// A read must not queue behind an open write transaction: reads run on the WAL
// read pool, not the single writer connection. Before the read pool existed this
// deadlocked outright — the write tx held the store's only connection.
func TestReadsProceedDuringOpenWriteTx(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "readpool@example.com")
	id := s.rootResource(t, owner, nil)

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// Take the write lock so the writer connection is genuinely busy.
	if _, err := tx.Exec(`INSERT INTO server_meta(key, value) VALUES('test-write-lock', x'00')`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.GetResource(id, owner)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read during an open write tx: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read blocked behind an open write transaction")
	}
}

// The read pool must reject writes loudly (query_only), so a mutation routed to it
// by mistake fails instead of racing the single writer to SQLITE_BUSY.
func TestReadPoolRejectsWrites(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	if _, err := s.rdb.Exec(`INSERT INTO server_meta(key, value) VALUES('nope', x'00')`); err == nil {
		t.Fatal("write on the read pool succeeded, want a query_only failure")
	}
}

// Cached token resolutions must die with their device (revocation) and their epoch
// (passphrase change) immediately, not at TTL expiry.
func TestAuthCacheInvalidation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	owner := s.mustAccount(t, "authcache@example.com")
	devA, tokA, err := s.CreateDevice(owner, "keeper", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	devB, tokB, err := s.CreateDevice(owner, "revoked", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Prime the cache with both tokens.
	if o, d, err := s.AuthByToken(tokA); err != nil || o != owner || d != devA {
		t.Fatalf("auth A = (%s, %s, %v)", o, d, err)
	}
	if _, d, err := s.AuthByToken(tokB); err != nil || d != devB {
		t.Fatalf("auth B = (%s, %v)", d, err)
	}

	// Revoking B must invalidate its cached entry, not wait out the TTL.
	if err := s.DeleteDevice(owner, devB); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthByToken(tokB); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token resolved from cache: %v, want ErrNotFound", err)
	}
	if _, _, err := s.AuthByToken(tokA); err != nil {
		t.Fatalf("unrelated token invalidated: %v", err)
	}

	// A passphrase change bumps the epoch: every other device's cached token dies,
	// the calling device's keeps working.
	_, tokC, err := s.CreateDevice(owner, "staled", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AuthByToken(tokC); err != nil {
		t.Fatal(err)
	}
	kdf := cryptotest.KdfParams(t)
	if _, err := s.ChangePassphrase(owner, devA, kdf,
		crypto.SealedBlob{Nonce: make([]byte, 1), Ciphertext: make([]byte, 1)},
		make([]byte, 32), []byte("new-verifier"), 1); err != nil {
		t.Fatalf("change passphrase: %v", err)
	}
	if _, _, err := s.AuthByToken(tokC); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-change token resolved from cache: %v, want ErrNotFound", err)
	}
	if _, _, err := s.AuthByToken(tokA); err != nil {
		t.Fatalf("initiating device's token must survive the epoch bump: %v", err)
	}
}
