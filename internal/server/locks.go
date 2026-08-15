// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import "sync"

// keyedMutex serializes operations per key. The server uses it to ensure only one
// mutation of a given resource runs at a time, so two concurrent syncs of the
// same folder cannot interleave their database and blob writes — in particular
// the manifest blob's shared temp path, which they would otherwise clobber.
//
// It is process-local: it serializes within one server instance, which suits the
// single-instance deployment. A horizontally scaled deployment would need a
// shared lock (e.g. a row lock in the database).
//
// The per-key entry is reference-counted and deleted on the last release, so the
// map never retains entries for idle keys. This matters because callers lock on
// raw, attacker-controlled resource ids before any ownership/existence check: a
// non-pruning map would let an authenticated client leak a permanent mutex per
// distinct bogus id (an unbounded-memory DoS).
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refMutex
}

// refMutex is a per-key mutex plus the number of goroutines currently holding or
// waiting on it; the entry is removed from the map when this reaches zero.
type refMutex struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: make(map[string]*refMutex)}
}

// lock blocks until it holds the lock for key, then returns its release func.
func (k *keyedMutex) lock(key string) (release func()) {
	k.mu.Lock()
	m, ok := k.locks[key]
	if !ok {
		m = &refMutex{}
		k.locks[key] = m
	}
	// Claim a reference under k.mu, before contending for m.mu, so the entry can
	// never be pruned out from under a waiter (pruning also happens under k.mu).
	m.refs++
	k.mu.Unlock()

	m.mu.Lock()
	return func() {
		m.mu.Unlock()
		k.mu.Lock()
		m.refs--
		if m.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

// size reports how many keys are currently held or contended (test-only).
func (k *keyedMutex) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.locks)
}
