package server

import "sync"

// keyedMutex serializes operations per key. The server uses it to ensure only one
// mutation of a given resource runs at a time, so two concurrent syncs of the
// same folder cannot interleave their database and blob writes — in particular
// the manifest blob's shared temp path, which they would otherwise clobber.
//
// It is process-local: it serializes within one server instance, which suits the
// single-instance deployment. A horizontally scaled deployment would need a
// shared lock (e.g. a row lock in the database). The per-key mutex map is never
// pruned, but it is bounded by the number of distinct resources an account holds.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: make(map[string]*sync.Mutex)}
}

// lock blocks until it holds the lock for key, then returns its release func.
func (k *keyedMutex) lock(key string) (release func()) {
	k.mu.Lock()
	m, ok := k.locks[key]
	if !ok {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()

	m.Lock()
	return m.Unlock
}
