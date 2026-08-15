// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/sha256"
	"sync"
	"time"
)

// authCacheTTL bounds how stale a cached token resolution can get on any path the
// explicit invalidations (ChangePassphrase, DeleteDevice) do not cover, e.g. an
// operator editing the database directly.
const authCacheTTL = 5 * time.Minute

// authCache memoizes successful token-hash -> (owner, device) resolutions so the
// per-request auth SELECT stops being the server's hottest query. Only positive
// results are cached and the key is the token's sha256 (never the token itself), so
// unauthenticated garbage cannot grow the map and a heap dump reveals no tokens.
// Its size is bounded by the number of live device tokens.
type authCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]authEntry
}

type authEntry struct {
	owner    string
	deviceID string
	expires  time.Time
}

func newAuthCache() *authCache {
	return &authCache{entries: make(map[[sha256.Size]byte]authEntry)}
}

// suspensionTTL bounds how long a running server keeps serving an account that an
// operator has just suspended. Suspension is written by a separate process
// (`aqt-server admin`), so this server's in-memory caches cannot be invalidated
// from there — only re-reading the row discovers it. A short TTL is the whole
// mechanism: it collapses the per-request cost of the check under a sync's request
// burst while bounding how long an abusive account keeps working after the
// operator acts.
const suspensionTTL = 10 * time.Second

// suspensionCacheMaxEntries is a backstop for a burst of distinct active accounts;
// normal cleanup keeps only entries touched during the last suspensionTTL.
const suspensionCacheMaxEntries = 4096

// suspensionCache memoizes the per-account suspension flag, keyed by owner handle.
// It is deliberately separate from authCache: that one memoizes a token resolution
// that only this process can invalidate, whereas this one memoizes state another
// process writes, so it needs its own much shorter expiry.
type suspensionCache struct {
	mu      sync.Mutex
	entries map[string]suspensionEntry
}

type suspensionEntry struct {
	disabled bool
	expires  time.Time
}

func newSuspensionCache() *suspensionCache {
	return &suspensionCache{entries: make(map[string]suspensionEntry)}
}

func (c *suspensionCache) get(owner string) (disabled, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[owner]
	if !ok {
		return false, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, owner)
		return false, false
	}
	return e.disabled, true
}

func (c *suspensionCache) put(owner string, disabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for key, entry := range c.entries {
		if now.Before(entry.expires) {
			continue
		}
		delete(c.entries, key)
	}
	if _, exists := c.entries[owner]; !exists && len(c.entries) >= suspensionCacheMaxEntries {
		for key := range c.entries {
			delete(c.entries, key)
			break
		}
	}
	c.entries[owner] = suspensionEntry{disabled: disabled, expires: now.Add(suspensionTTL)}
}

// invalidate drops one owner's entry, so a suspension written by *this* process
// takes effect on the next request rather than at TTL expiry.
func (c *suspensionCache) invalidate(owner string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, owner)
}

func (c *authCache) get(h [sha256.Size]byte) (owner, deviceID string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[h]
	if !ok {
		return "", "", false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, h)
		return "", "", false
	}
	return e.owner, e.deviceID, true
}

func (c *authCache) put(h [sha256.Size]byte, owner, deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[h] = authEntry{owner: owner, deviceID: deviceID, expires: time.Now().Add(authCacheTTL)}
}

// invalidateOwner drops every cached entry for the owner's devices (a passphrase
// change bumps the account epoch, staling all of them at once).
func (c *authCache) invalidateOwner(owner string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for h, e := range c.entries {
		if e.owner == owner {
			delete(c.entries, h)
		}
	}
}

// invalidateDevice drops one device's cached entry (revocation must take effect
// immediately, not at TTL expiry).
func (c *authCache) invalidateDevice(owner, deviceID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for h, e := range c.entries {
		if e.owner == owner && e.deviceID == deviceID {
			delete(c.entries, h)
		}
	}
}
