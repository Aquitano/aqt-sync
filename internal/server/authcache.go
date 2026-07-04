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
