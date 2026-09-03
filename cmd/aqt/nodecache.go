// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// nodeCacheBytes caps the persistent metadata cache. Directory nodes and chunk-list
// segments are small (a node is one directory's child list), so this holds the
// metadata of even very large accounts; file-content chunks never enter the cache.
const nodeCacheBytes = 256 << 20

// nodeCache is a persistent, content-addressed store of metadata-object ciphertexts
// (directory nodes and chunk-list segments) shared by every command that walks a
// remote tree. An object's id is the sha256 of its ciphertext, so an entry is
// immutable — a hit never needs invalidation — and self-verifying: a corrupt file
// fails the hash check on read and is dropped as a miss. Only ciphertext is stored,
// the same bytes the server keeps, so the cache reveals nothing beyond what the
// server already sees. Every method degrades to a miss (or a no-op) on IO errors:
// the cache can speed an operation up but never fail one. A nil *nodeCache is valid
// and always misses.
type nodeCache struct {
	dir       string
	budget    int64
	pruneOnce sync.Once
}

// openNodeCache returns the shared on-disk cache, or nil (disabled) when
// AQT_NO_NODE_CACHE=1 is set or no user cache directory exists.
// AQT_NODE_CACHE_DIR overrides the location.
func openNodeCache() *nodeCache {
	if os.Getenv("AQT_NO_NODE_CACHE") == "1" {
		return nil
	}
	dir := os.Getenv("AQT_NODE_CACHE_DIR")
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil
		}
		dir = filepath.Join(base, "aqt", "nodes")
	}
	return &nodeCache{dir: dir, budget: nodeCacheBytes}
}

// validCacheID guards an id's use as a filename: object ids are 64 hex chars, and
// anything else (however it got here) must not touch the filesystem.
func validCacheID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (c *nodeCache) path(id string) string {
	return filepath.Join(c.dir, id[:2], id)
}

func (c *nodeCache) get(id string) ([]byte, bool) {
	if c == nil || !validCacheID(id) {
		return nil, false
	}
	p := c.path(id)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != id {
		_ = os.Remove(p) // corrupt entry: drop it so the next fetch heals it
		return nil, false
	}
	now := time.Now()
	_ = os.Chtimes(p, now, now) // LRU signal for prune
	return b, true
}

func (c *nodeCache) put(id string, ct []byte) {
	if c == nil || !validCacheID(id) {
		return
	}
	c.pruneOnce.Do(c.prune)
	p := c.path(id)
	if _, err := os.Lstat(p); err == nil {
		return
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	// Temp+rename so a concurrent reader never sees a torn entry (the hash check
	// would drop it, costing a re-fetch). No fsync: losing a cache entry to a crash
	// is free.
	f, err := os.CreateTemp(filepath.Dir(p), ".aqt-tmp-*")
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.Write(ct)
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Rename(tmp, p) != nil {
		_ = os.Remove(tmp)
	}
}

// prune drops least-recently-used entries until the cache fits its budget. It runs
// once per process, before the first write, so a run that only hits never pays the
// directory walk.
func (c *nodeCache) prune() {
	type entry struct {
		path string
		size int64
		mod  time.Time
	}
	var entries []entry
	var total int64
	_ = filepath.WalkDir(c.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		entries = append(entries, entry{path: p, size: fi.Size(), mod: fi.ModTime()})
		total += fi.Size()
		return nil
	})
	if total <= c.budget {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.Before(entries[j].mod) })
	for _, e := range entries {
		if total <= c.budget {
			break
		}
		if os.Remove(e.path) == nil {
			total -= e.size
		}
	}
}
