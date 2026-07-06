package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cacheID(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestNodeCacheRoundTrip(t *testing.T) {
	c := &nodeCache{dir: t.TempDir(), budget: nodeCacheBytes}
	ct := []byte("sealed node bytes")
	id := cacheID(ct)

	if _, ok := c.get(id); ok {
		t.Fatal("empty cache reported a hit")
	}
	c.put(id, ct)
	got, ok := c.get(id)
	if !ok || !bytes.Equal(got, ct) {
		t.Fatalf("get after put = %q, %v; want %q, true", got, ok, ct)
	}
}

func TestNodeCacheRejectsCorruptEntry(t *testing.T) {
	c := &nodeCache{dir: t.TempDir(), budget: nodeCacheBytes}
	id := cacheID([]byte("the real bytes"))
	p := c.path(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.get(id); ok {
		t.Fatal("corrupt entry served as a hit")
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatal("corrupt entry was not removed")
	}
}

func TestNodeCacheIgnoresHostileIDs(t *testing.T) {
	c := &nodeCache{dir: t.TempDir(), budget: nodeCacheBytes}
	for _, id := range []string{"", "..", "../../etc/passwd", "ABCD", cacheID(nil)[:63]} {
		c.put(id, []byte("x"))
		if _, ok := c.get(id); ok {
			t.Fatalf("hostile id %q served as a hit", id)
		}
	}
}

func TestNodeCachePruneEvictsOldestFirst(t *testing.T) {
	c := &nodeCache{dir: t.TempDir(), budget: 64}
	old := bytes.Repeat([]byte("o"), 40)
	newer := bytes.Repeat([]byte("n"), 40)
	oldID, newID := cacheID(old), cacheID(newer)
	c.put(oldID, old)
	c.put(newID, newer)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(c.path(oldID), past, past); err != nil {
		t.Fatal(err)
	}

	c.prune()

	if _, ok := c.get(oldID); ok {
		t.Fatal("prune kept the least-recently-used entry over budget")
	}
	if _, ok := c.get(newID); !ok {
		t.Fatal("prune evicted the most-recently-used entry")
	}
}

// TestBatchNodeFetcherServesFromDiskCache proves a fully cached walk makes no network
// call at all: the fetcher is built with a nil client, which would panic inside
// newPackSource if any id missed the disk cache.
func TestBatchNodeFetcherServesFromDiskCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AQT_NODE_CACHE_DIR", dir)
	ct := []byte("node ciphertext served without a server")
	id := cacheID(ct)
	(&nodeCache{dir: dir, budget: nodeCacheBytes}).put(id, ct)

	fetch := newBatchNodeFetcher(nil, nil)
	got, err := fetch([]string{id})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[id], ct) {
		t.Fatalf("fetch returned %q, want %q", got[id], ct)
	}
}

func TestNodeCacheDisabledByEnv(t *testing.T) {
	t.Setenv("AQT_NO_NODE_CACHE", "1")
	if c := openNodeCache(); c != nil {
		t.Fatal("AQT_NO_NODE_CACHE=1 did not disable the cache")
	}
}
