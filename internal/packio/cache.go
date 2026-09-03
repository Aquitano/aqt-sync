// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import "container/list"

// DefaultCacheBytes is the download pack-range cache budget: a pack shared by several
// files is not re-GET per file, while download memory stays bounded by bytes (not
// a fixed pack count) and independent of tree size.
const DefaultCacheBytes = 128 << 20

// Cache is a byte-bounded LRU of fetched pack byte-ranges, so download memory is
// capped by total bytes (not a fixed pack count): a pack shared by many files is not
// re-fetched just because a few other packs were touched, while a handful of large
// packs cannot blow the budget. At least the most-recent entry is always kept, so a
// single pack larger than the budget still serves.
type Cache struct {
	capBytes int
	bytes    int
	data     map[string]*list.Element
	order    *list.List // front = least recently used; element value is cacheEntry
}

type cacheEntry struct {
	id string
	b  []byte
}

// NewCache returns an empty cache bounded to capBytes of held range data.
func NewCache(capBytes int) *Cache {
	return &Cache{capBytes: capBytes, data: map[string]*list.Element{}, order: list.New()}
}

// Get returns id's cached bytes and marks the entry most recently used.
func (c *Cache) Get(id string) ([]byte, bool) {
	el, ok := c.data[id]
	if !ok {
		return nil, false
	}
	// O(1): the share-link path caches per-chunk entries, so a linear-scan touch
	// turned every hit into a walk of the whole recency list.
	c.order.MoveToBack(el)
	return el.Value.(cacheEntry).b, true
}

// Put stores b under id, evicting least-recently-used entries to stay in budget.
func (c *Cache) Put(id string, b []byte) {
	if el, ok := c.data[id]; ok {
		c.bytes += len(b) - len(el.Value.(cacheEntry).b)
		el.Value = cacheEntry{id: id, b: b}
		c.order.MoveToBack(el)
		c.evict()
		return
	}
	c.data[id] = c.order.PushBack(cacheEntry{id: id, b: b})
	c.bytes += len(b)
	c.evict()
}

// evict drops least-recently-used packs until the cache fits its byte budget, always
// keeping the most-recently-used entry so Get can serve the pack just fetched.
func (c *Cache) evict() {
	for c.bytes > c.capBytes && c.order.Len() > 1 {
		el := c.order.Front()
		victim := el.Value.(cacheEntry)
		c.order.Remove(el)
		c.bytes -= len(victim.b)
		delete(c.data, victim.id)
	}
}
