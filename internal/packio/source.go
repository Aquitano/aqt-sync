// SPDX-License-Identifier: AGPL-3.0-or-later

package packio

import (
	"fmt"
	"sort"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
)

// packSpan is a contiguous byte range of a pack covering a run of objects a download
// needs — fetched in one Range request. A pack may map to several spans when its
// needed objects are far apart (see spanSplitGap), so a few KiB at opposite ends of a
// large pack never drags the whole pack down.
type packSpan struct {
	base int64
	end  int64
}

// spanSplitGap bounds wasted read-ahead within a pack: two needed objects more than
// this many bytes apart are fetched as separate ranges rather than one span swallowing
// the dead bytes between them. Needing 2 objects at opposite ends of a 16 MiB pack thus
// costs two small ranges instead of the whole pack; below the gap, one range
// still wins (one request, and the skipped bytes are cheap).
const spanSplitGap = 256 << 10

// Source resolves chunk ids to pack byte ranges (one locate up front) and
// serves their ciphertext, fetching each pack's covering span on demand and keeping
// a small LRU so a pack shared by several files is fetched once.
//
// It is safe for concurrent use by the download worker pool: locs and spans are
// immutable while concurrent gets run (Locate and ForgetLocations only ever run
// between batches, see their comments), the LRU is guarded by mu, and sf collapses a
// stampede of workers that all miss the same pack into one GetPackRange.
type Source struct {
	cl   *client.Client
	locs map[string]api.ObjectLocation
	// objSpan maps each object to the covering span its bytes fall in. A pack with
	// widely-separated needed objects has several spans, so Get fetches only the
	// window around each object rather than min..max across the whole pack.
	objSpan map[string]packSpan
	// spans records each pack's assigned spans so a later Locate (a caller walking a
	// tree level by level) reuses a span that already contains an object instead
	// of cutting a new one — the cache key is pack+span base, so reuse is what lets
	// a level-2 node inside a level-1 window come from the LRU, not the network.
	spans map[string][]packSpan
	mu    sync.Mutex // guards cache
	cache *Cache
	sf    singleflight.Group
}

// NewSource returns a source with ids already located.
func NewSource(cl *client.Client, ids []string) (*Source, error) {
	s := NewEmptySource(cl)
	if err := s.Locate(ids); err != nil {
		return nil, err
	}
	return s, nil
}

// ForgetLocations drops the resolved object index once a batch of files has landed,
// so a download's metadata stays bounded by the batch rather than by the whole tree.
// The span list and the LRU deliberately survive: spans coalesce contiguous needed
// runs (16 bytes per run, one per chunk only in the sparsest pull) and the LRU is
// O(packs), and keeping them lets the next batch reuse a span already fetched.
func (s *Source) ForgetLocations() {
	s.locs = map[string]api.ObjectLocation{}
	s.objSpan = map[string]packSpan{}
}

// NewEmptySource returns a source with no located objects yet, for callers
// that locate incrementally (a level-batched tree walk) while keeping one LRU
// across all their fetches.
func NewEmptySource(cl *client.Client) *Source {
	return &Source{
		cl:      cl,
		locs:    map[string]api.ObjectLocation{},
		objSpan: map[string]packSpan{},
		spans:   map[string][]packSpan{},
		cache:   NewCache(DefaultCacheBytes),
	}
}

// Locate resolves ids to pack spans and records them for Get. It mutates locs and
// objSpan, so it must not run concurrently with Get — callers either locate a whole
// batch before its downloads start or interleave Locate/Get on a single goroutine.
func (s *Source) Locate(ids []string) error {
	unseen := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, exists := s.locs[id]; !exists {
			unseen = append(unseen, id)
		}
	}
	ids = unseen
	if len(ids) == 0 {
		return nil
	}
	located, err := s.cl.LocateChunks(ids)
	if err != nil {
		return err
	}
	byPack := map[string][]api.ObjectLocation{}
	for _, loc := range located {
		s.locs[loc.ID] = loc
		byPack[loc.PackID] = append(byPack[loc.PackID], loc)
	}
	for _, objs := range byPack {
		s.assignSpans(objs)
	}
	return nil
}

// assignSpans groups one pack's needed objects into covering spans, opening a new span
// whenever the gap to the next object exceeds spanSplitGap, and records each object's
// span so Get range-fetches just that window. Objects within a pack never overlap.
// An object already contained in one of the pack's earlier spans (a prior Locate — a
// caller walking a tree level by level) adopts that span, so its bytes are served
// from the span already fetched rather than a fresh overlapping range.
func (s *Source) assignSpans(objs []api.ObjectLocation) {
	packID := objs[0].PackID
	fresh := objs[:0]
	for _, o := range objs {
		if sp, ok := spanContaining(s.spans[packID], o); ok {
			s.objSpan[o.ID] = sp
			continue
		}
		fresh = append(fresh, o)
	}
	objs = fresh
	if len(objs) == 0 {
		return
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Off < objs[j].Off })
	start := 0
	base := objs[0].Off
	end := objs[0].Off + objs[0].Len
	flush := func(hi int) {
		span := packSpan{base: base, end: end}
		s.spans[packID] = append(s.spans[packID], span)
		for _, o := range objs[start:hi] {
			s.objSpan[o.ID] = span
		}
	}
	for i := 1; i < len(objs); i++ {
		o := objs[i]
		if o.Off-end > spanSplitGap {
			flush(i)
			start, base = i, o.Off
		}
		if o.Off+o.Len > end {
			end = o.Off + o.Len
		}
	}
	flush(len(objs))
}

func spanContaining(spans []packSpan, o api.ObjectLocation) (packSpan, bool) {
	for _, sp := range spans {
		if o.Off >= sp.base && o.Off+o.Len <= sp.end {
			return sp, true
		}
	}
	return packSpan{}, false
}

// Get returns one located object's ciphertext, fetching its covering span if the
// LRU does not already hold it.
func (s *Source) Get(id string) ([]byte, error) {
	loc, ok := s.locs[id]
	if !ok {
		// The object was not in the locate response: the owner no longer stores it
		// (e.g. a concurrent sync superseded this version and GC reaped it). Surface
		// ErrNotFound so a manifest read can retry against the current version.
		return nil, fmt.Errorf("server could not locate chunk %s: %w", id, client.ErrNotFound)
	}
	span := s.objSpan[id]
	data, err := s.fetchSpan(loc.PackID, span)
	if err != nil {
		return nil, err
	}
	start := loc.Off - span.base
	return data[start : start+loc.Len], nil
}

// fetchSpan returns one span's bytes, fetching it at most once even under the
// concurrent download pool: the LRU is consulted under mu, and singleflight collapses
// concurrent misses of the same span into a single GetPackRange. The cache key is the
// pack plus the span base because a pack can hold several spans. The returned bytes are
// never mutated after the fetch, so a later eviction cannot disturb a caller still
// slicing its object out of them.
func (s *Source) fetchSpan(packID string, span packSpan) ([]byte, error) {
	key := fmt.Sprintf("%s@%d", packID, span.base)
	s.mu.Lock()
	data, ok := s.cache.Get(key)
	s.mu.Unlock()
	if ok {
		return data, nil
	}
	v, err, _ := s.sf.Do(key, func() (any, error) {
		s.mu.Lock()
		if data, ok := s.cache.Get(key); ok {
			s.mu.Unlock()
			return data, nil
		}
		s.mu.Unlock()
		data, err := s.cl.GetPackRange(packID, span.base, span.end-span.base)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) < span.end-span.base {
			return nil, fmt.Errorf("pack %s returned %d bytes, want %d", packID, len(data), span.end-span.base)
		}
		s.mu.Lock()
		s.cache.Put(key, data)
		s.mu.Unlock()
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
}
