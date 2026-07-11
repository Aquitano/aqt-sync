package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// publicBatchBytes bounds one public-read request by estimated ciphertext bytes, so a
// share-link pull streams a large file in windows rather than fetching every object up
// front. publicBatchIDs mirrors the server's per-request id cap.
const (
	publicBatchBytes = 8 << 20
	publicBatchIDs   = 10_000
	// frameOverhead over-estimates a chunk's ciphertext size from its plaintext Len:
	// the AEAD tag plus slack, since compression only ever shrinks the payload.
	frameOverhead = 64
)

// publicChunkSource serves a public streamed resource's objects to WriteFileRoot over
// the unauthenticated public endpoint (the share-link path, where the caller has the
// content key but no account token). WriteFileRoot walks the chunks in order, so on a
// miss it fetches a forward batch from the missing id (its first-appearance position)
// large enough to cover the next window. A byte-bounded LRU keeps already-fetched
// objects so a file's duplicate ids do not refetch while memory stays capped.
// Single-goroutine use only (pullStream is sequential); packCache is not self-locking.
type publicChunkSource struct {
	cl         *client.Client
	resourceID string
	ids        []string       // distinct object ids in first-appearance order
	idx        map[string]int // id -> position in ids
	lens       map[string]int // id -> plaintext length, for the batch-size estimate
	cache      *packCache
}

func newPublicChunkSource(cl *client.Client, resourceID string, chunks []crypto.Chunk) *publicChunkSource {
	s := &publicChunkSource{
		cl:         cl,
		resourceID: resourceID,
		idx:        make(map[string]int),
		lens:       make(map[string]int),
		cache:      newPackCache(packCacheBytes),
	}
	for _, ch := range chunks {
		if _, seen := s.idx[ch.ID]; seen {
			continue
		}
		s.idx[ch.ID] = len(s.ids)
		s.ids = append(s.ids, ch.ID)
		s.lens[ch.ID] = ch.Len
	}
	return s
}

func (s *publicChunkSource) get(id string) ([]byte, error) {
	if b, ok := s.cache.get(id); ok {
		return b, nil
	}
	start, ok := s.idx[id]
	if !ok {
		return nil, fmt.Errorf("object %s is not referenced by this resource", id)
	}
	if err := s.fetchBatch(start); err != nil {
		return nil, err
	}
	if b, ok := s.cache.get(id); ok {
		return b, nil
	}
	return nil, fmt.Errorf("public read did not return object %s", id)
}

// fetchBatch pulls objects from start forward until the estimated ciphertext bytes
// reach publicBatchBytes or the id cap, verifies each returned frame against its
// content address, and caches them.
func (s *publicChunkSource) fetchBatch(start int) error {
	end := start
	est := 0
	for end < len(s.ids) && end-start < publicBatchIDs {
		next := est + s.lens[s.ids[end]] + frameOverhead
		if end > start && next > publicBatchBytes {
			break
		}
		est = next
		end++
	}
	batch := s.ids[start:end]
	frames, err := s.cl.PublicObjects(s.resourceID, batch)
	if err != nil {
		return publicReadErr(err)
	}
	for i, frame := range frames {
		if err := verifyFrame(batch[i], frame); err != nil {
			return err
		}
		s.cache.put(batch[i], frame)
	}
	return nil
}

// publicReadErr translates a public-object fetch failure into user-facing guidance.
func publicReadErr(err error) error {
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("this link has expired or reached its read limit: %w", err)
	}
	if errors.Is(err, client.ErrNotFound) {
		return errors.New("public objects unavailable: the resource is no longer public, or the server predates public streamed sharing")
	}
	return err
}

// verifyFrame checks a returned frame against its content address, the same trust
// step every object fetch pays regardless of transport.
func verifyFrame(id string, frame []byte) error {
	sum := sha256.Sum256(frame)
	if hex.EncodeToString(sum[:]) != id {
		return fmt.Errorf("public object %s failed its content-address check (truncated or corrupt frame)", id)
	}
	return nil
}

// newPublicBatchFetcher is the link-holder counterpart of newBatchNodeFetcher: a
// level-batch fetch for a folder's metadata objects (directory nodes and chunk-list
// segments) over the unauthenticated public endpoint. Every frame is verified against
// its content address before use, so the shared on-disk node cache is exactly as
// trustworthy here as on the authed path.
func newPublicBatchFetcher(cl *client.Client, resourceID string) func([]string) (map[string][]byte, error) {
	cache := map[string][]byte{}
	disk := openNodeCache()
	return func(ids []string) (map[string][]byte, error) {
		var missing []string
		for _, id := range ids {
			if _, ok := cache[id]; ok {
				continue
			}
			if ct, ok := disk.get(id); ok {
				cache[id] = ct
				continue
			}
			missing = append(missing, id)
		}
		for start := 0; start < len(missing); start += publicBatchIDs {
			batch := missing[start:min(start+publicBatchIDs, len(missing))]
			frames, err := cl.PublicObjects(resourceID, batch)
			if err != nil {
				return nil, publicReadErr(err)
			}
			for i, frame := range frames {
				if err := verifyFrame(batch[i], frame); err != nil {
					return nil, err
				}
				cache[batch[i]] = frame
				disk.put(batch[i], frame)
			}
		}
		out := make(map[string][]byte, len(ids))
		for _, id := range ids {
			if ct, ok := cache[id]; ok {
				out[id] = ct
			}
		}
		return out, nil
	}
}

// newPublicEntrySource serves file-content objects for a set of folder entries to the
// concurrent download pool over the public endpoint. publicChunkSource is built for a
// single sequential reader, so a mutex serializes lookup+fetch; decryption and file
// writes still overlap across the pool's workers.
func newPublicEntrySource(cl *client.Client, resourceID string, entries []syncengine.Entry) func(id string) ([]byte, error) {
	var chunks []crypto.Chunk
	for _, e := range entries {
		chunks = append(chunks, e.Chunks...)
	}
	src := newPublicChunkSource(cl, resourceID, chunks)
	var mu sync.Mutex
	return func(id string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return src.get(id)
	}
}
