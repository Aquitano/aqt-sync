package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
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
		if errors.Is(err, client.ErrNotFound) {
			return errors.New("public objects unavailable: the resource is no longer public, or the server predates public streamed sharing")
		}
		return err
	}
	for i, frame := range frames {
		sum := sha256.Sum256(frame)
		if hex.EncodeToString(sum[:]) != batch[i] {
			return fmt.Errorf("public object %s failed its content-address check (truncated or corrupt frame)", batch[i])
		}
		s.cache.put(batch[i], frame)
	}
	return nil
}
