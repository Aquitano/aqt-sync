package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/aquitano/aqt-sync/internal/api"
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

// sliceFetch fetches exact object slices for one resource, one frame per requested
// id in request order. It abstracts the two non-owner transports: the
// unauthenticated public endpoint (share links) and the authed grant endpoint. Each
// maps its own transport's failures, since the same status means different things on
// the two: a 404 is a dead link on one and a revoked grant on the other.
type sliceFetch func(ids []string) ([][]byte, error)

func publicFetch(cl *client.Client, resourceID string) sliceFetch {
	return func(ids []string) ([][]byte, error) {
		frames, err := cl.PublicObjects(resourceID, ids)
		if err != nil {
			return nil, publicReadErr(err)
		}
		return frames, nil
	}
}

func grantFetch(cl *client.Client, resourceID string) sliceFetch {
	return func(ids []string) ([][]byte, error) {
		frames, err := cl.ResourceObjects(resourceID, ids)
		if err != nil {
			return nil, grantReadErr(err)
		}
		return frames, nil
	}
}

// remoteFetch picks the exact-slice transport for a non-owner read: public when the
// key came from a link fragment, the authed grant endpoint when the server returned
// a grant wrap. Nil means the caller is the owner and uses the authed pack path.
func remoteFetch(cl *client.Client, res api.GetResourceResponse, fragment string) sliceFetch {
	switch {
	case fragment != "":
		return publicFetch(cl, res.ID)
	case res.GrantKey != nil:
		return grantFetch(cl, res.ID)
	default:
		return nil
	}
}

// publicChunkSource serves a shared resource's objects to WriteFileRoot over an
// exact-slice transport (share link or grant, where the caller has the content key
// but no pack access). WriteFileRoot walks the chunks in order, so on a
// miss it fetches a forward batch from the missing id (its first-appearance position)
// large enough to cover the next window. A byte-bounded LRU keeps already-fetched
// objects so a file's duplicate ids do not refetch while memory stays capped.
// Single-goroutine use only (pullStream is sequential); packCache is not self-locking.
type publicChunkSource struct {
	fetch sliceFetch
	ids   []string       // distinct object ids in first-appearance order
	idx   map[string]int // id -> position in ids
	lens  map[string]int // id -> plaintext length, for the batch-size estimate
	cache *packCache
}

func newPublicChunkSource(fetch sliceFetch, chunks []crypto.Chunk) *publicChunkSource {
	s := &publicChunkSource{
		fetch: fetch,
		idx:   make(map[string]int),
		lens:  make(map[string]int),
		cache: newPackCache(packCacheBytes),
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
	frames, err := s.fetch(batch)
	if err != nil {
		return err
	}
	for i, frame := range frames {
		if err := verifyFrame(batch[i], frame); err != nil {
			return err
		}
		s.cache.put(batch[i], frame)
	}
	return nil
}

// publicReadErr translates a share-link object fetch failure into user-facing guidance.
func publicReadErr(err error) error {
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("this link has expired or reached its read limit: %w", err)
	}
	if errors.Is(err, client.ErrNotFound) {
		return errors.New("public objects unavailable: the resource is no longer public, or the server predates public streamed sharing")
	}
	return err
}

// grantReadErr translates a grant object fetch failure into user-facing guidance. The
// grantee is authenticated and holds no link, so link lifecycle never applies to them:
// their reads stop because the owner revoked the grant or deleted the resource.
func grantReadErr(err error) error {
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("the owner deleted this resource's content: %w", err)
	}
	if errors.Is(err, client.ErrNotFound) {
		return errors.New("this resource is no longer shared with you: the owner revoked your grant, or removed it")
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
func newPublicBatchFetcher(fetch sliceFetch) func([]string) (map[string][]byte, error) {
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
			frames, err := fetch(batch)
			if err != nil {
				return nil, err
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
func newPublicEntrySource(fetch sliceFetch, entries []syncengine.Entry) func(id string) ([]byte, error) {
	var chunks []crypto.Chunk
	for _, e := range entries {
		chunks = append(chunks, e.Chunks...)
	}
	src := newPublicChunkSource(fetch, chunks)
	var mu sync.Mutex
	return func(id string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		return src.get(id)
	}
}
