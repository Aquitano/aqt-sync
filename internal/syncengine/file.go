package syncengine

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// FileRootVersion 2 adds ChunkList (the indirect chunk-list form); version 1 roots
// carry the list inline and still open.
const FileRootVersion = 2

// FileRoot is the sealed resource blob of a streamed single file: it names the
// file's convergent chunk objects in order, the same way ManifestRoot names a
// folder's manifest objects, so push and pull stay O(one pack). A large file's
// record list would itself outgrow the resource body cap (~150 B per chunk), so
// past chunkListInlineMax records the list moves to sealed segments named by
// ChunkList and Chunks stays empty.
type FileRoot struct {
	Version   int            `json:"version"`
	Size      int64          `json:"size"`
	Chunks    []crypto.Chunk `json:"chunks,omitempty"`
	ChunkList []crypto.Chunk `json:"chunkList,omitempty"`
}

// BuildFileRoot assembles the root for a streamed file's chunk records, sealing the
// list into segments via sink when it is too large to inline, and returns it with
// the resource's full GC roots: every content chunk id plus any list-segment id.
func BuildFileRoot(chunks []crypto.Chunk, size int64, conv crypto.ConvergenceKey, sink ChunkSink) (FileRoot, []string, error) {
	root := FileRoot{Version: FileRootVersion, Size: size}
	refs := distinctIDs(chunks)
	if len(chunks) > chunkListInlineMax {
		if sink == nil {
			sink = nopSink{}
		}
		segs, err := sealChunkList(chunks, conv, sink)
		if err != nil {
			return FileRoot{}, nil, err
		}
		root.ChunkList = segs
		refs = append(refs, distinctIDs(segs)...)
	} else {
		root.Chunks = chunks
	}
	return root, refs, nil
}

// Refs returns the resource's full GC roots for the given resolved content chunks:
// the same id set BuildFileRoot produced at push time (every content chunk id, plus
// any list-segment id when the root stores its chunk list indirectly). Callers that
// re-PUT the root — key rotation — must carry these so the server does not drop the
// objects' liveness roots.
func (r FileRoot) Refs(chunks []crypto.Chunk) []string {
	refs := distinctIDs(chunks)
	if r.Indirect() {
		refs = append(refs, distinctIDs(r.ChunkList)...)
	}
	return refs
}

// Resolve returns the file's chunk records, fetching and opening the sealed list
// segments when the root stores the list indirectly.
func (r FileRoot) Resolve(fetch func(id string) ([]byte, error)) ([]crypto.Chunk, error) {
	if len(r.ChunkList) == 0 {
		return r.Chunks, nil
	}
	return openChunkList(r.ChunkList, fetch)
}

// Indirect reports whether the chunk list lives in sealed segments rather than
// inline, i.e. Resolve will fetch before the content chunks are known.
func (r FileRoot) Indirect() bool { return len(r.ChunkList) > 0 }

// ChunkIDs returns the distinct object ids the root references directly: the content
// chunks when inline, the list segments when indirect (resolve those to reach the
// content ids).
func (r FileRoot) ChunkIDs() []string {
	if r.Indirect() {
		return distinctIDs(r.ChunkList)
	}
	return distinctIDs(r.Chunks)
}

func distinctIDs(chunks []crypto.Chunk) []string {
	seen := make(map[string]bool, len(chunks))
	ids := make([]string, 0, len(chunks))
	for _, ch := range chunks {
		if !seen[ch.ID] {
			seen[ch.ID] = true
			ids = append(ids, ch.ID)
		}
	}
	return ids
}

// SealFileRoot seals a streamed file's root as the resource blob, bound to the
// resource id when known (empty on create, before the server assigns one).
func SealFileRoot(r FileRoot, ck crypto.ContentKey, resourceID string) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.SealBound(b, ck, crypto.AADBlob, resourceID)
}

func OpenFileRoot(blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string) (FileRoot, error) {
	var r FileRoot
	plain, err := crypto.OpenBound(blob, ck, crypto.AADBlob, resourceID)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(plain, &r); err != nil {
		return r, err
	}
	if r.Version > FileRootVersion {
		return FileRoot{}, fmt.Errorf("file root version %d is newer than this client supports (%d); upgrade aqt", r.Version, FileRootVersion)
	}
	return r, nil
}

// ChunkFile streams r through the chunker, sealing each chunk under conv into sink
// (fanned across cores by sealStream, in stream order), and returns the chunk
// records and total plaintext size. Memory is O(a few chunks + the sink's pack
// buffer).
func ChunkFile(r io.Reader, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) ([]crypto.Chunk, int64, error) {
	if sink == nil {
		sink = nopSink{}
	}
	return sealStream(r, conv, chunker, sink)
}

// WriteFileRoot streams a file's content to dst from its ordered chunk records,
// fetching each object via fetch. The caller resolves an indirect root's chunk list
// (FileRoot.Resolve) first, since the sealed list segments sit behind their own
// locate and are not among these content objects.
func WriteFileRoot(dst io.Writer, chunks []crypto.Chunk, fetch func(id string) ([]byte, error)) error {
	return WriteEntry(dst, Entry{Chunks: chunks}, fetch)
}
