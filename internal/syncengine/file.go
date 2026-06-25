package syncengine

import (
	"encoding/json"
	"io"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

const FileRootVersion = 1

// FileRoot is the sealed resource blob of a streamed single file: it names the
// file's convergent chunk objects in order, the same way ManifestRoot names a
// folder's manifest objects, so push and pull stay O(one pack).
type FileRoot struct {
	Version int            `json:"version"`
	Size    int64          `json:"size"`
	Chunks  []crypto.Chunk `json:"chunks"`
}

// ChunkIDs returns the distinct object ids the root references (its GC roots).
func (r FileRoot) ChunkIDs() []string {
	seen := make(map[string]bool, len(r.Chunks))
	ids := make([]string, 0, len(r.Chunks))
	for _, ch := range r.Chunks {
		if !seen[ch.ID] {
			seen[ch.ID] = true
			ids = append(ids, ch.ID)
		}
	}
	return ids
}

func SealFileRoot(r FileRoot, ck crypto.ContentKey) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.Seal(b, ck, crypto.AADBlob)
}

func OpenFileRoot(blob crypto.SealedBlob, ck crypto.ContentKey) (FileRoot, error) {
	var r FileRoot
	plain, err := crypto.Open(blob, ck, crypto.AADBlob)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(plain, &r)
}

// ChunkFile streams r through the chunker, sealing each chunk under conv into sink,
// and returns the chunk records and total plaintext size. Memory is O(one chunk +
// the sink's pack buffer).
func ChunkFile(r io.Reader, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) ([]crypto.Chunk, int64, error) {
	if sink == nil {
		sink = nopSink{}
	}
	var chunks []crypto.Chunk
	var size int64
	err := chunker.SplitStream(r, func(piece []byte) error {
		ct, ch, err := crypto.SealChunk(piece, conv)
		if err != nil {
			return err
		}
		size += int64(len(piece))
		chunks = append(chunks, ch)
		return sink.Add(ch, ct)
	})
	if err != nil {
		return nil, 0, err
	}
	return chunks, size, nil
}

func WriteFileRoot(dst io.Writer, r FileRoot, fetch func(id string) ([]byte, error)) error {
	return WriteEntry(dst, Entry{Chunks: r.Chunks}, fetch)
}
