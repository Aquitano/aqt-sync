package syncengine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

const (
	ignoreFile = ".aqtignore"
	configFile = ".aqtconfig"
	// ControlDir is the per-folder state directory (last-synced manifest, etc.).
	ControlDir = ".aqt"
)

// Entry describes one entry in a tracked folder. A symlink stores its target in
// Link (it is never followed). A small regular file carries its bytes inline
// (the manifest is sealed, so this stays confidential); a larger one references
// content-addressed chunks. Hash is over the plaintext (or the link target) and
// drives change detection.
type Entry struct {
	Path   string         `json:"path"` // POSIX, relative to the tracked root
	Mode   uint32         `json:"mode"`
	Size   int64          `json:"size"`
	MTime  int64          `json:"mtime,omitempty"` // mod time (UnixNano); drives the stat fast-path, never change detection
	Hash   string         `json:"hash"`
	Link   string         `json:"link,omitempty"` // symlink target; set => this entry is a symlink
	Inline []byte         `json:"inline,omitempty"`
	Chunks []crypto.Chunk `json:"chunks,omitempty"`
}

// IsSymlink reports whether the entry describes a symbolic link.
func (e Entry) IsSymlink() bool { return e.Link != "" }

// Manifest is the sealed description of a tracked folder. It is stored as the
// folder resource's blob, so the server only ever holds its ciphertext.
type Manifest struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

func (m *Manifest) byPath() map[string]Entry {
	out := make(map[string]Entry, len(m.Entries))
	for _, e := range m.Entries {
		out[e.Path] = e
	}
	return out
}

// ByPath indexes the manifest's entries by their path.
func (m *Manifest) ByPath() map[string]Entry { return m.byPath() }

// Lookup returns the entry for a path, if present.
func (m *Manifest) Lookup(path string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return Entry{}, false
}

// ChunkIDs returns the distinct chunk ids the manifest references — uploaded
// before a manifest commit and sent as the resource's GC roots.
func (m *Manifest) ChunkIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, e := range m.Entries {
		for _, ch := range e.Chunks {
			if !seen[ch.ID] {
				seen[ch.ID] = true
				ids = append(ids, ch.ID)
			}
		}
	}
	return ids
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
}

// ManifestRoot is the tiny resource blob that replaces the inline manifest. Rather
// than re-PUT the whole manifest every sync, the manifest is chunked through the
// same CDC pipeline as file content and stored as objects; the root names those
// objects (id + per-chunk key + length), in order. It is sealed under the folder
// content key exactly as the inline manifest blob was, so it stays kilobytes and
// the 64 MiB manifest ceiling goes away. Because entries are path-sorted, a
// one-file edit perturbs a localized region of the serialized bytes, so CDC re-cuts
// only the manifest chunks near it — the sync uploads a handful, not the whole
// manifest.
type ManifestRoot struct {
	Version int            `json:"version"`
	Chunks  []crypto.Chunk `json:"chunks"`
}

// SealManifestRoot serializes and encrypts a root pointer under the folder content
// key (the resource blob).
func SealManifestRoot(r ManifestRoot, ck crypto.ContentKey) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.Seal(b, ck, crypto.AADBlob)
}

// OpenManifestRoot decrypts and parses a sealed root pointer.
func OpenManifestRoot(blob crypto.SealedBlob, ck crypto.ContentKey) (ManifestRoot, error) {
	var r ManifestRoot
	plain, err := crypto.Open(blob, ck, crypto.AADBlob)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(plain, &r)
}

// ChunkManifest serializes a manifest and chunks+seals it through the convergence
// key, feeding each chunk's ciphertext to sink and returning the chunk records the
// root pointer needs. The same CDC + seal path as file content, so the manifest
// objects dedup across syncs and a localized edit re-uploads only the changed
// chunks.
func ChunkManifest(m Manifest, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) ([]crypto.Chunk, error) {
	if sink == nil {
		sink = nopSink{}
	}
	sortEntries(m.Entries)
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var chunks []crypto.Chunk
	err = chunker.SplitStream(bytes.NewReader(b), func(piece []byte) error {
		ct, ch, err := crypto.SealChunk(piece, conv)
		if err != nil {
			return err
		}
		chunks = append(chunks, ch)
		return sink.Add(ch, ct)
	})
	if err != nil {
		return nil, err
	}
	return chunks, nil
}

// OpenManifestFromRoot reassembles the manifest from its objects (fetched by id via
// fetch) and parses it. Each chunk is verified against its address and AEAD tag on
// open, so a tampered or wrong-keyed manifest object fails loudly.
func OpenManifestFromRoot(r ManifestRoot, fetch func(id string) ([]byte, error)) (Manifest, error) {
	var buf bytes.Buffer
	for _, ch := range r.Chunks {
		ct, err := fetch(ch.ID)
		if err != nil {
			return Manifest{}, fmt.Errorf("fetch manifest chunk %s: %w", ch.ID, err)
		}
		plain, err := crypto.OpenChunk(ct, ch)
		if err != nil {
			return Manifest{}, err
		}
		buf.Write(plain)
	}
	var m Manifest
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
