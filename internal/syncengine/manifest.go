package syncengine

import (
	"encoding/json"
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

// SealManifest serializes and encrypts a manifest under the folder content key.
func SealManifest(m Manifest, ck crypto.ContentKey) (crypto.SealedBlob, error) {
	sortEntries(m.Entries)
	b, err := json.Marshal(m)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.Seal(b, ck)
}

// OpenManifest decrypts and parses a sealed manifest blob.
func OpenManifest(blob crypto.SealedBlob, ck crypto.ContentKey) (Manifest, error) {
	var m Manifest
	plain, err := crypto.Open(blob, ck)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(plain, &m)
	return m, err
}
