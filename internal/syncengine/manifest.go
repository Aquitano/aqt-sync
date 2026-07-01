package syncengine

import (
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

// DirEntry is a tracked directory: its POSIX path and mode. The flat manifest
// records directories so empty ones round-trip and directory permission changes
// propagate — neither of which a files-only manifest can express. A directory that
// merely contains files needs no DirEntry to exist (it is implied by its children's
// paths); a DirEntry pins its mode and keeps an empty directory alive.
type DirEntry struct {
	Path string `json:"path"` // POSIX, relative to the tracked root
	Mode uint32 `json:"mode"`
}

// Manifest is the sealed description of a tracked folder. It is stored as the
// folder resource's blob, so the server only ever holds its ciphertext.
type Manifest struct {
	Version int        `json:"version"`
	Entries []Entry    `json:"entries"`
	Dirs    []DirEntry `json:"dirs,omitempty"`
}

func (m *Manifest) dirsByPath() map[string]DirEntry {
	out := make(map[string]DirEntry, len(m.Dirs))
	for _, d := range m.Dirs {
		out[d.Path] = d
	}
	return out
}

// DirsByPath indexes the manifest's tracked directories by their path.
func (m *Manifest) DirsByPath() map[string]DirEntry { return m.dirsByPath() }

func sortDirs(ds []DirEntry) {
	sort.Slice(ds, func(i, j int) bool { return ds[i].Path < ds[j].Path })
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

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
}
