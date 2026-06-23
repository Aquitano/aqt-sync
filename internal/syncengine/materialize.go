package syncengine

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// FileBytes reconstructs an entry's plaintext. Inline (and empty) files return
// directly; chunked files are reassembled from chunks, which fetch must supply
// keyed by id. Each chunk is verified against its address and AEAD tag on open.
func FileBytes(e Entry, fetch func(id string) ([]byte, error)) ([]byte, error) {
	if len(e.Chunks) == 0 {
		return e.Inline, nil
	}
	var out []byte
	for _, ch := range e.Chunks {
		ct, err := fetch(ch.ID)
		if err != nil {
			return nil, fmt.Errorf("fetch chunk %s: %w", ch.ID, err)
		}
		plain, err := crypto.OpenChunk(ct, ch)
		if err != nil {
			return nil, err
		}
		out = append(out, plain...)
	}
	return out, nil
}

// WriteFile writes an entry's bytes under dir at its relative path, creating
// parent directories and applying the recorded mode.
func WriteFile(dir string, e Entry, data []byte) error {
	full := filepath.Join(dir, filepath.FromSlash(e.Path))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(e.Mode).Perm()
	if mode == 0 {
		mode = 0o600
	}
	return os.WriteFile(full, data, mode)
}

// RemoveFile deletes dir/relPath, pruning now-empty parent directories up to (but
// not including) the tracked root. A missing file is not an error.
func RemoveFile(dir, relPath string) error {
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	for parent := filepath.Dir(full); parent != dir; parent = filepath.Dir(parent) {
		if err := os.Remove(parent); err != nil {
			break // not empty (or gone): stop pruning
		}
	}
	return nil
}
