package syncengine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// safeJoin resolves dir/relPath and refuses a result that escapes dir, so a
// corrupted or hostile manifest (e.g. a "../" path) cannot write outside the
// tracked root. Symlink targets are not constrained — only the entry's own path.
func safeJoin(dir, relPath string) (string, error) {
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the tracked root", relPath)
	}
	return full, nil
}

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
//
// It writes a sibling temp file, fsyncs it, and renames it into place. Rename
// replaces whatever currently occupies the path atomically and without following
// it, so a crash mid-write leaves the old file or the new one but never a
// truncated mix, and a stale local symlink is overwritten in place rather than
// followed (os.WriteFile would write through it to a possibly out-of-tree target).
func WriteFile(dir string, e Entry, data []byte) error {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(e.Mode).Perm()
	if mode == 0 {
		mode = 0o600
	}

	tmp, err := os.CreateTemp(filepath.Dir(full), ".aqt-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed; cleans up every failure path
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, full)
}

// WriteSymlink recreates a symlink entry under dir, pointing at its stored target
// verbatim. An existing file at the path is replaced (the target may have moved).
func WriteSymlink(dir string, e Entry) error {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(e.Link, full)
}

// RemoveFile deletes dir/relPath, pruning now-empty parent directories up to (but
// not including) the tracked root. A missing file is not an error.
func RemoveFile(dir, relPath string) error {
	full, err := safeJoin(dir, relPath)
	if err != nil {
		return err
	}
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
