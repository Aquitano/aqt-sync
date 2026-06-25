package syncengine

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// safeJoin resolves dir/relPath and refuses a result that escapes dir, so a
// corrupted or hostile manifest (e.g. a "../" path) cannot write outside the
// tracked root. It is purely lexical: it guards the entry's own final path, not
// intermediate components that may be symlinks — refuseSymlinkParents covers those.
func safeJoin(dir, relPath string) (string, error) {
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the tracked root", relPath)
	}
	return full, nil
}

// refuseSymlinkParents rejects a write whose path descends through an existing
// symlinked directory component, which safeJoin's lexical leaf check misses: without
// it, an archive that creates a symlink (-> outside the root) then writes through it
// escapes via MkdirAll/Rename. A scanned tree never puts a file under a symlink (the
// walk does not descend into one), so this only fires on hostile input.
func refuseSymlinkParents(dir, full string) error {
	rel, err := filepath.Rel(dir, full)
	if err != nil {
		return err
	}
	cur := dir
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		cur = filepath.Join(cur, part)
		if cur == full {
			break // the leaf itself is replaced, not followed, by the caller
		}
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			break // nothing below here exists yet; MkdirAll will create real dirs
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path %q descends through a symlink at %q", rel, cur)
		}
	}
	return nil
}

// WriteEntry reconstructs an entry's plaintext into dst. Inline (and empty) files
// write their stored bytes; chunked files stream chunk-by-chunk via fetch, so the
// whole file is never held in memory. Each chunk is verified against its address,
// AEAD tag, and length on open, so corrupt or wrong-keyed content fails loudly
// rather than landing on disk.
func WriteEntry(dst io.Writer, e Entry, fetch func(id string) ([]byte, error)) error {
	if len(e.Chunks) == 0 {
		_, err := dst.Write(e.Inline)
		return err
	}
	for _, ch := range e.Chunks {
		ct, err := fetch(ch.ID)
		if err != nil {
			return fmt.Errorf("fetch chunk %s: %w", ch.ID, err)
		}
		plain, err := crypto.OpenChunk(ct, ch)
		if err != nil {
			return err
		}
		if _, err := dst.Write(plain); err != nil {
			return err
		}
	}
	return nil
}

// FileBytes reconstructs an entry's plaintext in memory. It is a thin wrapper over
// WriteEntry for callers that genuinely need the bytes; the materialize path uses
// MaterializeFile instead so large content never lands fully in RAM.
func FileBytes(e Entry, fetch func(id string) ([]byte, error)) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteEntry(&buf, e, fetch); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteFile writes an entry's in-memory bytes under dir at its relative path.
func WriteFile(dir string, e Entry, data []byte) error {
	return writeAtomic(dir, e, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// MaterializeFile writes a chunked (or inline) entry under dir, streaming its
// chunks straight to the destination file so the whole content is never held in
// memory — the bounded-memory pull counterpart to the streaming push.
func MaterializeFile(dir string, e Entry, fetch func(id string) ([]byte, error)) error {
	return writeAtomic(dir, e, func(w io.Writer) error {
		return WriteEntry(w, e, fetch)
	})
}

// writeAtomic creates parent dirs, runs write into a sibling temp file, fsyncs it,
// applies the entry's mode, and renames it into place. Rename replaces whatever
// occupies the path atomically and without following it, so a crash mid-write
// leaves the old file or the new one but never a truncated mix, and a stale local
// symlink is overwritten rather than followed (a plain write would write through it
// to a possibly out-of-tree target).
func writeAtomic(dir string, e Entry, write func(w io.Writer) error) error {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return err
	}
	if err := refuseSymlinkParents(dir, full); err != nil {
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
	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		tmp.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
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
	if err := refuseSymlinkParents(dir, full); err != nil {
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
