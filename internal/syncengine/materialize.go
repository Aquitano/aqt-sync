// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/aquitano/aqt-sync/internal/compress"
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
		// Inline rides inside the sealed manifest, so its length is already
		// authenticated; -1 skips the exact-length pin a chunk record carries.
		data, err := compress.Decode(e.Inline, e.InlineAlg, -1)
		if err != nil {
			return err
		}
		_, err = dst.Write(data)
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

// WriteFile writes an entry's in-memory bytes under dir at its relative path, and
// returns the mtime the file landed with (see materializeAt).
func WriteFile(dir string, e Entry, data []byte) (int64, error) {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return 0, err
	}
	return materializeAt(full, entryMode(e), func() error { return refuseSymlinkParents(dir, full) },
		func(w io.Writer) error { _, err := w.Write(data); return err })
}

// MaterializeFile writes a chunked (or inline) entry under dir, streaming its
// chunks straight to the destination file so the whole content is never held in
// memory — the bounded-memory pull counterpart to the streaming push. It returns the
// mtime the file landed with (see materializeAt).
func MaterializeFile(dir string, e Entry, fetch func(id string) ([]byte, error)) (int64, error) {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return 0, err
	}
	return materializeAt(full, entryMode(e), func() error { return refuseSymlinkParents(dir, full) },
		func(w io.Writer) error { return WriteEntry(w, e, fetch) })
}

// WriteSymlink recreates a symlink entry under dir, pointing at its stored target
// verbatim. An existing file at the path is replaced (the target may have moved).
func WriteSymlink(dir string, e Entry) error {
	full, err := safeJoin(dir, e.Path)
	if err != nil {
		return err
	}
	return writeSymlinkAt(full, e.Link, func() error { return refuseSymlinkParents(dir, full) })
}

// entryMode returns an entry's permission bits, defaulting to 0o600 when unset.
func entryMode(e Entry) os.FileMode {
	if mode := os.FileMode(e.Mode).Perm(); mode != 0 {
		return mode
	}
	return 0o600
}

// materializeAt runs prepare (the parent-path policy), creates parent dirs, runs
// write into a sibling temp file, fsyncs it, applies mode, and renames it into place
// at full. Rename replaces whatever occupies the path atomically and without
// following it, so a crash mid-write leaves the old file or the new one but never a
// truncated mix, and a stale local symlink is overwritten rather than followed (a
// plain write would write through it to a possibly out-of-tree target).
//
// It returns the mtime (UnixNano) the file carries once it is in place, so the caller
// can record it on the entry it stores in the base manifest. A remote entry carries
// no mtime — the DAG does not store one — and a base entry without one never matches
// a stat, so every later scan would re-read and re-hash the whole file. The mtime is
// read off the temp file, which neither chmod nor rename disturbs: a writer that
// touches the path after the rename leaves a *newer* mtime, which fails the stat
// check and forces the re-hash that catches it.
func materializeAt(full string, mode os.FileMode, prepare func() error, write func(w io.Writer) error) (int64, error) {
	if err := prepare(); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".aqt-tmp-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed; cleans up every failure path
	bw := bufio.NewWriter(tmp)
	if err := write(bw); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := bw.Flush(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return 0, err
	}
	fi, err := os.Stat(tmpName)
	if err != nil {
		return 0, err
	}
	// A remote directory->file replacement leaves an emptied directory at full once
	// its children are deleted; Rename refuses to replace a directory (EISDIR/ENOTEMPTY)
	// even an empty one, so drop it first. Only an empty directory is removed, so a
	// directory still holding data is never silently destroyed.
	if stale, err := os.Lstat(full); err == nil && stale.IsDir() {
		if err := os.Remove(full); err != nil {
			return 0, err
		}
	}
	if err := os.Rename(tmpName, full); err != nil {
		return 0, err
	}
	return fi.ModTime().UnixNano(), nil
}

// writeSymlinkAt runs prepare, creates parent dirs, and (re)creates the symlink at
// full, replacing any existing entry there.
func writeSymlinkAt(full, target string, prepare func() error) error {
	if err := prepare(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, full); err != nil {
		if runtime.GOOS == "windows" {
			// The raw Win32 text ("A required privilege is not held...") names
			// neither the tracked path nor the fix.
			return fmt.Errorf("create symlink %s: %w; on Windows, enable Developer Mode or use an elevated shell", full, err)
		}
		return err
	}
	return nil
}

// treeWriter materializes a whole tree in a single pass (a pack-and-seal extraction).
// It records the symlinks it writes so it can tell two cases apart that look identical
// on disk: a stale local file or symlink the remote replaced with a directory (cleared
// so the directory can be created — a legitimate type change), versus a symlink this
// same pass created and then writes through (refused — the traversal a hostile archive
// attempts, which refuseSymlinkParents blocks for the per-entry chunked path).
type treeWriter struct {
	dir     string
	created map[string]bool // relative slash paths this pass wrote as symlinks
	dirs    []DirEntry      // tracked directories written this pass, for applyDirModes
}

func newTreeWriter(dir string) *treeWriter {
	return &treeWriter{dir: dir, created: map[string]bool{}}
}

func (w *treeWriter) writeFile(e Entry, write func(w io.Writer) error) (int64, error) {
	full, err := safeJoin(w.dir, e.Path)
	if err != nil {
		return 0, err
	}
	return materializeAt(full, entryMode(e), func() error { return w.prepareParents(full) }, write)
}

func (w *treeWriter) writeSymlink(e Entry) error {
	full, err := safeJoin(w.dir, e.Path)
	if err != nil {
		return err
	}
	if err := writeSymlinkAt(full, e.Link, func() error { return w.prepareParents(full) }); err != nil {
		return err
	}
	w.created[w.relKey(full)] = true
	return nil
}

// writeDir creates a tracked directory during a whole-tree pass, using the same
// stale-parent handling as the file and symlink writers rather than refusing outright.
// The recorded mode is deliberately not applied here — the archive lists a directory
// ahead of the entries under it, so a mode that denies write would block its own
// children; applyDirModes sets it once the pass is done.
func (w *treeWriter) writeDir(d DirEntry) error {
	full, err := safeJoin(w.dir, d.Path)
	if err != nil {
		return err
	}
	if err := w.prepareParents(full); err != nil {
		return err
	}
	// prepareParents stops short of the leaf, which the file and symlink writers
	// replace rather than follow. A directory has to do the same clearing itself, or
	// MkdirAll fails on the stale file or symlink standing where the directory goes.
	if err := w.clearStaleLeaf(full); err != nil {
		return err
	}
	if err := os.MkdirAll(full, 0o700); err != nil {
		return err
	}
	w.dirs = append(w.dirs, d)
	return nil
}

// applyDirModes sets the recorded mode of every directory this pass created.
func (w *treeWriter) applyDirModes() error { return applyDirModes(w.dir, w.dirs) }

// clearStaleLeaf removes a non-directory at full: a path the remote turned into a
// directory. Replacing the entry is never a traversal — the escape prepareParents
// guards against is descending *through* a symlink, not overwriting one.
func (w *treeWriter) clearStaleLeaf(full string) error {
	fi, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return nil
	}
	if err := os.Remove(full); err != nil {
		return err
	}
	delete(w.created, w.relKey(full))
	return nil
}

func (w *treeWriter) relKey(full string) string {
	rel, _ := filepath.Rel(w.dir, full)
	return filepath.ToSlash(rel)
}

// prepareParents clears a stale local file or symlink occupying a parent path
// component of full — a remote entry that became a directory — so MkdirAll can create
// the real directory. It refuses a component this pass wrote as a symlink: that is a
// hostile archive creating a symlink and then writing a file through it.
func (w *treeWriter) prepareParents(full string) error {
	rel, err := filepath.Rel(w.dir, full)
	if err != nil {
		return err
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := w.dir
	for _, part := range parts[:len(parts)-1] { // parents only; the leaf is replaced, not followed
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil // nothing below here exists yet; MkdirAll will create real dirs
		}
		if err != nil {
			return err
		}
		if fi.IsDir() {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 && w.created[w.relKey(cur)] {
			return fmt.Errorf("path %q descends through a symlink at %q", rel, cur)
		}
		// A stale local file or symlink the remote turned into a directory. Removing it
		// clears the whole subtree (it has no children), so MkdirAll recreates the chain.
		if err := os.Remove(cur); err != nil {
			return err
		}
		return nil
	}
	return nil
}

// HashOnDisk returns the content hash of dir/relPath as Take/Scan would record it (a
// regular file's streamed sha256, a symlink's domain-separated linkHash), plus whether
// the path exists and whether it is a directory. The apply guard uses it to re-verify
// a file still holds the bytes the snapshot saw before a destructive download or delete
// overwrites it. A directory (a remote dir->file replacement target) is reported as
// such so the caller lets materialize handle it instead of trying to hash it; a special
// file (device/socket/fifo) is reported as present with an empty hash, which never
// matches a real content hash, so the guard refuses to clobber it.
func HashOnDisk(dir, relPath string) (hash string, exists, isDir bool, err error) {
	full, err := safeJoin(dir, relPath)
	if err != nil {
		return "", false, false, err
	}
	fi, err := os.Lstat(full)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		// Absent, or unreachable because a parent component is a file or stale symlink
		// the apply will replace: nothing exists at this exact path to destroy.
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(full)
		if err != nil {
			return "", false, false, err
		}
		return linkHash(target), true, false, nil
	case fi.IsDir():
		return "", true, true, nil
	case fi.Mode().IsRegular():
		h, err := streamHash(full)
		if err != nil {
			return "", false, false, err
		}
		return h, true, false, nil
	default:
		return "", true, false, nil
	}
}

// MaterializeDirs creates every tracked directory under dir and then applies their
// recorded modes. It materializes the empty tracked directories a file download does
// not create on its own, and applies directory permission changes to the ones that
// already exist.
//
// Creation runs shallowest first so a parent exists before its children; the modes
// come after, because a directory whose recorded mode denies write cannot receive the
// children created below it (see applyDirModes).
func MaterializeDirs(dir string, dirs []DirEntry) error {
	ordered := append([]DirEntry(nil), dirs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for _, d := range ordered {
		full, err := safeJoin(dir, d.Path)
		if err != nil {
			return err
		}
		if err := refuseSymlinkParents(dir, full); err != nil {
			return err
		}
		if err := os.MkdirAll(full, 0o700); err != nil {
			return err
		}
	}
	return applyDirModes(dir, ordered)
}

// applyDirModes sets each tracked directory's recorded mode, deepest first: a parent
// whose mode denies write or traversal must not take effect while the tree below it is
// still being built.
func applyDirModes(dir string, dirs []DirEntry) error {
	ordered := append([]DirEntry(nil), dirs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path > ordered[j].Path })
	for _, d := range ordered {
		full, err := safeJoin(dir, d.Path)
		if err != nil {
			return err
		}
		if err := os.Chmod(full, dirMode(d)); err != nil {
			return err
		}
	}
	return nil
}

func dirMode(d DirEntry) os.FileMode {
	if m := os.FileMode(d.Mode).Perm(); m != 0 {
		return m
	}
	return 0o700
}

// EnsureDirs recreates every tracked directory under dir that is missing, applying
// recorded modes only to the ones it creates. It is the healing pass after the
// destructive half of an apply: RemoveFile and RemoveDir prune now-empty parent
// directories with no regard for the tracked set, so a delete that empties a
// tracked directory takes the directory with it — and the next scan would read that
// as a local delete and push it fleet-wide. Directories that already exist are left
// untouched, so a mode this pass did not create is never clobbered.
func EnsureDirs(dir string, dirs []DirEntry) error {
	ordered := append([]DirEntry(nil), dirs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	var created []DirEntry
	for _, d := range ordered {
		full, err := safeJoin(dir, d.Path)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(full); err == nil {
			continue
		}
		if err := refuseSymlinkParents(dir, full); err != nil {
			return err
		}
		if err := os.MkdirAll(full, 0o700); err != nil {
			return err
		}
		created = append(created, d)
	}
	return applyDirModes(dir, created)
}

// RemoveDir removes a tracked directory under dir only if it is empty, then prunes
// now-empty parents up to (but not including) the tracked root. A directory still
// holding entries (untracked files, or tracked ones not yet deleted) is left in
// place rather than destroyed.
func RemoveDir(dir, relPath string) error {
	full, err := safeJoin(dir, relPath)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(full)
	if os.IsNotExist(err) {
		return nil
	}
	// The path is no longer a directory: a remote dir->file type change replaced it with a
	// regular file (materialized earlier in the same apply). There is no directory to remove
	// and the replacement file must be left alone, so treat it as done rather than failing.
	if errors.Is(err, syscall.ENOTDIR) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return nil
	}
	if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
		return err
	}
	for parent := filepath.Dir(full); parent != dir; parent = filepath.Dir(parent) {
		if err := os.Remove(parent); err != nil {
			break
		}
	}
	return nil
}

// RenameCaseOnly moves dir/fromRel to dir/toRel, for paths that differ only by
// case: on a case-folding filesystem both names resolve to one physical entry, so
// the rename fixes its stored case in place instead of the caller deleting the
// old name (which would destroy the survivor). A missing source is not an error —
// on a genuinely case-sensitive filesystem (the test seam) an earlier ancestor
// rename may already have moved it, so the source is retried under the target's
// parent before giving up.
func RenameCaseOnly(dir, fromRel, toRel string) error {
	from, err := safeJoin(dir, fromRel)
	if err != nil {
		return err
	}
	to, err := safeJoin(dir, toRel)
	if err != nil {
		return err
	}
	if _, statErr := os.Lstat(from); os.IsNotExist(statErr) {
		alt := filepath.Join(filepath.Dir(to), filepath.Base(from))
		if _, altErr := os.Lstat(alt); os.IsNotExist(altErr) {
			return nil
		}
		from = alt
	}
	if from == to {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
