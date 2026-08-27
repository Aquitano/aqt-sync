// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/aquitano/aqt-sync/internal/compress"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// EntryFromBytes seals one in-memory regular file into the same Entry shape Take
// produces. It is used for bounded derived content such as a clean text merge,
// avoiding a whole-tree rescan merely to upload one resolved file.
func EntryFromBytes(path string, data []byte, mode uint32, conv crypto.ConvergenceKey, selector ChunkSelector, sink ChunkSink) (Entry, error) {
	e := Entry{Path: path, Mode: mode, Size: int64(len(data)), Hash: hashOf(data)}
	chunker := selector.ChunkerFor(e.Size)
	if e.Size <= int64(chunker.Min) {
		e.Inline, e.InlineAlg = compress.Encode(data)
		return e, nil
	}
	// Past the inline threshold every chunk's ciphertext goes only to the sink;
	// discarding it would leave the returned entry pointing at chunks nobody stored.
	if sink == nil {
		return Entry{}, errors.New("syncengine: chunk sink is required for chunked content")
	}
	seal := sealStream
	if e.Size < serialSealCutoff {
		seal = sealSerial
	}
	chunks, _, err := seal(bytes.NewReader(data), conv, chunker, sink)
	if err != nil {
		return Entry{}, err
	}
	e.Chunks = chunks
	return e, nil
}

// ChunkSink receives the ciphertext of each chunk a snapshot seals for a changed
// file, so the caller can pack and upload it without the snapshot ever holding the
// whole tree in memory. ciphertext is owned by the sink after the call returns
// (crypto.SealChunk produces an independent allocation, so no copy is needed).
type ChunkSink interface {
	Add(ch crypto.Chunk, ciphertext []byte) error
}

// nopSink discards chunks; Take uses it when a snapshot only needs the manifest
// (no upload), though callers typically reach for Scan in that case.
type nopSink struct{}

func (nopSink) Add(crypto.Chunk, []byte) error { return nil }

// fileNode is one tracked entry surfaced by the walk: either a symlink (target
// set) or a regular file. The walk reads no file content — it carries the path so
// a caller can stream the file itself, keeping walk memory O(1) per node.
type fileNode struct {
	rel     string
	path    string
	info    fs.FileInfo
	symlink bool
	target  string
}

// SkippedPath is one tracked path a scan could not read. The scan records it and
// moves on: one unreadable file (a root-owned file, a directory this user cannot
// enter) is a per-file problem, not a reason to wedge the whole folder. The scan
// keeps whatever the base manifest recorded for such a path, so nothing is deleted
// for being unreadable; callers report the list so the skip is never silent.
type SkippedPath struct {
	Path string
	// Err is the bare cause (the syscall error), not the wrapping fs.PathError: the
	// path is already in Path, and repeating it absolute in every warning line is
	// noise. It still matches errors.Is(err, fs.ErrPermission).
	Err error
}

// skipList collects one walk's unreadable paths.
type skipList struct{ paths []SkippedPath }

// tolerate classifies a failure to read one tracked path. A vanished entry is churn
// — the walk listed it and it was gone by the time we looked (an editor swap file, a
// finished download renaming itself, a build cleaning up) — so it is skipped
// silently and the next scan sees the tree as it then is. An unreadable one is
// recorded and skipped. Anything else fails the walk, as does any error that is not
// a filesystem error against this very path: a sealing or upload failure reaches the
// same callback and must not be mistaken for churn.
func (s *skipList) tolerate(rel, path string, err error) error {
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) || pathErr.Path != path {
		return err
	}
	switch {
	// ENOTDIR is the directory flavor of vanished: a parent component stopped being
	// a directory between the listing and this read (HashOnDisk treats it the same).
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return nil
	case errors.Is(err, fs.ErrPermission), lockedByAnotherProcess(err):
		s.paths = append(s.paths, SkippedPath{Path: rel, Err: pathErr.Err})
		return nil
	}
	return err
}

// walkFiles invokes fn for every tracked symlink and regular file under dir, and
// onDir (when non-nil) for every tracked directory. Ignored paths and other special
// files (devices, sockets, fifos) are skipped. It loads each directory's .aqtignore
// as it descends (skipping ignored directories, whose .aqtignore is therefore never
// consulted), so nested rules apply to their subtree. Symlinks are read with
// Readlink — never followed — so a link into an ignored or out-of-tree location is
// captured as its target.
//
// A path the walk cannot read is passed to skips rather than aborting the tree; only
// the tracked root itself is fatal, since there would be no tree left to describe.
func walkFiles(dir string, skips *skipList, fn func(fileNode) error, onDir func(rel string, info fs.FileInfo) error) error {
	ig := newIgnore()
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if walkErr != nil {
			// Only a directory whose listing failed reaches this (an ignored one returned
			// SkipDir before it was read), plus the root itself when it cannot be statted.
			if rel == "." {
				return walkErr
			}
			return skips.tolerate(rel, path, walkErr)
		}
		if rel == "." {
			ig.loadDir(dir, "")
			return nil
		}
		if d.IsDir() {
			if ig.Match(rel, true) {
				return filepath.SkipDir
			}
			ig.loadDir(path, rel)
			if onDir != nil {
				info, err := d.Info()
				if err != nil {
					return skips.tolerate(rel, path, err)
				}
				if err := onDir(rel, info); err != nil {
					return err
				}
			}
			return nil
		}
		if ig.Match(rel, false) {
			return nil
		}
		// Only paths that survive the ignore filter are sealed into the manifest, and
		// json.Marshal silently coerces invalid UTF-8 to U+FFFD — which would restore
		// the file under a corrupted name and collapse two siblings differing only in
		// invalid bytes into one, losing a file. Refuse the tree, naming the offender.
		// Ignored paths are skipped above, so a non-UTF-8 name in an ignored cache or
		// build dir never wedges the sync.
		if !utf8.ValidString(rel) {
			return fmt.Errorf("path %q is not valid UTF-8; rename it to sync this folder", rel)
		}
		info, err := d.Info()
		if err != nil {
			return skips.tolerate(rel, path, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return skips.tolerate(rel, path, err)
			}
			return fn(fileNode{rel: rel, path: path, info: info, symlink: true, target: target})
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return fn(fileNode{rel: rel, path: path, info: info})
	})
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// streamHash returns the hex sha256 of a file's contents without holding it in
// memory — the bounded-memory change detector for files too large to inline.
func streamHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// metaEntry builds the path/size/mode (and Link/Hash, for symlinks) part of an
// entry. A regular file's content Hash is filled in by the caller after it reads
// or streams the bytes.
func metaEntry(n fileNode) Entry {
	if n.symlink {
		return Entry{Path: n.rel, Size: int64(len(n.target)), Link: n.target, Hash: linkHash(n.target)}
	}
	return Entry{Path: n.rel, Mode: uint32(n.info.Mode().Perm()), Size: n.info.Size(), MTime: n.info.ModTime().UnixNano()}
}

// linkHash hashes a symlink's target, domain-separated from file content so a file
// whose bytes equal a link's target is never mistaken for it. Pack-and-seal extraction
// reuses it so an untarred tree scans back to identical hashes.
func linkHash(target string) string {
	return hashOf([]byte("symlink\x00" + target))
}

// Scan reads dir into a manifest of path/size/mode/hash (and link targets) only —
// no sealing — for cheap change detection (e.g. `status`, and the local side of a
// pull-only sync) without the convergence key. Large files are hashed streaming,
// so scan memory is bounded regardless of file size. Nested .aqtignore files are
// honored.
func Scan(dir string) (Manifest, error) {
	return ScanReusing(dir, nil, false)
}

// ScanReusing is Scan with the last-synced manifest as a stat fast-path: a regular
// file whose size, mode, and mtime match its base entry reuses the recorded entry
// (hash and content refs) without being read — the same signal Take trusts — so
// `status` and pull-only syncs stop re-reading an unchanged tree. A file that fails
// the stat check is re-hashed, and one whose content still matches keeps its base
// entry (with the new mtime/mode) so content refs survive. rehash forces the
// content hash for the rare edit that preserves size, mode, and mtime.
func ScanReusing(dir string, base *Manifest, rehash bool) (Manifest, error) {
	var reuse map[string]Entry
	var reuseDirs map[string]DirEntry
	if base != nil {
		reuse = base.byPath()
		reuseDirs = base.DirsByPath()
	}
	var m Manifest
	var skips skipList
	err := walkFiles(dir, &skips, func(n fileNode) error {
		e := metaEntry(n)
		if !n.symlink {
			prev, inBase := reuse[n.rel]
			e.Mode = scanFileMode(n.info, prev.Mode, inBase)
			if inBase && !rehash && unchangedStat(prev, e) {
				m.Entries = append(m.Entries, prev)
				return nil
			}
			h, err := streamHash(n.path)
			if err != nil {
				return skips.tolerate(n.rel, n.path, err)
			}
			if inBase && h == prev.Hash {
				m.Entries = append(m.Entries, touchedReuse(prev, e))
				return nil
			}
			e.Hash = h
		}
		m.Entries = append(m.Entries, e)
		return nil
	}, func(rel string, info fs.FileInfo) error {
		prev, inBase := reuseDirs[rel]
		m.Dirs = append(m.Dirs, DirEntry{Path: rel, Mode: scanDirMode(info, prev.Mode, inBase)})
		return nil
	})
	m.Skipped = skips.paths
	keepUnreadable(&m, base)
	keepUnsupportedLinks(&m, base, dir)
	sortEntries(m.Entries)
	sortDirs(m.Dirs)
	return m, err
}

// keepUnreadable re-adds base's record of every path the scan could not read, so an
// unreadable file — or the subtree under a directory the walk could not enter — reads
// as unchanged rather than deleted. Without it a single `chmod 000` would plan a
// remote delete for content that is still sitting on disk.
func keepUnreadable(m *Manifest, base *Manifest) {
	if len(m.Skipped) == 0 || base == nil {
		return
	}
	haveEntry := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		haveEntry[e.Path] = true
	}
	haveDir := make(map[string]bool, len(m.Dirs))
	for _, d := range m.Dirs {
		haveDir[d.Path] = true
	}
	for _, s := range m.Skipped {
		for _, e := range base.Entries {
			if !haveEntry[e.Path] && underPath(s.Path, e.Path) {
				m.Entries = append(m.Entries, e)
				haveEntry[e.Path] = true
			}
		}
		for _, d := range base.Dirs {
			if !haveDir[d.Path] && underPath(s.Path, d.Path) {
				m.Dirs = append(m.Dirs, d)
				haveDir[d.Path] = true
			}
		}
	}
}

// underPath reports whether p is root itself or lies beneath it.
func underPath(root, p string) bool {
	return p == root || strings.HasPrefix(p, root+"/")
}

// keepUnsupportedLinks re-adds base's symlink entries the walk did not see when the
// filesystem cannot create symlinks at all: there (Windows without Developer Mode)
// their absence is inability, not intent, and reading it as a local delete would
// remove every symlink from the server. The probe runs only when a base link is
// actually missing, so ordinary scans never pay for it — and on a filesystem that
// does support links, a genuinely deleted one still propagates as a delete.
func keepUnsupportedLinks(m *Manifest, base *Manifest, dir string) {
	m.Entries = append(m.Entries, unsupportedBaseLinks(m, base, dir)...)
}

// unsupportedBaseLinks returns base's symlink entries that m lacks, but only on a
// filesystem where their absence means inability rather than deletion.
func unsupportedBaseLinks(m *Manifest, base *Manifest, dir string) []Entry {
	if base == nil {
		return nil
	}
	have := make(map[string]bool, len(m.Entries))
	for _, e := range m.Entries {
		have[e.Path] = true
	}
	var missing []Entry
	for _, e := range base.Entries {
		if e.IsSymlink() && !have[e.Path] {
			missing = append(missing, e)
		}
	}
	if len(missing) == 0 || SymlinkSupport(dir) {
		return nil
	}
	return missing
}

// namePaths renders skipped paths for a message, naming the first few and counting
// the rest so one unreadable directory of ten thousand files stays one line.
func namePaths(skipped []SkippedPath) string {
	const show = 3
	names := make([]string, 0, show)
	for _, s := range skipped[:min(show, len(skipped))] {
		names = append(names, strconv.Quote(s.Path))
	}
	out := strings.Join(names, ", ")
	if rest := len(skipped) - len(names); rest > 0 {
		out += fmt.Sprintf(" and %d more", rest)
	}
	return out
}

// ListPaths returns the relative slash path of every tracked file and symlink under
// dir, honoring .aqtignore. It is the hash-free walk a prune needs: unlike Scan it
// reads no file content, so it is cheap on a large tree.
func ListPaths(dir string) ([]string, error) {
	var paths []string
	var skips skipList
	err := walkFiles(dir, &skips, func(n fileNode) error {
		paths = append(paths, n.rel)
		return nil
	}, nil)
	return paths, err
}

// Fingerprint summarizes the tracked tree from metadata only — path, size,
// mtime, mode, and symlink target — without reading any file contents. It is the
// watch daemon's cheap change detector: one lstat per file instead of a full
// read+hash, so a continuously-polling watcher does not re-read the whole tree
// every tick. It walks exactly what Scan walks, so the same .aqtignore rules apply
// and the same churn is tolerated — the watcher fingerprints the busiest trees there
// are, so one file vanishing mid-walk must not cost it a tick.
//
// The residual gap versus a content hash is an edit that preserves size, mode,
// and mtime to the nanosecond — exceedingly rare, and caught on the next stat
// change anyway because the authoritative content hashing happens in Take when a
// sync actually runs.
func Fingerprint(dir string) (string, error) {
	h := sha256.New()
	var skips skipList
	err := walkFiles(dir, &skips, func(n fileNode) error {
		if n.symlink {
			fmt.Fprintf(h, "L\x00%s\x00%s\n", n.rel, n.target)
			return nil
		}
		fmt.Fprintf(h, "F\x00%s\x00%d\x00%d\x00%o\n", n.rel, n.info.Size(), n.info.ModTime().UnixNano(), n.info.Mode().Perm())
		return nil
	}, nil)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Take scans dir into a manifest, streaming each file so memory stays O(one pack
// buffer + manifest) regardless of file or tree size. Files at or below the chunker
// minimum are inlined; larger files are chunked and sealed under the convergence
// key, and each sealed chunk's ciphertext is handed to sink (the pack assembler) as
// it is produced — Take never accumulates ciphertext itself.
//
// When base is non-nil, an unchanged file reuses its previous entry verbatim, so it
// is neither re-read nor re-sealed: if size+mode+mtime still match the base entry the
// content is taken as unchanged with no read at all (the same mtime-granularity
// signal Fingerprint trusts to gate the watcher). rehash forces the authoritative
// content hash for the rare edit that preserves all three; a file that fails the stat
// check is hashed and only re-sealed if its content actually changed.
//
// sink may be nil for a manifest-only snapshot (no upload).
func Take(dir string, conv crypto.ConvergenceKey, chunker ChunkSelector, base *Manifest, sink ChunkSink, rehash bool) (Manifest, error) {
	if sink == nil {
		sink = nopSink{}
	}
	var reuse map[string]Entry
	var reuseDirs map[string]DirEntry
	if base != nil {
		reuse = base.byPath()
		reuseDirs = base.DirsByPath()
	}
	var m Manifest
	var skips skipList

	err := walkFiles(dir, &skips, func(n fileNode) error {
		if n.symlink {
			e := metaEntry(n)
			if prev, ok := reuse[n.rel]; ok && prev.Hash == e.Hash {
				e = prev
			}
			m.Entries = append(m.Entries, e)
			return nil
		}
		e, err := snapshotFile(n, reuse, conv, chunker, sink, rehash)
		if err != nil {
			return skips.tolerate(n.rel, n.path, err)
		}
		m.Entries = append(m.Entries, e)
		return nil
	}, func(rel string, info fs.FileInfo) error {
		prev, inBase := reuseDirs[rel]
		m.Dirs = append(m.Dirs, DirEntry{Path: rel, Mode: scanDirMode(info, prev.Mode, inBase)})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	m.Skipped = skips.paths
	keepUnreadable(&m, base)
	keepUnsupportedLinks(&m, base, dir)
	sortEntries(m.Entries)
	sortDirs(m.Dirs)
	return m, nil
}

// snapshotFile turns one regular file into an entry, reusing the base entry when
// the content is unchanged so it is neither re-read nor re-sealed. Small files
// inline; larger ones stream through the chunker into sink.
func snapshotFile(n fileNode, reuse map[string]Entry, conv crypto.ConvergenceKey, selector ChunkSelector, sink ChunkSink, rehash bool) (Entry, error) {
	entry := metaEntry(n)
	prev, inBase := reuse[n.rel]
	entry.Mode = scanFileMode(n.info, prev.Mode, inBase)
	size := n.info.Size()

	// Stat fast-path: identical size, mode, and mtime means the content is unchanged,
	// so reuse the base entry without opening the file. This skips the whole-tree
	// read+hash a stable tree otherwise pays on every sync. rehash forces the content
	// check below for the rare edit that leaves all three untouched.
	if !rehash && inBase && unchangedStat(prev, entry) {
		return prev, nil
	}

	// Pick the chunker for this file's size before deciding to inline: its Min is the
	// inline cutoff, and the smallest tier (used for everything inlinable) keeps that
	// cutoff at the default so inline behavior is unchanged.
	chunker := selector.ChunkerFor(size)

	// Small files are inlined into the (sealed) manifest; read fully — bounded by
	// the inline cutoff — and hash.
	if size <= int64(chunker.Min) {
		data, err := os.ReadFile(n.path)
		if err != nil {
			return Entry{}, err
		}
		entry.Hash = hashOf(data)
		if inBase && prev.Hash == entry.Hash {
			return touchedReuse(prev, entry), nil
		}
		entry.Inline, entry.InlineAlg = compress.Encode(data)
		return entry, nil
	}

	// Large files: if base holds a same-size entry, hash first (one read, no seal)
	// to skip re-sealing an unchanged file. Otherwise it is new or changed and must
	// be sealed regardless.
	if inBase && prev.Size == size {
		h, err := streamHash(n.path)
		if err != nil {
			return Entry{}, err
		}
		if h == prev.Hash {
			return touchedReuse(prev, entry), nil
		}
	}
	return sealFile(n, entry, conv, chunker, sink)
}

// unchangedStat reports whether cur's stat metadata matches prev so closely that the
// content is taken as unchanged without reading it. A zero prev.MTime (an entry from
// before mtimes were recorded, or a symlink) never matches, forcing a content hash.
func unchangedStat(prev, cur Entry) bool {
	return prev.MTime != 0 && prev.MTime == cur.MTime && prev.Size == cur.Size && prev.Mode == cur.Mode
}

// touchedReuse reuses prev's content (chunks/inline/hash) but adopts cur's mtime and
// mode, so a file touched without a content change records its new mtime in the manifest
// and the next sync stat-fast-paths it instead of re-hashing forever. Mode is a synced
// attribute, so a permission-only change (e.g. chmod +x) must carry through here even
// though the content read was skipped — otherwise the new mode is lost before upload.
func touchedReuse(prev, cur Entry) Entry {
	prev.MTime = cur.MTime
	prev.Mode = cur.Mode
	return prev
}

// sealFile streams a file through the chunker once, sealing each chunk into sink
// (fanned across cores by sealStream for content large enough to amortize the
// pool, inline otherwise — same chunks, same order either way) and computing the
// content hash from the same pass.
func sealFile(n fileNode, entry Entry, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) (Entry, error) {
	f, err := os.Open(n.path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	seal := sealStream
	if n.info.Size() < serialSealCutoff {
		seal = sealSerial
	}
	h := sha256.New()
	tee := io.TeeReader(f, h)
	chunks, _, err := seal(tee, conv, chunker, sink)
	if err != nil {
		return Entry{}, err
	}
	entry.Chunks = chunks
	entry.Hash = hex.EncodeToString(h.Sum(nil))
	return entry, nil
}
