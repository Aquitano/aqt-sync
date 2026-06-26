package syncengine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

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

// walkFiles invokes fn for every tracked symlink and regular file under dir.
// Ignored paths and other special files (devices, sockets, fifos) are skipped.
// It loads each directory's .aqtignore as it descends (skipping ignored
// directories, whose .aqtignore is therefore never consulted), so nested rules
// apply to their subtree. Symlinks are read with Readlink — never followed — so
// a link into an ignored or out-of-tree location is captured as its target.
func walkFiles(dir string, fn func(fileNode) error) error {
	ig := newIgnore()
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			ig.loadDir(dir, "")
			return nil
		}
		if d.IsDir() {
			if ig.Match(rel, true) {
				return filepath.SkipDir
			}
			ig.loadDir(path, rel)
			return nil
		}
		if ig.Match(rel, false) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
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
	return Entry{Path: n.rel, Mode: uint32(n.info.Mode().Perm()), Size: n.info.Size()}
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
	var m Manifest
	err := walkFiles(dir, func(n fileNode) error {
		e := metaEntry(n)
		if !n.symlink {
			h, err := streamHash(n.path)
			if err != nil {
				return err
			}
			e.Hash = h
		}
		m.Entries = append(m.Entries, e)
		return nil
	})
	sortEntries(m.Entries)
	return m, err
}

// ListPaths returns the relative slash path of every tracked file and symlink under
// dir, honoring .aqtignore. It is the hash-free walk a prune needs: unlike Scan it
// reads no file content, so it is cheap on a large tree.
func ListPaths(dir string) ([]string, error) {
	var paths []string
	err := walkFiles(dir, func(n fileNode) error {
		paths = append(paths, n.rel)
		return nil
	})
	return paths, err
}

// Fingerprint summarizes the tracked tree from metadata only — path, size,
// mtime, mode, and symlink target — without reading any file contents. It is the
// watch daemon's cheap change detector: one lstat per file instead of a full
// read+hash, so a continuously-polling watcher does not re-read the whole tree
// every tick. Honors nested .aqtignore exactly as Scan does.
//
// The residual gap versus a content hash is an edit that preserves size, mode,
// and mtime to the nanosecond — exceedingly rare, and caught on the next stat
// change anyway because the authoritative content hashing happens in Take when a
// sync actually runs.
func Fingerprint(dir string) (string, error) {
	h := sha256.New()
	ig := newIgnore()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			ig.loadDir(dir, "")
			return nil
		}
		if d.IsDir() {
			if ig.Match(rel, true) {
				return filepath.SkipDir
			}
			ig.loadDir(path, rel)
			return nil
		}
		if ig.Match(rel, false) {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "L\x00%s\x00%s\n", rel, target)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "F\x00%s\x00%d\x00%d\x00%o\n", rel, info.Size(), info.ModTime().UnixNano(), info.Mode().Perm())
		return nil
	})
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
// When base is non-nil, a file whose content is unchanged reuses its previous entry
// verbatim, so it is neither re-sealed nor re-uploaded. The unchanged check reads
// the file once to hash it (the read a sync must do anyway) but skips the seal; a
// large file that did change is the only case sealed, and it streams.
//
// sink may be nil for a manifest-only snapshot (no upload).
func Take(dir string, conv crypto.ConvergenceKey, chunker *Chunker, base *Manifest, sink ChunkSink) (Manifest, error) {
	if sink == nil {
		sink = nopSink{}
	}
	var reuse map[string]Entry
	if base != nil {
		reuse = base.byPath()
	}
	var m Manifest

	err := walkFiles(dir, func(n fileNode) error {
		if n.symlink {
			e := metaEntry(n)
			if prev, ok := reuse[n.rel]; ok && prev.Hash == e.Hash {
				e = prev
			}
			m.Entries = append(m.Entries, e)
			return nil
		}
		e, err := snapshotFile(n, reuse, conv, chunker, sink)
		if err != nil {
			return err
		}
		m.Entries = append(m.Entries, e)
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sortEntries(m.Entries)
	return m, nil
}

// snapshotFile turns one regular file into an entry, reusing the base entry when
// the content is unchanged so it is not re-sealed. Small files inline; larger ones
// stream through the chunker into sink.
func snapshotFile(n fileNode, reuse map[string]Entry, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) (Entry, error) {
	entry := metaEntry(n)
	prev, inBase := reuse[n.rel]
	size := n.info.Size()

	// Small files are inlined into the (sealed) manifest; read fully — bounded by
	// the inline cutoff — and hash.
	if size <= int64(chunker.Min) {
		data, err := os.ReadFile(n.path)
		if err != nil {
			return Entry{}, err
		}
		entry.Hash = hashOf(data)
		if inBase && prev.Hash == entry.Hash {
			return prev, nil
		}
		entry.Inline = data
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
			return prev, nil
		}
	}
	return sealFile(n, entry, conv, chunker, sink)
}

// sealFile streams a file through the chunker once, sealing each chunk into sink
// and computing the content hash from the same pass.
func sealFile(n fileNode, entry Entry, conv crypto.ConvergenceKey, chunker *Chunker, sink ChunkSink) (Entry, error) {
	f, err := os.Open(n.path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	h := sha256.New()
	tee := io.TeeReader(f, h)
	err = chunker.SplitStream(tee, func(piece []byte) error {
		ct, ch, err := crypto.SealChunk(piece, conv)
		if err != nil {
			return err
		}
		entry.Chunks = append(entry.Chunks, ch)
		return sink.Add(ch, ct)
	})
	if err != nil {
		return Entry{}, err
	}
	entry.Hash = hex.EncodeToString(h.Sum(nil))
	return entry, nil
}
