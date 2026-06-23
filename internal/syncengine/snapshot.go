package syncengine

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Snapshot is the result of scanning a tracked directory: the manifest plus the
// ciphertexts of any chunks it (re)sealed, keyed by chunk id, so the caller can
// upload the ones the server is missing.
type Snapshot struct {
	Manifest  Manifest
	NewChunks map[string][]byte
}

// fileNode is one tracked entry surfaced by the walk: either a symlink (target
// set) or a regular file (data set).
type fileNode struct {
	rel     string
	info    fs.FileInfo
	symlink bool
	target  string
	data    []byte
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
			return fn(fileNode{rel: rel, info: info, symlink: true, target: target})
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fn(fileNode{rel: rel, info: info, data: data})
	})
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// metaEntry builds the path/size/mode/hash (and Link, for symlinks) part of an
// entry. The link hash is domain-separated from file content so a file whose
// bytes equal a link's target is never mistaken for unchanged.
func metaEntry(n fileNode) Entry {
	if n.symlink {
		return Entry{Path: n.rel, Size: int64(len(n.target)), Link: n.target, Hash: hashOf([]byte("symlink\x00" + n.target))}
	}
	return Entry{Path: n.rel, Mode: uint32(n.info.Mode().Perm()), Size: n.info.Size(), Hash: hashOf(n.data)}
}

// Scan reads dir into a manifest of path/size/mode/hash (and link targets) only —
// no sealing — for cheap change detection (e.g. `status`) without the convergence
// key. Nested .aqtignore files are honored.
func Scan(dir string) (Manifest, error) {
	var m Manifest
	err := walkFiles(dir, func(n fileNode) error {
		m.Entries = append(m.Entries, metaEntry(n))
		return nil
	})
	sortEntries(m.Entries)
	return m, err
}

// Take scans dir into a Snapshot. Files at or below the chunker minimum are
// stored inline; larger files are chunked and sealed under the convergence key.
// When base is non-nil, a file whose plaintext is unchanged reuses its previous
// entry verbatim — so unchanged files are neither re-sealed nor re-listed for
// upload.
func Take(dir string, conv crypto.ConvergenceKey, chunker *Chunker, base *Manifest) (*Snapshot, error) {
	var reuse map[string]Entry
	if base != nil {
		reuse = base.byPath()
	}
	snap := &Snapshot{NewChunks: map[string][]byte{}}

	err := walkFiles(dir, func(n fileNode) error {
		entry := metaEntry(n)
		if prev, ok := reuse[n.rel]; ok && prev.Hash == entry.Hash {
			snap.Manifest.Entries = append(snap.Manifest.Entries, prev)
			return nil
		}
		switch {
		case n.symlink:
			// fully described by metaEntry (target in Link); nothing to seal
		case len(n.data) <= chunker.Min:
			entry.Inline = n.data
		default:
			for _, piece := range chunker.Split(n.data) {
				ct, ch, err := crypto.SealChunk(piece, conv)
				if err != nil {
					return err
				}
				entry.Chunks = append(entry.Chunks, ch)
				snap.NewChunks[ch.ID] = ct
			}
		}
		snap.Manifest.Entries = append(snap.Manifest.Entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sortEntries(snap.Manifest.Entries)
	return snap, nil
}
