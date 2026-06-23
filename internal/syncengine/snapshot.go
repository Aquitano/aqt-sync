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

// walkFiles invokes fn for every tracked regular file under dir (ignored paths
// and non-regular files are skipped), passing each file's relative POSIX path,
// info, and contents.
func walkFiles(dir string, ig *Ignore, fn func(rel string, info fs.FileInfo, data []byte) error) error {
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
			return nil
		}
		if d.IsDir() {
			if ig.Match(rel, true) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || ig.Match(rel, false) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return fn(rel, info, data)
	})
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func entryMeta(rel string, info fs.FileInfo, hash string) Entry {
	return Entry{Path: rel, Mode: uint32(info.Mode().Perm()), Size: info.Size(), Hash: hash}
}

// Scan reads dir into a manifest of path/size/mode/hash only — no sealing — for
// cheap change detection (e.g. `status`) without needing the convergence key.
func Scan(dir string, ig *Ignore) (Manifest, error) {
	var m Manifest
	err := walkFiles(dir, ig, func(rel string, info fs.FileInfo, data []byte) error {
		m.Entries = append(m.Entries, entryMeta(rel, info, hashOf(data)))
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
func Take(dir string, ig *Ignore, conv crypto.ConvergenceKey, chunker *Chunker, base *Manifest) (*Snapshot, error) {
	var reuse map[string]Entry
	if base != nil {
		reuse = base.byPath()
	}
	snap := &Snapshot{NewChunks: map[string][]byte{}}

	err := walkFiles(dir, ig, func(rel string, info fs.FileInfo, data []byte) error {
		hash := hashOf(data)
		if prev, ok := reuse[rel]; ok && prev.Hash == hash {
			snap.Manifest.Entries = append(snap.Manifest.Entries, prev)
			return nil
		}
		entry := entryMeta(rel, info, hash)
		if len(data) <= chunker.Min {
			entry.Inline = data
		} else {
			for _, piece := range chunker.Split(data) {
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
