// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// A resource's blob is stored as one immutable file per nonce
// (blobs/<id>.<hex-nonce>.bin). Each reseal draws a fresh nonce, so a content
// change writes a new file and never mutates an existing one; the resource's row
// (which carries the live blob_nonce) selects the authoritative file. A
// half-applied write can therefore only orphan a new file, never pair the row's
// nonce with mismatched bytes. A visibility flip keeps the nonce, so it needs no
// blob rewrite. Superseded files are reclaimed after the row that supersedes
// them commits.

// maxBlobNonce bounds the nonce a write may carry, well above the 24 bytes every
// client seals with, and short enough that the hex filename stays under 255 bytes.
const maxBlobNonce = 64

// blobPath addresses a resource's blob by id+nonce. Like packPath, it fans the file
// out by id prefix (blobs/<ab>/<cd>/<id>.<nonce>.bin) so blobs/ never grows into one
// flat directory whose every entry a glob (removeStaleBlobs) must scan.
func (s *Store) blobPath(id string, nonce []byte) string {
	return filepath.Join(s.blobDir(id), id+"."+hex.EncodeToString(nonce)+".bin")
}

// blobDir is the fan-out directory that holds id's blob file(s). Resource ids are
// fixed-length (newID(8)), so the prefix slice is always in range.
func (s *Store) blobDir(id string) string {
	return filepath.Join(s.blobsDir, id[0:2], id[2:4])
}

// writeBlob writes a blob to its nonce-addressed file and fsyncs it, so the bytes
// are durable before the referencing row commits.
func (s *Store) writeBlob(id string, nonce, ciphertext []byte) error {
	if err := os.MkdirAll(s.blobDir(id), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.blobPath(id, nonce), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Flush the directory entry so the new blob file's name is durable before the
	// referencing row commits, not just its bytes (see fsyncDir).
	return fsyncDir(s.blobDir(id))
}

// removeStaleBlobs deletes every blob file of id except the one for keepNonce
// (pass nil to drop them all). Best-effort: a leak here costs only disk, never
// correctness.
func (s *Store) removeStaleBlobs(id string, keepNonce []byte) {
	keep := s.blobPath(id, keepNonce)
	matches, _ := filepath.Glob(filepath.Join(s.blobDir(id), id+".*.bin"))
	for _, m := range matches {
		if m != keep {
			_ = os.Remove(m)
		}
	}
}

func (s *Store) readBlob(id string, nonce []byte) ([]byte, error) {
	b, err := os.ReadFile(s.blobPath(id, nonce))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// packPath fans out content-addressed packs by their id prefix to keep any one
// directory small: packs/<owner>/<ab>/<cd>/<id>.bin. The id is hex, so the path is
// safe on case-insensitive filesystems.
func (s *Store) packPath(owner, id string) string {
	return filepath.Join(s.packsDir, owner, id[0:2], id[2:4], id+".bin")
}

// writePack writes a pack to its content-addressed file via temp+fsync+rename, so
// the bytes are durable before the row that references them commits (a committed
// manifest must never point at a pack the kernel has not flushed).
func (s *Store) writePack(owner, id string, data []byte) error {
	tmp, err := s.stagePack(owner, id, data)
	if err != nil {
		return err
	}
	if err := s.commitStagedPack(tmp, s.packPath(owner, id)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// stagePack writes data to a uniquely named, fsynced temp file beside the pack's
// final path and returns its name. The name is unique so two uploads of the same
// pack can stage concurrently without truncating each other's bytes.
func (s *Store) stagePack(owner, id string, data []byte) (string, error) {
	dir := filepath.Dir(s.packPath(owner, id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, id+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// commitStagedPack renames a staged pack into place. It also flushes the directory
// entry: the renamed file's data is durable, but the rename itself (the entry
// pointing at it) is not until the dir is fsynced, so a committed manifest could
// otherwise reference a pack the kernel loses on a crash.
func (s *Store) commitStagedPack(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// newID returns a URL-safe random identifier encoding nBytes of entropy.
func newID(nBytes int) string {
	return encodeID(randomBytes(nBytes))
}

// newIDFrom encodes given bytes in the newID shape, so a deterministic decoy
// handle is indistinguishable from a freshly minted one.
func newIDFrom(b []byte) string {
	return encodeID(b)
}

// encodeID is the one id spelling both generators share. base64url's alphabet
// includes '-', and a leading one makes the id unaddressable as a bare CLI
// positional (cobra reads it as a flag cluster), so it is folded to 'A'. Doing the
// fold here rather than by re-drawing keeps newIDFrom byte-deterministic and leaves
// the two generators' output distributions identical, so a leading character can
// never distinguish a decoy handle from a minted one.
func encodeID(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	if strings.HasPrefix(s, "-") {
		return "A" + s[1:]
	}
	return s
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}
