package syncengine

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Pack-and-seal is the alternative to the chunked default (see DESIGN.md 4.2a):
// the whole tracked tree is tarred and sealed into one opaque object stream rather
// than chunked per file. It leaks no structure (the server sees only fixed-size,
// per-sync-unique segments) at the cost of dedup — any change re-ships the whole
// folder. Selected per folder by .aqtconfig pack=true.

// PackRootVersion identifies the on-the-wire layout of a sealed pack-and-seal root.
const PackRootVersion = 1

// segTarget is the plaintext span sealed into one segment object. It is fixed-size,
// not content-defined: the only thing the object boundaries can leak is the tree's
// total byte count, never its internal file structure — the property that separates
// pack-and-seal from the chunked default. A handful of segments share one pack.
const segTarget = 4 << 20

// epoch zeroes the tar entries' modification time so the tarball does not carry
// per-file mtimes (and so two packs of the same bytes differ only by their nonces).
var epoch = time.Unix(0, 0)

// Segment names one sealed slice of the tarball stream by its content-address id
// and plaintext length. The slice is sealed under the folder content key with a
// fresh random nonce (stored as a prefix of the object bytes), so re-sealing the
// same plaintext yields a different id every sync: pack-and-seal keeps no
// chunk-level dedup, and each sync's segments supersede the last.
type Segment struct {
	ID  string `json:"id"`
	Len int    `json:"len"`
}

// PackRoot is the sealed resource blob of a pack-and-seal folder: it names the
// tarball's segment objects in order, the same way FileRoot names a streamed file's
// chunks. Reassembling the segments and decrypting yields the tar of the whole tree.
type PackRoot struct {
	Version  int       `json:"version"`
	Size     int64     `json:"size"` // tarball plaintext length
	Segments []Segment `json:"segments"`
}

// SegmentIDs returns the object ids the root references — its GC roots, sent as the
// resource's ChunkRefs. They are distinct by construction (each carries a unique
// nonce), so no dedup pass is needed.
func (r PackRoot) SegmentIDs() []string {
	ids := make([]string, len(r.Segments))
	for i, s := range r.Segments {
		ids[i] = s.ID
	}
	return ids
}

func SealPackRoot(r PackRoot, ck crypto.ContentKey) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.Seal(b, ck, crypto.AADBlob)
}

func OpenPackRoot(blob crypto.SealedBlob, ck crypto.ContentKey) (PackRoot, error) {
	var r PackRoot
	plain, err := crypto.Open(blob, ck, crypto.AADBlob)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(plain, &r)
}

// ObjectSink receives each sealed pack-and-seal segment so the caller can pack and
// upload it. It is distinct from ChunkSink: a segment carries no convergent key (it
// is sealed under the folder content key) and is identified only by its address.
type ObjectSink interface {
	Add(id string, object []byte) error
}

type nopObjectSink struct{}

func (nopObjectSink) Add(string, []byte) error { return nil }

// sealSegment seals one tarball slice under the content key and returns the object
// to store (its nonce prefixed to the ciphertext, content-addressed) plus the
// Segment record the root needs. The zero nonce trick used for convergent chunks is
// unavailable here — the key is the same for every segment — so a fresh random nonce
// per segment is what keeps (key, nonce) pairs unique.
func sealSegment(plain []byte, ck crypto.ContentKey) (object []byte, seg Segment, err error) {
	blob, err := crypto.Seal(plain, ck, crypto.AADPack)
	if err != nil {
		return nil, Segment{}, err
	}
	object = make([]byte, 0, len(blob.Nonce)+len(blob.Ciphertext))
	object = append(object, blob.Nonce...)
	object = append(object, blob.Ciphertext...)
	sum := sha256.Sum256(object)
	return object, Segment{ID: hex.EncodeToString(sum[:]), Len: len(plain)}, nil
}

// openSegment reverses sealSegment, verifying the object against its address and
// AEAD tag (and the plaintext length) before returning the slice.
func openSegment(object []byte, seg Segment, ck crypto.ContentKey) ([]byte, error) {
	sum := sha256.Sum256(object)
	if hex.EncodeToString(sum[:]) != seg.ID {
		return nil, errors.New("segment id mismatch: object does not match its address")
	}
	if len(object) < crypto.NonceSize {
		return nil, errors.New("segment shorter than a nonce")
	}
	plain, err := crypto.Open(crypto.SealedBlob{Nonce: object[:crypto.NonceSize], Ciphertext: object[crypto.NonceSize:]}, ck, crypto.AADPack)
	if err != nil {
		return nil, err
	}
	if len(plain) != seg.Len {
		return nil, errors.New("segment length mismatch")
	}
	return plain, nil
}

// TarAndSeal walks dir (honoring .aqtignore exactly as Scan/Take do), writes a tar
// of every tracked file and symlink, and seals the stream into fixed-size segments
// fed to sink as they fill — so the whole tree is never held in memory. It returns
// the root naming those segments in order. sink may be nil for a size-only pass.
func TarAndSeal(dir string, ck crypto.ContentKey, sink ObjectSink) (PackRoot, error) {
	if sink == nil {
		sink = nopObjectSink{}
	}
	ss := &segmentSink{ck: ck, sink: sink}
	tw := tar.NewWriter(ss)
	err := walkFiles(dir, func(n fileNode) error {
		return writeTarEntry(tw, n)
	})
	if err != nil {
		return PackRoot{}, err
	}
	if err := tw.Close(); err != nil { // flushes the archive trailer into ss
		return PackRoot{}, err
	}
	if err := ss.finish(); err != nil {
		return PackRoot{}, err
	}
	return PackRoot{Version: PackRootVersion, Size: ss.size, Segments: ss.segments}, nil
}

// writeTarEntry appends one node with a content-only header — permission bits, but a
// zeroed mtime and no owner identity, so the tarball carries the tree's bytes and
// modes and nothing about the host.
func writeTarEntry(tw *tar.Writer, n fileNode) error {
	if n.symlink {
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     n.rel,
			Linkname: n.target,
			Mode:     0o777,
			ModTime:  epoch,
		})
	}
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     n.rel,
		Mode:     int64(n.info.Mode().Perm()),
		Size:     n.info.Size(),
		ModTime:  epoch,
	}); err != nil {
		return err
	}
	f, err := os.Open(n.path)
	if err != nil {
		return err
	}
	defer f.Close()
	written, err := io.Copy(tw, f)
	if err != nil {
		return err
	}
	// tar headers commit to Size up front; a file that grew or shrank between the
	// stat and the read would desync the archive, so fail loudly rather than ship a
	// corrupt tarball.
	if written != n.info.Size() {
		return fmt.Errorf("file %s changed size during pack (%d != %d)", n.rel, written, n.info.Size())
	}
	return nil
}

// segmentSink is the io.Writer the tar stream is written into: it accumulates bytes
// and seals each segTarget-sized slice into sink as the buffer fills, so memory
// stays O(segTarget + one pack) regardless of tree size.
type segmentSink struct {
	ck       crypto.ContentKey
	sink     ObjectSink
	buf      []byte
	segments []Segment
	size     int64
}

func (s *segmentSink) Write(p []byte) (int, error) {
	s.size += int64(len(p))
	s.buf = append(s.buf, p...)
	for len(s.buf) >= segTarget {
		if err := s.emit(s.buf[:segTarget]); err != nil {
			return 0, err
		}
		s.buf = s.buf[:copy(s.buf, s.buf[segTarget:])]
	}
	return len(p), nil
}

func (s *segmentSink) emit(plain []byte) error {
	object, seg, err := sealSegment(plain, s.ck)
	if err != nil {
		return err
	}
	s.segments = append(s.segments, seg)
	return s.sink.Add(seg.ID, object)
}

// finish seals the trailing partial segment; the caller flushes the sink's last pack.
func (s *segmentSink) finish() error {
	if len(s.buf) == 0 {
		return nil
	}
	err := s.emit(s.buf)
	s.buf = s.buf[:0]
	return err
}

// ExtractToTree reassembles a pack-and-seal tarball from its segments (fetched by id
// via fetch) and unpacks it under dir, streaming each segment so neither the tarball
// nor any file is held whole in memory. It returns the manifest of what it wrote
// (path/mode/size/hash, link targets) so the caller can record the new base and
// prune local files the tarball no longer contains.
func ExtractToTree(dir string, root PackRoot, ck crypto.ContentKey, fetch func(id string) ([]byte, error)) (Manifest, error) {
	pr, pw := io.Pipe()
	go func() {
		for _, seg := range root.Segments {
			object, err := fetch(seg.ID)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			plain, err := openSegment(object, seg, ck)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := pw.Write(plain); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
		pw.Close()
	}()
	m, err := extractTar(dir, pr)
	if err != nil {
		pr.CloseWithError(err) // unblock the writer if extraction bailed early
		return Manifest{}, err
	}
	sortEntries(m.Entries)
	return m, nil
}

// extractTar writes every regular file and symlink in the tar under dir and returns
// their manifest. Each path is resolved through safeJoin (via writeAtomic /
// WriteSymlink), so a corrupt or hostile archive cannot escape the tracked root.
func extractTar(dir string, r io.Reader) (Manifest, error) {
	var m Manifest
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return m, nil
		}
		if err != nil {
			return Manifest{}, err
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			e := Entry{Path: hdr.Name, Size: int64(len(hdr.Linkname)), Link: hdr.Linkname, Hash: linkHash(hdr.Linkname)}
			if err := WriteSymlink(dir, e); err != nil {
				return Manifest{}, err
			}
			m.Entries = append(m.Entries, e)
		case tar.TypeReg, tar.TypeRegA:
			e := Entry{Path: hdr.Name, Mode: uint32(fs.FileMode(hdr.Mode).Perm()), Size: hdr.Size}
			h := sha256.New()
			if err := writeAtomic(dir, e, func(w io.Writer) error {
				_, err := io.Copy(w, io.TeeReader(tr, h))
				return err
			}); err != nil {
				return Manifest{}, err
			}
			e.Hash = hex.EncodeToString(h.Sum(nil))
			m.Entries = append(m.Entries, e)
		default:
			// Parent dirs are created by writeAtomic; we write no other type, so an
			// unexpected one is skipped rather than trusted.
		}
	}
}
