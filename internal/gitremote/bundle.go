package gitremote

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// BundleSegmentSize bounds memory during a push/fetch while keeping segment
// counts modest. Git bundle payloads are already pack-compressed.
const BundleSegmentSize = 4 << 20

// ObjectSink receives one sealed bundle segment for packing and upload.
type ObjectSink interface {
	Add(id string, object []byte) error
}

// SealBundle reads a Git bundle, seals it in fixed-size independently nonced
// segments, and returns the group descriptor stored in RefsRoot.
func SealBundle(r io.Reader, key crypto.ContentKey, sink ObjectSink) (BundleRef, error) {
	if sink == nil {
		return BundleRef{}, errors.New("git bundle sink is required")
	}
	h := sha256.New()
	var segments []Segment
	buf := make([]byte, BundleSegmentSize)
	for {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return BundleRef{}, err
		}
		if n > 0 {
			blob, sealErr := crypto.Seal(buf[:n], key, crypto.AADGitBundle)
			if sealErr != nil {
				return BundleRef{}, sealErr
			}
			object := make([]byte, 0, len(blob.Nonce)+len(blob.Ciphertext))
			object = append(object, blob.Nonce...)
			object = append(object, blob.Ciphertext...)
			sum := sha256.Sum256(object)
			id := hex.EncodeToString(sum[:])
			if err := sink.Add(id, object); err != nil {
				return BundleRef{}, err
			}
			segments = append(segments, Segment{ID: id, Len: n, Size: len(object)})
			_, _ = io.WriteString(h, id)
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			break
		}
	}
	if len(segments) == 0 {
		return BundleRef{}, errors.New("git bundle is empty")
	}
	return BundleRef{ID: hex.EncodeToString(h.Sum(nil)), Segments: segments}, nil
}

// OpenBundle fetches, verifies, decrypts, and writes one bundle in segment order.
func OpenBundle(bundle BundleRef, key crypto.ContentKey, get func(string) ([]byte, error), w io.Writer) error {
	if bundle.ID == "" || len(bundle.Segments) == 0 {
		return errors.New("git bundle entry is missing its id or segments")
	}
	h := sha256.New()
	for _, segment := range bundle.Segments {
		object, err := get(segment.ID)
		if err != nil {
			return err
		}
		if len(object) != segment.Size {
			return fmt.Errorf("git bundle segment %s has size %d, want %d", segment.ID, len(object), segment.Size)
		}
		sum := sha256.Sum256(object)
		if hex.EncodeToString(sum[:]) != segment.ID {
			return fmt.Errorf("git bundle segment %s does not match its address", segment.ID)
		}
		if len(object) < crypto.NonceSize {
			return fmt.Errorf("git bundle segment %s is shorter than a nonce", segment.ID)
		}
		plain, err := crypto.Open(crypto.SealedBlob{
			Nonce: object[:crypto.NonceSize], Ciphertext: object[crypto.NonceSize:],
		}, key, crypto.AADGitBundle)
		if err != nil {
			return fmt.Errorf("open git bundle segment %s: %w", segment.ID, err)
		}
		if len(plain) != segment.Len {
			return fmt.Errorf("git bundle segment %s has plaintext length %d, want %d", segment.ID, len(plain), segment.Len)
		}
		n, err := w.Write(plain)
		if err != nil {
			return err
		}
		if n != len(plain) {
			return io.ErrShortWrite
		}
		_, _ = io.WriteString(h, segment.ID)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != bundle.ID {
		return fmt.Errorf("git bundle group id mismatch: got %s, want %s", got, bundle.ID)
	}
	return nil
}
