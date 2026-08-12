package syncengine

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// recordingSink captures every Add in call order, verifying the ciphertext is an
// independent allocation by reopening it later.
type recordingSink struct {
	chunks []crypto.Chunk
	cts    [][]byte
}

func (s *recordingSink) Add(ch crypto.Chunk, ct []byte) error {
	s.chunks = append(s.chunks, ch)
	s.cts = append(s.cts, ct)
	return nil
}

// The parallel seal must be indistinguishable from the serial loop: same chunk
// records in the same order, and sink.Add called in that order with ciphertext
// that opens back to the original bytes.
func TestSealStreamMatchesSerial(t *testing.T) {
	t.Parallel()
	data := make([]byte, 1<<20)
	rand.New(rand.NewSource(42)).Read(data)
	var conv crypto.ConvergenceKey
	copy(conv[:], bytes.Repeat([]byte{7}, len(conv)))
	chunker := NewChunker(2<<10, 8<<10, 64<<10)

	serialSink := &recordingSink{}
	serialChunks, serialSize, err := sealSerial(bytes.NewReader(data), conv, chunker, serialSink)
	if err != nil {
		t.Fatal(err)
	}

	parSink := &recordingSink{}
	parChunks, parSize, err := sealStream(bytes.NewReader(data), conv, chunker, parSink)
	if err != nil {
		t.Fatal(err)
	}

	if parSize != serialSize || parSize != int64(len(data)) {
		t.Fatalf("size = %d (serial %d), want %d", parSize, serialSize, len(data))
	}
	if len(parChunks) != len(serialChunks) {
		t.Fatalf("chunk count = %d, want %d", len(parChunks), len(serialChunks))
	}
	for i := range parChunks {
		if parChunks[i].ID != serialChunks[i].ID {
			t.Fatalf("chunk %d id mismatch: parallel %s, serial %s", i, parChunks[i].ID, serialChunks[i].ID)
		}
		if parSink.chunks[i].ID != parChunks[i].ID {
			t.Fatalf("sink saw chunk %d out of order", i)
		}
	}

	// Reassemble from the sink's ciphertext: proves each ct is an owned allocation
	// (no buffer was recycled underneath it) and the stream order is the file order.
	var rebuilt bytes.Buffer
	for i, ct := range parSink.cts {
		plain, err := crypto.OpenChunk(ct, parSink.chunks[i])
		if err != nil {
			t.Fatalf("open chunk %d: %v", i, err)
		}
		rebuilt.Write(plain)
	}
	if !bytes.Equal(rebuilt.Bytes(), data) {
		t.Fatal("reassembled plaintext differs from input")
	}
}

type failingSink struct {
	after int
	calls int
}

var errSinkBoom = errors.New("sink boom")

func (s *failingSink) Add(crypto.Chunk, []byte) error {
	s.calls++
	if s.calls > s.after {
		return errSinkBoom
	}
	return nil
}

// A sink error must surface (not the internal abort sentinel), and sealStream must
// not deadlock or leak goroutines while draining in-flight work.
func TestSealStreamSinkError(t *testing.T) {
	t.Parallel()
	data := make([]byte, 1<<20)
	rand.New(rand.NewSource(1)).Read(data)
	var conv crypto.ConvergenceKey
	chunker := NewChunker(2<<10, 8<<10, 64<<10)

	_, _, err := sealStream(bytes.NewReader(data), conv, chunker, &failingSink{after: 2})
	if !errors.Is(err, errSinkBoom) {
		t.Fatalf("want errSinkBoom, got %v", err)
	}
}
