package syncengine

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

type memSink map[string][]byte

func (m memSink) Add(ch crypto.Chunk, ct []byte) error {
	m[ch.ID] = append([]byte(nil), ct...)
	return nil
}

func TestFileRootRoundTrip(t *testing.T) {
	var conv crypto.ConvergenceKey
	if _, err := rand.Read(conv[:]); err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 300*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	sink := memSink{}
	chunks, size, err := ChunkFile(bytes.NewReader(data), conv, DefaultChunker(), sink)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if size != int64(len(data)) {
		t.Fatalf("size = %d, want %d", size, len(data))
	}
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}

	root := FileRoot{Version: FileRootVersion, Size: size, Chunks: chunks}
	blob, err := SealFileRoot(root, ck)
	if err != nil {
		t.Fatalf("SealFileRoot: %v", err)
	}
	got, err := OpenFileRoot(blob, ck)
	if err != nil {
		t.Fatalf("OpenFileRoot: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteFileRoot(&buf, got.Chunks, func(id string) ([]byte, error) { return sink[id], nil }); err != nil {
		t.Fatalf("WriteFileRoot: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("round-trip mismatch")
	}

	other, _ := crypto.GenerateContentKey()
	if _, err := OpenFileRoot(blob, other); err == nil {
		t.Fatal("OpenFileRoot accepted a wrong key")
	}
}
