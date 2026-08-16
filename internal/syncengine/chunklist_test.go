// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// fakeChunks builds n distinct chunk records with arbitrary ids. The values are only
// serialized and address-counted here, never opened, so they need not be real chunks.
func fakeChunks(n int) []crypto.Chunk {
	cs := make([]crypto.Chunk, n)
	for i := range cs {
		cs[i] = crypto.Chunk{ID: fmt.Sprintf("chunk-%08d", i), Key: bytes.Repeat([]byte{7}, crypto.KeySize), Len: 100}
	}
	return cs
}

// A file whose chunk list crosses the indirection threshold seals its list to
// segments and reconstructs to the identical records, and its content still writes
// out byte-for-byte.
func TestFileRootIndirectRoundTrip(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 4<<20) // ~512 chunks at the 8K default, well past the threshold
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	sink := mapSink{}
	chunks, size, err := ChunkFile(bytes.NewReader(data), conv, testChunker(), sink)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(chunks) <= chunkListInlineMax {
		t.Fatalf("test needs a list past the threshold, got %d chunks", len(chunks))
	}

	root, refs, err := BuildFileRoot(chunks, size, conv, sink)
	if err != nil {
		t.Fatalf("BuildFileRoot: %v", err)
	}
	if !root.Indirect() {
		t.Fatal("a large chunk list must be stored indirectly")
	}
	if len(root.Chunks) != 0 {
		t.Fatal("indirect root must not also inline the chunk list")
	}
	if len(root.ChunkList) == 0 {
		t.Fatal("indirect root must name its list segments")
	}

	// refs are the resource GC roots: every content chunk plus every list segment.
	refSet := map[string]bool{}
	for _, id := range refs {
		refSet[id] = true
	}
	for _, ch := range chunks {
		if !refSet[ch.ID] {
			t.Fatalf("content chunk %s missing from GC roots", ch.ID)
		}
	}
	for _, seg := range root.ChunkList {
		if !refSet[seg.ID] {
			t.Fatalf("list segment %s missing from GC roots", seg.ID)
		}
	}

	// The root survives a seal/open cycle and resolves to the original records.
	blob, err := SealFileRoot(root, ck, "res1")
	if err != nil {
		t.Fatalf("SealFileRoot: %v", err)
	}
	got, err := OpenFileRoot(blob, ck, "res1")
	if err != nil {
		t.Fatalf("OpenFileRoot: %v", err)
	}
	resolved, err := got.Resolve(sink.get)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(resolved, chunks) {
		t.Fatal("resolved chunk list differs from the original")
	}

	var buf bytes.Buffer
	if err := WriteFileRoot(&buf, resolved, sink.get); err != nil {
		t.Fatalf("WriteFileRoot: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Fatal("content round-trip mismatch")
	}
}

// A version-1 root (list inline, no ChunkList marker) still opens and resolves
// without any fetch, and a root from a newer client is rejected with a clear error.
func TestFileRootLegacyInlineAndVersionGuard(t *testing.T) {
	t.Parallel()
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	legacy := FileRoot{Version: 1, Size: 300, Chunks: fakeChunks(3)}
	if legacy.Indirect() {
		t.Fatal("an inline root must not report indirect")
	}
	resolved, err := legacy.Resolve(func(string) ([]byte, error) {
		t.Fatal("inline root must resolve without fetching")
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(resolved, legacy.Chunks) {
		t.Fatal("inline resolve must return the inline chunks verbatim")
	}
	blob, err := SealFileRoot(legacy, ck, "res1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRoot(blob, ck, "res1"); err != nil {
		t.Fatalf("a legacy v1 root must still open: %v", err)
	}

	future := FileRoot{Version: FileRootVersion + 1, Size: 1, Chunks: fakeChunks(1)}
	fblob, err := SealFileRoot(future, ck, "res1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRoot(fblob, ck, "res1"); err == nil {
		t.Fatal("a root newer than this client must be rejected")
	}
}

// Indirection kicks in strictly above the threshold: a list of exactly the maximum
// stays inline, one record more moves to segments.
func TestFileRootThresholdBoundary(t *testing.T) {
	t.Parallel()
	conv := testConv(t)

	atMax, _, err := BuildFileRoot(fakeChunks(chunkListInlineMax), 1, conv, memSink{})
	if err != nil {
		t.Fatal(err)
	}
	if atMax.Indirect() {
		t.Fatalf("a list of exactly %d records must stay inline", chunkListInlineMax)
	}
	if len(atMax.Chunks) != chunkListInlineMax {
		t.Fatalf("inline root must carry all %d records", chunkListInlineMax)
	}

	sink := memSink{}
	overMax, _, err := BuildFileRoot(fakeChunks(chunkListInlineMax+1), 1, conv, sink)
	if err != nil {
		t.Fatal(err)
	}
	if !overMax.Indirect() {
		t.Fatalf("a list of %d records must indirect", chunkListInlineMax+1)
	}
	if len(sink) == 0 {
		t.Fatal("indirection must have sealed at least one list segment into the sink")
	}
}

// The tree path indirects a file's oversized chunk list into a directory node and
// reconstructs the identical manifest, keeping both content chunks and list segments
// as GC roots.
func TestTreeIndirectChunkListRoundTrip(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	sink := mapSink{}

	data := make([]byte, 3<<20) // past the threshold at the 8K default
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	fileChunks, size, err := ChunkFile(bytes.NewReader(data), conv, testChunker(), sink)
	if err != nil {
		t.Fatalf("ChunkFile: %v", err)
	}
	if len(fileChunks) <= chunkListInlineMax {
		t.Fatalf("test needs a list past the threshold, got %d chunks", len(fileChunks))
	}

	in := Manifest{
		Version: TreeManifestVersion,
		Entries: []Entry{
			{Path: "big.bin", Mode: 0o644, Size: size, Hash: "hbig", Chunks: fileChunks},
			{Path: "small.txt", Mode: 0o644, Size: 1, Hash: "hs", Inline: []byte("x")},
		},
	}
	root, refs, err := SealTree(in, conv, sink)
	if err != nil {
		t.Fatalf("SealTree: %v", err)
	}
	got, err := openTreeSingle(root, sink.get)
	if err != nil {
		t.Fatalf("open tree: %v", err)
	}
	want := normalize(in)
	got = normalize(got)
	if !reflect.DeepEqual(want.Entries, got.Entries) {
		t.Fatalf("entries round-trip mismatch:\n want %d entries\n got  %d entries", len(want.Entries), len(got.Entries))
	}

	// Every content chunk must remain a GC root even though it is now reached through
	// the sealed list segments rather than named directly in the node.
	refSet := map[string]bool{}
	for _, id := range refs {
		refSet[id] = true
	}
	for _, ch := range fileChunks {
		if !refSet[ch.ID] {
			t.Fatalf("content chunk %s missing from GC roots after indirection", ch.ID)
		}
	}
}

// A directory node with too many direct children to fit one pack fails with a clear,
// actionable client-side error rather than an opaque server rejection later.
func TestNodeSizeCeiling(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	var entries []Entry
	for i := 0; i < 25; i++ { // 25 x ~1 MiB inline overflows MaxNodeBytes (24 MiB)
		entries = append(entries, Entry{
			Path:   fmt.Sprintf("f%02d", i),
			Mode:   0o644,
			Size:   1 << 20,
			Hash:   fmt.Sprintf("h%02d", i),
			Inline: bytes.Repeat([]byte{byte(i)}, 1<<20),
		})
	}
	_, _, err := SealTree(Manifest{Version: TreeManifestVersion, Entries: entries}, conv, mapSink{})
	if err == nil {
		t.Fatal("a node past MaxNodeBytes must be rejected client-side")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("too much metadata")) {
		t.Fatalf("error should explain the node is too large, got: %v", err)
	}
}
