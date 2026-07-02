package syncengine

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

type mapSink map[string][]byte

func (s mapSink) Add(ch crypto.Chunk, ct []byte) error {
	s[ch.ID] = append([]byte(nil), ct...)
	return nil
}

func (s mapSink) get(id string) ([]byte, error) {
	ct, ok := s[id]
	if !ok {
		return nil, fmt.Errorf("missing node %s", id)
	}
	return ct, nil
}

func normalize(m Manifest) Manifest {
	sortEntries(m.Entries)
	sortDirs(m.Dirs)
	return m
}

func TestSealOpenTreeRoundTrip(t *testing.T) {
	conv := testConv(t)
	key := make([]byte, crypto.KeySize)
	in := Manifest{
		Version: TreeManifestVersion,
		Entries: []Entry{
			{Path: "a.txt", Mode: 0o644, Size: 3, Hash: "ha", Inline: []byte("abc")},
			{Path: "dir/b.bin", Mode: 0o600, Size: 5, Hash: "hb", Chunks: []crypto.Chunk{{ID: "c1", Key: key, Len: 5}}},
			{Path: "dir/link", Size: 6, Hash: linkHash("target"), Link: "target"},
			{Path: "dir/sub/c.txt", Mode: 0o644, Size: 1, Hash: "hc", Inline: []byte("x")},
		},
		Dirs: []DirEntry{
			{Path: "dir", Mode: 0o700},
			{Path: "dir/sub", Mode: 0o755},
			{Path: "empty", Mode: 0o750},
		},
	}

	sink := mapSink{}
	root, refs, err := SealTree(in, conv, sink)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenTree(root, sink.get)
	if err != nil {
		t.Fatal(err)
	}
	want := normalize(in)
	got = normalize(got)
	if !reflect.DeepEqual(want.Entries, got.Entries) {
		t.Fatalf("entries round-trip mismatch:\n want %+v\n got  %+v", want.Entries, got.Entries)
	}
	if !reflect.DeepEqual(want.Dirs, got.Dirs) {
		t.Fatalf("dirs round-trip mismatch:\n want %+v\n got  %+v", want.Dirs, got.Dirs)
	}

	// refs must root every node object (in the sink) and every file chunk id.
	refSet := map[string]bool{}
	for _, id := range refs {
		refSet[id] = true
	}
	for id := range sink {
		if !refSet[id] {
			t.Errorf("node object %s missing from refs", id)
		}
	}
	if !refSet["c1"] {
		t.Error("file chunk id c1 missing from refs")
	}
}

func TestSubtreeDedup(t *testing.T) {
	conv := testConv(t)
	// The same two files under lib/ vs vendor/lib/. Their containing directory node
	// must seal to the same object id, so a move re-uploads zero objects.
	libID := subtreeRootID(t, conv, []Entry{
		{Path: "util.go", Mode: 0o644, Hash: "u", Inline: []byte("util")},
		{Path: "math.go", Mode: 0o644, Hash: "m", Inline: []byte("math")},
	})
	vendorLibID := subtreeRootID(t, conv, []Entry{
		{Path: "util.go", Mode: 0o644, Hash: "u", Inline: []byte("util")},
		{Path: "math.go", Mode: 0o644, Hash: "m", Inline: []byte("math")},
	})
	if libID != vendorLibID {
		t.Fatalf("identical subtree contents must share a node id: %s != %s", libID, vendorLibID)
	}

	// A different mode on one file must change the node id (mode is content here).
	other := subtreeRootID(t, conv, []Entry{
		{Path: "util.go", Mode: 0o755, Hash: "u", Inline: []byte("util")},
		{Path: "math.go", Mode: 0o644, Hash: "m", Inline: []byte("math")},
	})
	if other == libID {
		t.Fatal("a mode change must change the subtree node id")
	}
}

// subtreeRootID seals a standalone manifest and returns its root node id, which (by
// content addressing) equals the id any directory with these exact contents seals to.
func subtreeRootID(t *testing.T, conv crypto.ConvergenceKey, entries []Entry) string {
	t.Helper()
	root, _, err := SealTree(Manifest{Version: TreeManifestVersion, Entries: entries}, conv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return root.Root.ID
}

func TestEditLocality(t *testing.T) {
	conv := testConv(t)
	base := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		{Path: "main.go", Hash: "main", Inline: []byte("m")},
		{Path: "lib/util.go", Hash: "u", Inline: []byte("u")},
		{Path: "docs/readme.md", Hash: "r", Inline: []byte("r")},
	}}
	edited := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		{Path: "main.go", Hash: "main", Inline: []byte("m")},
		{Path: "lib/util.go", Hash: "u2", Inline: []byte("u2")}, // only this changed
		{Path: "docs/readme.md", Hash: "r", Inline: []byte("r")},
	}}

	baseCT, err := SealTreeCiphertexts(base, conv)
	if err != nil {
		t.Fatal(err)
	}
	editCT, err := SealTreeCiphertexts(edited, conv)
	if err != nil {
		t.Fatal(err)
	}
	docsBefore := dirNodeID(t, base, conv, "docs")
	docsAfter := dirNodeID(t, edited, conv, "docs")
	if docsBefore != docsAfter {
		t.Fatal("docs/ subtree must be untouched by a lib/ edit")
	}
	if dirNodeID(t, base, conv, "lib") == dirNodeID(t, edited, conv, "lib") {
		t.Fatal("lib/ subtree must change when its file changes")
	}
	// The docs node object is byte-identical across both trees (same id present in both).
	if _, ok := baseCT[docsBefore]; !ok {
		t.Fatal("docs node missing from base ciphertexts")
	}
	if _, ok := editCT[docsAfter]; !ok {
		t.Fatal("docs node missing from edited ciphertexts")
	}
}

func dirNodeID(t *testing.T, m Manifest, conv crypto.ConvergenceKey, dir string) string {
	t.Helper()
	var sub []Entry
	prefix := dir + "/"
	for _, e := range m.Entries {
		if len(e.Path) > len(prefix) && e.Path[:len(prefix)] == prefix {
			sub = append(sub, Entry{Path: e.Path[len(prefix):], Mode: e.Mode, Hash: e.Hash, Inline: e.Inline, Chunks: e.Chunks, Link: e.Link, Size: e.Size})
		}
	}
	return subtreeRootID(t, conv, sub)
}

// TestOpenTreeReusingBaseNodes proves the reconcile's lazy remote read: because directory
// nodes are content-addressed, serving any node id the base tree already holds from memory
// yields exactly the manifest a full server walk would, while fetching only the nodes on a
// changed spine. A remote identical to base fetches nothing.
func TestOpenTreeReusingBaseNodes(t *testing.T) {
	conv := testConv(t)
	base := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		{Path: "keep/a.txt", Hash: "a", Inline: []byte("a")},
		{Path: "keep/deep/b.txt", Hash: "b", Inline: []byte("b")},
		{Path: "change/c.txt", Hash: "c", Inline: []byte("c")},
	}}
	remote := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		{Path: "keep/a.txt", Hash: "a", Inline: []byte("a")},      // unchanged subtree
		{Path: "keep/deep/b.txt", Hash: "b", Inline: []byte("b")}, // unchanged subtree
		{Path: "change/c.txt", Hash: "c2", Inline: []byte("c2")},  // changed
	}}

	server := mapSink{}
	root, _, err := SealTree(remote, conv, server)
	if err != nil {
		t.Fatal(err)
	}
	full, err := OpenTree(root, server.get)
	if err != nil {
		t.Fatal(err)
	}

	baseCT, err := SealTreeCiphertexts(base, conv)
	if err != nil {
		t.Fatal(err)
	}
	fetched := 0
	hybrid := func(id string) ([]byte, error) {
		if ct, ok := baseCT[id]; ok {
			return ct, nil
		}
		fetched++
		return server.get(id)
	}
	got, err := OpenTree(root, hybrid)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(full), normalize(got)) {
		t.Fatalf("base-reuse read != full read:\n full %+v\n got  %+v", full, got)
	}
	// The "keep" subtree is identical in base and remote, so its nodes are served from
	// memory; only the root and the changed "change" node are fetched.
	if fetched != 2 {
		t.Fatalf("expected 2 server fetches (root + changed node), got %d", fetched)
	}

	// A remote identical to base fetches nothing at all: every node id is already in memory.
	sameRoot, _, err := SealTree(base, conv, mapSink{})
	if err != nil {
		t.Fatal(err)
	}
	fetched = 0
	if _, err := OpenTree(sameRoot, hybrid); err != nil {
		t.Fatal(err)
	}
	if fetched != 0 {
		t.Fatalf("an unchanged remote must fetch no nodes, got %d", fetched)
	}
}

// TestOpenTreeBatchedOneFetchPerLevel proves the level-batched walk collapses a
// tree's node fetches to one batch per depth level (the fix for 2.4's 2-RTT-per-node
// cost), and reconstructs exactly the manifest the depth-first OpenTree does.
func TestOpenTreeBatchedOneFetchPerLevel(t *testing.T) {
	conv := testConv(t)
	in := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		{Path: "a/sub/f1.txt", Hash: "h1", Inline: []byte("1")},
		{Path: "b/sub/f2.txt", Hash: "h2", Inline: []byte("2")},
	}, Dirs: []DirEntry{
		{Path: "a", Mode: 0o700}, {Path: "a/sub", Mode: 0o700},
		{Path: "b", Mode: 0o700}, {Path: "b/sub", Mode: 0o700},
	}}

	sink := mapSink{}
	root, _, err := SealTree(in, conv, sink)
	if err != nil {
		t.Fatal(err)
	}

	var batchSizes []int
	fetchBatch := func(ids []string) (map[string][]byte, error) {
		batchSizes = append(batchSizes, len(ids))
		out := make(map[string][]byte, len(ids))
		for _, id := range ids {
			ct, err := sink.get(id)
			if err != nil {
				return nil, err
			}
			out[id] = ct
		}
		return out, nil
	}
	got, err := OpenTreeBatched(root, fetchBatch)
	if err != nil {
		t.Fatal(err)
	}
	full, err := OpenTree(root, sink.get)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(full), normalize(got)) {
		t.Fatalf("batched read != depth-first read:\n full %+v\n got  %+v", full, got)
	}
	// root level (1 node), then {a,b} (2), then {a/sub,b/sub} (2): three batches,
	// each one locate round-trip, instead of five separate 2-RTT node fetches.
	wantSizes := []int{1, 2, 2}
	if !reflect.DeepEqual(batchSizes, wantSizes) {
		t.Fatalf("batch sizes = %v, want %v (one batch per level)", batchSizes, wantSizes)
	}
}

func TestTreeRootAADSeparation(t *testing.T) {
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	root := TreeRoot{Version: TreeManifestVersion, Root: crypto.Chunk{ID: "abc", Key: make([]byte, crypto.KeySize), Len: 4}}
	blob, err := SealTreeRoot(root, ck)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenTreeRoot(blob, ck)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root, got) {
		t.Fatalf("tree root round-trip mismatch: %+v vs %+v", root, got)
	}
	// A reader using a different AAD (e.g. the generic resource-blob tag) must not open
	// a TreeRoot blob, so a mis-routed folder fails the AEAD check loudly instead of
	// reading an empty tree and deleting everything.
	if _, err := crypto.Open(blob, ck, crypto.AADBlob); err == nil {
		t.Fatal("opening a TreeRoot blob under AADBlob must fail the AEAD check")
	}
}
