package syncengine

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
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

	_, baseReg, err := buildTreeRegistry(base, conv)
	if err != nil {
		t.Fatal(err)
	}
	_, editReg, err := buildTreeRegistry(edited, conv)
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
	// The docs node object is shared across both registries (same id present in both).
	if _, ok := baseReg[docsBefore]; !ok {
		t.Fatal("docs node missing from base registry")
	}
	if _, ok := editReg[docsAfter]; !ok {
		t.Fatal("docs node missing from edited registry")
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

func TestDiffTreeMatchesPlan(t *testing.T) {
	conv := testConv(t)
	// Leaf paths chosen so no path is a prefix of another (no file/dir name clash).
	pool := []string{"a", "b", "c/d", "c/e", "f/g/h", "f/g/i", "j/k", "j/l", "m"}
	rng := rand.New(rand.NewSource(1))

	for iter := 0; iter < 300; iter++ {
		base := randManifest(rng, pool)
		local := mutate(rng, base, pool)
		remote := mutate(rng, base, pool)

		want := Plan(local, base, remote)

		remoteRoot, remoteReg, err := buildTreeRegistry(remote, conv)
		if err != nil {
			t.Fatal(err)
		}
		diff, err := DiffManifests(local, base, conv, remoteRoot, registryFetch(remoteReg))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, normActions(diff.Actions)) {
			t.Fatalf("iter %d: DiffTree actions != Plan\n local=%v\n base=%v\n remote=%v\n want=%v\n got =%v",
				iter, local.Entries, base.Entries, remote.Entries, want, diff.Actions)
		}
	}
}

func normActions(as []Action) []Action {
	if as == nil {
		return nil
	}
	sort.Slice(as, func(i, j int) bool { return as[i].Path < as[j].Path })
	return as
}

func randManifest(rng *rand.Rand, pool []string) Manifest {
	var m Manifest
	m.Version = TreeManifestVersion
	for _, p := range pool {
		if rng.Intn(2) == 0 {
			continue
		}
		m.Entries = append(m.Entries, Entry{Path: p, Mode: 0o600 + uint32(rng.Intn(2)*0o111), Hash: fmt.Sprintf("h%d", rng.Intn(3)), Inline: []byte("x")})
	}
	sortEntries(m.Entries)
	return m
}

func mutate(rng *rand.Rand, base Manifest, pool []string) Manifest {
	idx := base.ByPath()
	out := Manifest{Version: TreeManifestVersion}
	for _, p := range pool {
		e, present := idx[p]
		switch rng.Intn(4) {
		case 0: // drop
			continue
		case 1: // add/keep with a fresh hash
			out.Entries = append(out.Entries, Entry{Path: p, Mode: 0o600 + uint32(rng.Intn(2)*0o111), Hash: fmt.Sprintf("h%d", rng.Intn(4)), Inline: []byte("y")})
		default:
			if present {
				out.Entries = append(out.Entries, e)
			}
		}
	}
	sortEntries(out.Entries)
	return out
}

func TestDiffTreeDirActions(t *testing.T) {
	conv := testConv(t)
	base := Manifest{Version: TreeManifestVersion,
		Entries: []Entry{{Path: "keep/f.txt", Hash: "f", Inline: []byte("f")}},
		Dirs:    []DirEntry{{Path: "keep", Mode: 0o755}, {Path: "gone", Mode: 0o700}},
	}
	local := Manifest{Version: TreeManifestVersion,
		Entries: []Entry{{Path: "keep/f.txt", Hash: "f", Inline: []byte("f")}},
		Dirs:    []DirEntry{{Path: "keep", Mode: 0o700}, {Path: "fresh", Mode: 0o750}}, // keep chmod, gone removed, fresh added
	}

	remoteRoot, remoteReg, err := buildTreeRegistry(base, conv)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := DiffManifests(local, base, conv, remoteRoot, registryFetch(remoteReg))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ActionKind{}
	for _, d := range diff.DirActions {
		got[d.Path] = d.Kind
	}
	want := map[string]ActionKind{"keep": Upload, "gone": DeleteRemote, "fresh": Upload}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("dir actions mismatch:\n want %v\n got  %v", want, got)
	}
	// No file actions: the only file is unchanged.
	if len(diff.Actions) != 0 {
		t.Fatalf("expected no file actions, got %v", diff.Actions)
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
	// A v1 ManifestRoot reader must not open a v2 TreeRoot (distinct AAD), or it would
	// read an empty manifest and delete the tree.
	if _, err := OpenManifestRoot(blob, ck); err == nil {
		t.Fatal("a ManifestRoot open of a TreeRoot blob must fail the AEAD check")
	}
}
