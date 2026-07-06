package syncengine

import (
	"fmt"
	"reflect"
	"testing"
)

// diffFetcher adapts a mapSink to the batch shape and records every id requested,
// so a test can prove an unchanged subtree was pruned rather than fetched.
type diffFetcher struct {
	cts       mapSink
	requested map[string]bool
}

func newDiffFetcher(sinks ...mapSink) *diffFetcher {
	f := &diffFetcher{cts: mapSink{}, requested: map[string]bool{}}
	for _, s := range sinks {
		for id, ct := range s {
			f.cts[id] = ct
		}
	}
	return f
}

func (f *diffFetcher) fetch(ids []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(ids))
	for _, id := range ids {
		f.requested[id] = true
		ct, ok := f.cts[id]
		if !ok {
			return nil, fmt.Errorf("missing node %s", id)
		}
		out[id] = ct
	}
	return out, nil
}

func file(path, content string) Entry {
	return Entry{Path: path, Mode: 0o644, Size: int64(len(content)), Hash: "h-" + content, Inline: []byte(content)}
}

func TestDiffTreeRootsReportsChanges(t *testing.T) {
	conv := testConv(t)
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("keep/same.txt", "same"),
		file("mod/changed.txt", "v1"),
		file("gone/only-left.txt", "l"),
		file("root-gone.txt", "rl"),
		{Path: "links/ln", Size: 1, Hash: linkHash("old-target"), Link: "old-target"},
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("keep/same.txt", "same"),
		file("mod/changed.txt", "v2"),
		file("fresh/only-right.txt", "r"),
		file("root-new.txt", "rn"),
		{Path: "links/ln", Size: 1, Hash: linkHash("new-target"), Link: "new-target"},
	}}

	leftSink, rightSink := mapSink{}, mapSink{}
	leftRoot, _, err := SealTree(left, conv, leftSink)
	if err != nil {
		t.Fatal(err)
	}
	rightRoot, _, err := SealTree(right, conv, rightSink)
	if err != nil {
		t.Fatal(err)
	}
	f := newDiffFetcher(leftSink, rightSink)

	added, removed, modified, err := DiffTreeRoots(leftRoot, rightRoot, f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"fresh/only-right.txt", "root-new.txt"}; !reflect.DeepEqual(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
	if want := []string{"gone/only-left.txt", "root-gone.txt"}; !reflect.DeepEqual(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}
	if want := []string{"mod/changed.txt"}; !reflect.DeepEqual(modified, want) {
		t.Errorf("modified = %v, want %v", modified, want)
	}

	// The unchanged "keep" subtree hashes equal on both sides, so its node must be
	// pruned by address, never fetched. Find its id via the left root's children.
	rootChildren, err := openNodeChildren(leftRoot.Root, leftSink[leftRoot.Root.ID])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rootChildren {
		if c.Name == "keep" {
			if f.requested[c.Node.ID] {
				t.Error("unchanged subtree node was fetched instead of pruned")
			}
		}
	}
	// The symlink target changed but symlinks are not reported (parity with the
	// on-disk diff) — the "links" dir differs by hash yet must yield no output.
	for _, p := range [][]string{added, removed, modified} {
		for _, path := range p {
			if path == "links/ln" {
				t.Error("symlink change was reported")
			}
		}
	}
}

func TestDiffTreeRootsIdenticalRootsFetchNothing(t *testing.T) {
	conv := testConv(t)
	m := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("a/b.txt", "x")}}
	sink := mapSink{}
	root, _, err := SealTree(m, conv, sink)
	if err != nil {
		t.Fatal(err)
	}
	f := newDiffFetcher(sink)
	added, removed, modified, err := DiffTreeRoots(root, root, f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if len(added)+len(removed)+len(modified) != 0 {
		t.Fatalf("identical roots diffed non-empty: +%v -%v ~%v", added, removed, modified)
	}
	if len(f.requested) != 0 {
		t.Fatalf("identical roots fetched %d nodes, want 0", len(f.requested))
	}
}

func TestDiffTreeRootsTypeChange(t *testing.T) {
	conv := testConv(t)
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("x", "was a file"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("x/inner.txt", "now a dir"),
		file("x/deep/nested.txt", "deeper"),
	}}
	leftSink, rightSink := mapSink{}, mapSink{}
	leftRoot, _, err := SealTree(left, conv, leftSink)
	if err != nil {
		t.Fatal(err)
	}
	rightRoot, _, err := SealTree(right, conv, rightSink)
	if err != nil {
		t.Fatal(err)
	}

	added, removed, modified, err := DiffTreeRoots(leftRoot, rightRoot, newDiffFetcher(leftSink, rightSink).fetch)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"x/deep/nested.txt", "x/inner.txt"}; !reflect.DeepEqual(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
	if want := []string{"x"}; !reflect.DeepEqual(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}
	if len(modified) != 0 {
		t.Errorf("modified = %v, want none", modified)
	}
}
