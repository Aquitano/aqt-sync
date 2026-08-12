package syncengine

import (
	"errors"
	"testing"
)

func TestResolveTreePathFetchesOnlyTheSpine(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	m := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("a/b/target.txt", "found"),
		file("a/sibling.txt", "s"),
		file("other/unrelated.txt", "u"),
	}}
	sink := mapSink{}
	root, _, err := SealTree(m, conv, sink)
	if err != nil {
		t.Fatal(err)
	}
	f := newDiffFetcher(sink)

	child, err := ResolveTreePath(root, "a/b/target.txt", f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if child.Type != ChildFile || child.Name != "target.txt" {
		t.Fatalf("resolved %+v, want file target.txt", child)
	}

	// Only the spine (root, a, a/b) may be fetched; the "other" subtree must not.
	rootChildren, err := openNodeChildren(root.Root, sink[root.Root.ID])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rootChildren {
		if c.Name == "other" && f.requested[c.Node.ID] {
			t.Error("resolving a path fetched an unrelated subtree node")
		}
	}
	if want := 3; len(f.requested) != want {
		t.Errorf("fetched %d nodes, want %d (the spine)", len(f.requested), want)
	}
}

func TestResolveTreePathRootAndMisses(t *testing.T) {
	t.Parallel()
	conv := testConv(t)
	m := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("dir/f.txt", "x")}}
	sink := mapSink{}
	root, _, err := SealTree(m, conv, sink)
	if err != nil {
		t.Fatal(err)
	}
	f := newDiffFetcher(sink)

	child, err := ResolveTreePath(root, "", f.fetch)
	if err != nil || child.Type != ChildDir || child.Node.ID != root.Root.ID {
		t.Fatalf("empty path = %+v, %v; want the root dir", child, err)
	}
	for _, p := range []string{"nope", "dir/nope", "dir/f.txt/deeper"} {
		if _, err := ResolveTreePath(root, p, f.fetch); !errors.Is(err, ErrPathNotFound) {
			t.Errorf("ResolveTreePath(%q) err = %v, want ErrPathNotFound", p, err)
		}
	}
}

func TestEntryFromChild(t *testing.T) {
	t.Parallel()
	link := TreeChild{Name: "ln", Type: ChildSymlink, Size: 3, Hash: linkHash("tgt"), Link: "tgt"}
	e, err := EntryFromChild("sub/ln", link, nil)
	if err != nil || e.Link != "tgt" || e.Path != "sub/ln" {
		t.Fatalf("symlink entry = %+v, %v", e, err)
	}
	dir := TreeChild{Name: "d", Type: ChildDir}
	if _, err := EntryFromChild("d", dir, nil); err == nil {
		t.Fatal("directory child converted to an entry without error")
	}
}
