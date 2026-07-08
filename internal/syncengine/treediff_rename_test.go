package syncengine

import (
	"reflect"
	"testing"
)

func diffManifests(t *testing.T, left, right Manifest) (TreeDiff, *diffFetcher, TreeRoot, mapSink) {
	t.Helper()
	conv := testConv(t)
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
	d, err := DiffTreeRoots(leftRoot, rightRoot, f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	return d, f, leftRoot, leftSink
}

func TestDiffTreeRootsFileRename(t *testing.T) {
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("dir/old.txt", "same")}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("dir/new.txt", "same")}}

	d, _, _, _ := diffManifests(t, left, right)

	want := []Rename{{From: "dir/old.txt", To: "dir/new.txt"}}
	if !reflect.DeepEqual(d.Renamed, want) {
		t.Errorf("renamed = %v, want %v", d.Renamed, want)
	}
	if len(d.Added) != 0 {
		t.Errorf("added = %v, want empty", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %v, want empty", d.Removed)
	}
}

func TestDiffTreeRootsDirectoryRenameCoalesces(t *testing.T) {
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("olddir/a.txt", "a"),
		file("olddir/sub/b.txt", "b"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("newdir/a.txt", "a"),
		file("newdir/sub/b.txt", "b"),
	}}

	d, _, _, _ := diffManifests(t, left, right)

	want := []Rename{{From: "olddir", To: "newdir", Dir: true}}
	if !reflect.DeepEqual(d.Renamed, want) {
		t.Errorf("renamed = %v, want %v", d.Renamed, want)
	}
	if len(d.Added) != 0 {
		t.Errorf("added = %v, want empty", d.Added)
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %v, want empty", d.Removed)
	}
}

func TestDiffTreeRootsDuplicateContentStaysDeleteAdd(t *testing.T) {
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("one.txt", "dup"),
		file("two.txt", "dup"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("moved.txt", "dup")}}

	d, _, _, _ := diffManifests(t, left, right)

	if len(d.Renamed) != 0 {
		t.Errorf("renamed = %v, want none", d.Renamed)
	}
	if want := []string{"one.txt", "two.txt"}; !reflect.DeepEqual(d.Removed, want) {
		t.Errorf("removed = %v, want %v", d.Removed, want)
	}
	if want := []string{"moved.txt"}; !reflect.DeepEqual(d.Added, want) {
		t.Errorf("added = %v, want %v", d.Added, want)
	}
}

func TestDiffTreeRootsModifiedUntouchedByPairing(t *testing.T) {
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("dir/old.txt", "same"),
		file("mod.txt", "v1"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("dir/new.txt", "same"),
		file("mod.txt", "v2"),
	}}

	d, _, _, _ := diffManifests(t, left, right)

	if want := []Rename{{From: "dir/old.txt", To: "dir/new.txt"}}; !reflect.DeepEqual(d.Renamed, want) {
		t.Errorf("renamed = %v, want %v", d.Renamed, want)
	}
	if want := []string{"mod.txt"}; !reflect.DeepEqual(d.Modified, want) {
		t.Errorf("modified = %v, want %v", d.Modified, want)
	}
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Errorf("added/removed = %v/%v, want empty", d.Added, d.Removed)
	}
}

func TestDiffTreeRootsRenameDoesNotFetchUnchangedSubtree(t *testing.T) {
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("keep/same.txt", "same"),
		file("dir/old.txt", "renamed"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("keep/same.txt", "same"),
		file("dir/new.txt", "renamed"),
	}}

	d, f, leftRoot, leftSink := diffManifests(t, left, right)

	if want := []Rename{{From: "dir/old.txt", To: "dir/new.txt"}}; !reflect.DeepEqual(d.Renamed, want) {
		t.Errorf("renamed = %v, want %v", d.Renamed, want)
	}

	rootChildren, err := openNodeChildren(leftRoot.Root, leftSink[leftRoot.Root.ID])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rootChildren {
		if c.Name == "keep" && f.requested[c.Node.ID] {
			t.Error("unchanged subtree node was fetched instead of pruned")
		}
	}
}
