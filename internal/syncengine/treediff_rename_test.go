// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"reflect"
	"testing"
)

func diffManifests(t *testing.T, left, right Manifest) (Delta, *diffFetcher, TreeRoot, mapSink) {
	t.Helper()
	conv := testConv(t)
	leftSink, rightSink := mapSink{}, mapSink{}
	leftRoot, _, err := SealTree(left, conv, leftSink, nil)
	if err != nil {
		t.Fatal(err)
	}
	rightRoot, _, err := SealTree(right, conv, rightSink, nil)
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
	t.Parallel()
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("dir/old.txt", "same")}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("dir/new.txt", "same")}}

	d, _, _, _ := diffManifests(t, left, right)

	want := []Rename{{From: "dir/old.txt", To: "dir/new.txt"}}
	if !reflect.DeepEqual(d.Renamed, want) {
		t.Errorf("renamed = %v, want %v", d.Renamed, want)
	}
	if len(d.Paths(ChangeAdded)) != 0 {
		t.Errorf("added = %v, want empty", d.Paths(ChangeAdded))
	}
	if len(d.Paths(ChangeRemoved)) != 0 {
		t.Errorf("removed = %v, want empty", d.Paths(ChangeRemoved))
	}
}

func TestDiffTreeRootsDirectoryRenameCoalesces(t *testing.T) {
	t.Parallel()
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
	if len(d.Paths(ChangeAdded)) != 0 {
		t.Errorf("added = %v, want empty", d.Paths(ChangeAdded))
	}
	if len(d.Paths(ChangeRemoved)) != 0 {
		t.Errorf("removed = %v, want empty", d.Paths(ChangeRemoved))
	}
}

func TestDiffTreeRootsDuplicateContentStaysDeleteAdd(t *testing.T) {
	t.Parallel()
	left := Manifest{Version: TreeManifestVersion, Entries: []Entry{
		file("one.txt", "dup"),
		file("two.txt", "dup"),
	}}
	right := Manifest{Version: TreeManifestVersion, Entries: []Entry{file("moved.txt", "dup")}}

	d, _, _, _ := diffManifests(t, left, right)

	if len(d.Renamed) != 0 {
		t.Errorf("renamed = %v, want none", d.Renamed)
	}
	if want := []string{"one.txt", "two.txt"}; !reflect.DeepEqual(d.Paths(ChangeRemoved), want) {
		t.Errorf("removed = %v, want %v", d.Paths(ChangeRemoved), want)
	}
	if want := []string{"moved.txt"}; !reflect.DeepEqual(d.Paths(ChangeAdded), want) {
		t.Errorf("added = %v, want %v", d.Paths(ChangeAdded), want)
	}
}

func TestDiffTreeRootsModifiedUntouchedByPairing(t *testing.T) {
	t.Parallel()
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
	if want := []string{"mod.txt"}; !reflect.DeepEqual(d.Paths(ChangeContent), want) {
		t.Errorf("modified = %v, want %v", d.Paths(ChangeContent), want)
	}
	if len(d.Paths(ChangeAdded)) != 0 || len(d.Paths(ChangeRemoved)) != 0 {
		t.Errorf("added/removed = %v/%v, want empty", d.Paths(ChangeAdded), d.Paths(ChangeRemoved))
	}
}

func TestDiffTreeRootsRenameDoesNotFetchUnchangedSubtree(t *testing.T) {
	t.Parallel()
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
