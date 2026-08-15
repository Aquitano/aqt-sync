// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"reflect"
	"testing"
)

func ent(path string, mode uint32, hash string) Entry {
	return Entry{Path: path, Mode: mode, Hash: hash}
}

func TestDetectRenamesSimpleFileRename(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("a.txt", 0o644, "H")}}
	cur := Manifest{Entries: []Entry{ent("b.txt", 0o644, "H")}}

	renames, added, deleted := DetectRenames([]string{"b.txt"}, []string{"a.txt"}, cur, old)

	want := []Rename{{From: "a.txt", To: "b.txt"}}
	if !reflect.DeepEqual(renames, want) {
		t.Errorf("renames = %v, want %v", renames, want)
	}
	if len(added) != 0 {
		t.Errorf("added = %v, want empty", added)
	}
	if len(deleted) != 0 {
		t.Errorf("deleted = %v, want empty", deleted)
	}
}

func TestDetectRenamesDuplicateContentNotPaired(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("d1.txt", 0o644, "H"), ent("d2.txt", 0o644, "H")}}
	cur := Manifest{Entries: []Entry{ent("a1.txt", 0o644, "H")}}

	added, deleted := []string{"a1.txt"}, []string{"d1.txt", "d2.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(added, deleted, cur, old)

	if renames != nil {
		t.Errorf("renames = %v, want nil", renames)
	}
	if !reflect.DeepEqual(gotAdded, added) {
		t.Errorf("added = %v, want %v", gotAdded, added)
	}
	if !reflect.DeepEqual(gotDeleted, deleted) {
		t.Errorf("deleted = %v, want %v", gotDeleted, deleted)
	}
}

func TestDetectRenamesContentReferencedElsewhereBlocksPairing(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("a.txt", 0o644, "H"), ent("keep.txt", 0o644, "H")}}
	cur := Manifest{Entries: []Entry{ent("b.txt", 0o644, "H"), ent("keep.txt", 0o644, "H")}}

	added, deleted := []string{"b.txt"}, []string{"a.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(added, deleted, cur, old)

	if renames != nil {
		t.Errorf("renames = %v, want nil", renames)
	}
	if !reflect.DeepEqual(gotAdded, added) {
		t.Errorf("added = %v, want %v", gotAdded, added)
	}
	if !reflect.DeepEqual(gotDeleted, deleted) {
		t.Errorf("deleted = %v, want %v", gotDeleted, deleted)
	}
}

func TestDetectRenamesModeMismatchBlocksPairing(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("a.txt", 0o644, "H")}}
	cur := Manifest{Entries: []Entry{ent("b.txt", 0o755, "H")}}

	added, deleted := []string{"b.txt"}, []string{"a.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(added, deleted, cur, old)

	if renames != nil {
		t.Errorf("renames = %v, want nil", renames)
	}
	if !reflect.DeepEqual(gotAdded, added) {
		t.Errorf("added = %v, want %v", gotAdded, added)
	}
	if !reflect.DeepEqual(gotDeleted, deleted) {
		t.Errorf("deleted = %v, want %v", gotDeleted, deleted)
	}
}

func TestDetectRenamesWholeDirectoryMoveCoalesces(t *testing.T) {
	t.Parallel()
	old := Manifest{
		Entries: []Entry{ent("dir/x.txt", 0o644, "Hx"), ent("dir/sub/y.txt", 0o644, "Hy")},
		Dirs:    []DirEntry{{Path: "dir", Mode: 0o755}, {Path: "dir/sub", Mode: 0o755}},
	}
	cur := Manifest{
		Entries: []Entry{ent("moved/x.txt", 0o644, "Hx"), ent("moved/sub/y.txt", 0o644, "Hy")},
		Dirs:    []DirEntry{{Path: "moved", Mode: 0o755}, {Path: "moved/sub", Mode: 0o755}},
	}

	added := []string{"moved/x.txt", "moved/sub/y.txt"}
	deleted := []string{"dir/x.txt", "dir/sub/y.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(added, deleted, cur, old)

	want := []Rename{{From: "dir", To: "moved", Dir: true}}
	if !reflect.DeepEqual(renames, want) {
		t.Errorf("renames = %v, want %v", renames, want)
	}
	if len(gotAdded) != 0 {
		t.Errorf("added = %v, want empty", gotAdded)
	}
	if len(gotDeleted) != 0 {
		t.Errorf("deleted = %v, want empty", gotDeleted)
	}
}

func TestDetectRenamesPartialMoveStaysPerFile(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("dir/a.txt", 0o644, "Ha"), ent("dir/b.txt", 0o644, "Hb")}}
	cur := Manifest{Entries: []Entry{ent("dir/a.txt", 0o644, "Ha"), ent("moved/b.txt", 0o644, "Hb")}}

	renames, gotAdded, gotDeleted := DetectRenames([]string{"moved/b.txt"}, []string{"dir/b.txt"}, cur, old)

	want := []Rename{{From: "dir/b.txt", To: "moved/b.txt"}}
	if !reflect.DeepEqual(renames, want) {
		t.Errorf("renames = %v, want %v", renames, want)
	}
	if len(gotAdded) != 0 {
		t.Errorf("added = %v, want empty", gotAdded)
	}
	if len(gotDeleted) != 0 {
		t.Errorf("deleted = %v, want empty", gotDeleted)
	}
}

func TestDetectRenamesDirModeChangeBlocksCoalescing(t *testing.T) {
	t.Parallel()
	old := Manifest{
		Entries: []Entry{ent("dir/x.txt", 0o644, "Hx"), ent("dir/y.txt", 0o644, "Hy")},
		Dirs:    []DirEntry{{Path: "dir", Mode: 0o755}},
	}
	cur := Manifest{
		Entries: []Entry{ent("moved/x.txt", 0o644, "Hx"), ent("moved/y.txt", 0o644, "Hy")},
		Dirs:    []DirEntry{{Path: "moved", Mode: 0o700}},
	}

	added := []string{"moved/x.txt", "moved/y.txt"}
	deleted := []string{"dir/x.txt", "dir/y.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(added, deleted, cur, old)

	want := []Rename{
		{From: "dir/x.txt", To: "moved/x.txt"},
		{From: "dir/y.txt", To: "moved/y.txt"},
	}
	if !reflect.DeepEqual(renames, want) {
		t.Errorf("renames = %v, want %v", renames, want)
	}
	if len(gotAdded) != 0 {
		t.Errorf("added = %v, want empty", gotAdded)
	}
	if len(gotDeleted) != 0 {
		t.Errorf("deleted = %v, want empty", gotDeleted)
	}
}

func TestDetectRenamesEmptyInputReturnsUnchanged(t *testing.T) {
	t.Parallel()
	old := Manifest{Entries: []Entry{ent("a.txt", 0o644, "H")}}
	cur := Manifest{Entries: []Entry{ent("a.txt", 0o644, "H")}}

	deleted := []string{"a.txt"}
	renames, gotAdded, gotDeleted := DetectRenames(nil, deleted, cur, old)
	if renames != nil {
		t.Errorf("renames = %v, want nil", renames)
	}
	if len(gotAdded) != 0 {
		t.Errorf("added = %v, want empty", gotAdded)
	}
	if !reflect.DeepEqual(gotDeleted, deleted) {
		t.Errorf("deleted = %v, want %v", gotDeleted, deleted)
	}

	added := []string{"a.txt"}
	renames, gotAdded, gotDeleted = DetectRenames(added, nil, cur, old)
	if renames != nil {
		t.Errorf("renames = %v, want nil", renames)
	}
	if !reflect.DeepEqual(gotAdded, added) {
		t.Errorf("added = %v, want %v", gotAdded, added)
	}
	if len(gotDeleted) != 0 {
		t.Errorf("deleted = %v, want empty", gotDeleted)
	}
}
