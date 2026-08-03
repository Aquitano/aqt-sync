package syncengine

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"pgregory.net/rapid"
)

func dir(path string, mode uint32) DirEntry { return DirEntry{Path: path, Mode: mode} }

func link(path, target string) Entry {
	return Entry{Path: path, Size: int64(len(target)), Link: target, Hash: linkHash(target)}
}

func modeFile(path, content string, mode uint32) Entry {
	e := file(path, content)
	e.Mode = mode
	return e
}

func TestDiffClassifies(t *testing.T) {
	tests := []struct {
		name     string
		old, cur Manifest
		want     []Change
	}{
		{
			name: "identical manifests converge",
			old:  Manifest{Entries: []Entry{file("a.txt", "x")}, Dirs: []DirEntry{dir("d", 0o755)}},
			cur:  Manifest{Entries: []Entry{file("a.txt", "x")}, Dirs: []DirEntry{dir("d", 0o755)}},
		},
		{
			name: "file added and removed",
			old:  Manifest{Entries: []Entry{file("gone.txt", "x")}},
			cur:  Manifest{Entries: []Entry{file("fresh.txt", "y")}},
			want: []Change{
				{Path: "fresh.txt", Kind: ChangeAdded, Type: ChildFile},
				{Path: "gone.txt", Kind: ChangeRemoved, Type: ChildFile},
			},
		},
		{
			name: "file content change",
			old:  Manifest{Entries: []Entry{file("a.txt", "v1")}},
			cur:  Manifest{Entries: []Entry{file("a.txt", "v2")}},
			want: []Change{{Path: "a.txt", Kind: ChangeContent, Type: ChildFile}},
		},
		{
			name: "file mode-only change",
			old:  Manifest{Entries: []Entry{modeFile("run.sh", "x", 0o644)}},
			cur:  Manifest{Entries: []Entry{modeFile("run.sh", "x", 0o755)}},
			want: []Change{{Path: "run.sh", Kind: ChangeMode, Type: ChildFile}},
		},
		{
			name: "content change subsumes a simultaneous mode edit",
			old:  Manifest{Entries: []Entry{modeFile("run.sh", "v1", 0o644)}},
			cur:  Manifest{Entries: []Entry{modeFile("run.sh", "v2", 0o755)}},
			want: []Change{{Path: "run.sh", Kind: ChangeContent, Type: ChildFile}},
		},
		{
			name: "symlink retarget is a content change",
			old:  Manifest{Entries: []Entry{link("ln", "old")}},
			cur:  Manifest{Entries: []Entry{link("ln", "new")}},
			want: []Change{{Path: "ln", Kind: ChangeContent, Type: ChildSymlink}},
		},
		{
			name: "file becomes a symlink",
			old:  Manifest{Entries: []Entry{file("p", "x")}},
			cur:  Manifest{Entries: []Entry{link("p", "elsewhere")}},
			want: []Change{{Path: "p", Kind: ChangeType, Type: ChildSymlink, Was: ChildFile}},
		},
		{
			name: "file becomes a directory, its contents arrive",
			old:  Manifest{Entries: []Entry{file("p", "x")}},
			cur:  Manifest{Entries: []Entry{file("p/inner.txt", "y")}, Dirs: []DirEntry{dir("p", 0o755)}},
			want: []Change{
				{Path: "p", Kind: ChangeType, Type: ChildDir, Was: ChildFile},
				{Path: "p/inner.txt", Kind: ChangeAdded, Type: ChildFile},
			},
		},
		{
			name: "empty directory added",
			old:  Manifest{},
			cur:  Manifest{Dirs: []DirEntry{dir("empty", 0o755)}},
			want: []Change{{Path: "empty", Kind: ChangeAdded, Type: ChildDir}},
		},
		{
			name: "empty directory removed",
			old:  Manifest{Dirs: []DirEntry{dir("empty", 0o755)}},
			cur:  Manifest{},
			want: []Change{{Path: "empty", Kind: ChangeRemoved, Type: ChildDir}},
		},
		{
			name: "directory mode-only change",
			old:  Manifest{Dirs: []DirEntry{dir("d", 0o755)}},
			cur:  Manifest{Dirs: []DirEntry{dir("d", 0o700)}},
			want: []Change{{Path: "d", Kind: ChangeMode, Type: ChildDir}},
		},
		{
			name: "unique content moved is a rename, not delete+add",
			old:  Manifest{Entries: []Entry{file("a.txt", "only")}},
			cur:  Manifest{Entries: []Entry{file("b.txt", "only")}},
		},
		{
			name: "duplicate content stays delete+add",
			old:  Manifest{Entries: []Entry{file("one.txt", "dup"), file("two.txt", "dup")}},
			cur:  Manifest{Entries: []Entry{file("moved.txt", "dup")}},
			want: []Change{
				{Path: "moved.txt", Kind: ChangeAdded, Type: ChildFile},
				{Path: "one.txt", Kind: ChangeRemoved, Type: ChildFile},
				{Path: "two.txt", Kind: ChangeRemoved, Type: ChildFile},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Diff(tc.old, tc.cur)
			if len(got.Changes) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got.Changes, tc.want) {
				t.Errorf("changes = %+v, want %+v", got.Changes, tc.want)
			}
		})
	}
}

func TestDiffRenameSwallowsTheDirectoryPair(t *testing.T) {
	old := Manifest{
		Entries: []Entry{file("olddir/a.txt", "a"), file("olddir/sub/b.txt", "b")},
		Dirs:    []DirEntry{dir("olddir", 0o755), dir("olddir/sub", 0o755)},
	}
	cur := Manifest{
		Entries: []Entry{file("newdir/a.txt", "a"), file("newdir/sub/b.txt", "b")},
		Dirs:    []DirEntry{dir("newdir", 0o755), dir("newdir/sub", 0o755)},
	}

	got := Diff(old, cur)

	want := []Rename{{From: "olddir", To: "newdir", Dir: true}}
	if !reflect.DeepEqual(got.Renamed, want) {
		t.Errorf("renamed = %+v, want %+v", got.Renamed, want)
	}
	// The directories moved as a set with their modes intact, so their add/remove pair
	// carries nothing the rename does not already say.
	if len(got.Changes) != 0 {
		t.Errorf("changes = %+v, want none", got.Changes)
	}
}

// A directory that moves *and* changes mode does not pair: the rename claim would
// hide the permission edit, so both sides are reported instead.
func TestDiffDirectoryRenameWithModeEditStaysExplicit(t *testing.T) {
	old := Manifest{
		Entries: []Entry{file("olddir/a.txt", "a")},
		Dirs:    []DirEntry{dir("olddir", 0o755)},
	}
	cur := Manifest{
		Entries: []Entry{file("newdir/a.txt", "a")},
		Dirs:    []DirEntry{dir("newdir", 0o700)},
	}

	got := Diff(old, cur)

	if want := []string{"newdir"}; !reflect.DeepEqual(got.Paths(ChangeAdded), want) {
		t.Errorf("added = %v, want %v", got.Paths(ChangeAdded), want)
	}
	if want := []string{"olddir"}; !reflect.DeepEqual(got.Paths(ChangeRemoved), want) {
		t.Errorf("removed = %v, want %v", got.Paths(ChangeRemoved), want)
	}
}

// Symlink permission bits are not a synced attribute — a scan never records them and
// apply never sets them — so a manifest that carries one must not manufacture a change
// no side could resolve.
func TestDiffIgnoresSymlinkMode(t *testing.T) {
	old := Manifest{Entries: []Entry{link("ln", "target")}}
	cur := Manifest{Entries: []Entry{link("ln", "target")}}
	cur.Entries[0].Mode = 0o777

	if got := Diff(old, cur); !got.Empty() {
		t.Errorf("symlink mode reported as a change: %+v", got.Changes)
	}
}

// deltaManifestsGen draws two manifests over a shared small alphabet of paths, kinds,
// hashes, and modes, so every classification (and both one-sided and two-sided shapes)
// occurs across runs. Symlinks are drawn without a mode, exactly as Scan records them,
// which is what lets the property below compare raw attributes.
func deltaManifestsGen() *rapid.Generator[[2]Manifest] {
	return rapid.Custom(func(t *rapid.T) [2]Manifest {
		paths := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{
			"a", "b", "c/d", "c/e", "f/g/h",
		}), 0, 5, rapid.ID).Draw(t, "paths")
		var out [2]Manifest
		for i := range out {
			for _, p := range paths {
				switch rapid.SampledFrom([]string{"absent", "file", "symlink", "dir"}).Draw(t, "kind") {
				case "absent":
				case "file":
					out[i].Entries = append(out[i].Entries, Entry{
						Path: p,
						Hash: rapid.SampledFrom([]string{"h1", "h2"}).Draw(t, "hash"),
						Mode: uint32(rapid.SampledFrom([]int{0o644, 0o755}).Draw(t, "mode")),
					})
				case "symlink":
					out[i].Entries = append(out[i].Entries, link(p, rapid.SampledFrom([]string{"t1", "t2"}).Draw(t, "target")))
				case "dir":
					out[i].Dirs = append(out[i].Dirs, DirEntry{
						Path: p,
						Mode: uint32(rapid.SampledFrom([]int{0o755, 0o700}).Draw(t, "dirmode")),
					})
				}
			}
		}
		return out
	})
}

// TestDiffProps pins the invariants every caller relies on: one verdict per path,
// convergence means silence, and a difference is never dropped.
func TestDiffProps(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ms := deltaManifestsGen().Draw(t, "manifests")
		old, cur := ms[0], ms[1]
		d := Diff(old, cur)

		seen := map[string]bool{}
		for _, c := range d.Changes {
			if seen[c.Path] {
				t.Fatalf("path %q classified twice", c.Path)
			}
			seen[c.Path] = true
		}

		o, n := trackedByPath(old), trackedByPath(cur)
		renamedFrom, renamedTo := map[string]bool{}, map[string]bool{}
		for _, r := range d.Renamed {
			renamedFrom[r.From], renamedTo[r.To] = true, true
		}
		// Every path that actually differs is either classified or explained by a
		// rename; every path that does not differ is silent.
		for p := range union(o, n) {
			before, hadBefore := o[p]
			after, hadAfter := n[p]
			differs := hadBefore != hadAfter || before != after
			explained := seen[p] || renamedFrom[p] || renamedTo[p]
			if differs && !explained {
				t.Fatalf("path %q differs (%+v -> %+v) but is not reported", p, before, after)
			}
			if !differs && explained {
				t.Fatalf("path %q is identical on both sides but was reported", p)
			}
		}

		// Diff is the definition of Empty: identical manifests produce nothing.
		if same := Diff(old, old); !same.Empty() {
			t.Fatalf("manifest diffed against itself is non-empty: %+v", same)
		}
	})
}

func union(a, b map[string]tracked) map[string]struct{} {
	out := make(map[string]struct{}, len(a)+len(b))
	for p := range a {
		out[p] = struct{}{}
	}
	for p := range b {
		out[p] = struct{}{}
	}
	return out
}

// TestDiffTreeRootsMatchesManifestDiff is the equivalence AC: the Merkle-DAG walk and
// the flat-manifest comparison must classify the same on-disk trees identically, so a
// caller cannot get a different answer depending on which side of the wire it read.
func TestDiffTreeRootsMatchesManifestDiff(t *testing.T) {
	oldDir, curDir := t.TempDir(), t.TempDir()
	for _, d := range []string{oldDir, curDir} {
		writeFile(t, d, "keep.txt", []byte("same"))
		writeFile(t, d, "mod.txt", []byte("v1"))
		writeFile(t, d, "perm.sh", []byte("#!/bin/sh"))
		writeFile(t, d, "nested/deep/leaf.txt", []byte("leaf"))
	}
	writeFile(t, oldDir, "gone/only-old.txt", []byte("o"))
	writeFile(t, oldDir, "moved/unique.txt", []byte("unique content"))
	writeFile(t, oldDir, "retyped", []byte("was a file"))
	writeFile(t, curDir, "fresh/only-new.txt", []byte("n"))
	writeFile(t, curDir, "elsewhere/unique.txt", []byte("unique content"))
	writeFile(t, curDir, "retyped/inner.txt", []byte("now a dir"))
	writeFile(t, curDir, "mod.txt", []byte("v2"))
	if err := os.Chmod(filepath.Join(curDir, "perm.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(curDir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-a", filepath.Join(oldDir, "ln")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := os.Symlink("target-b", filepath.Join(curDir, "ln")); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(curDir, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	oldScan, err := Scan(oldDir)
	if err != nil {
		t.Fatal(err)
	}
	curScan, err := Scan(curDir)
	if err != nil {
		t.Fatal(err)
	}

	conv := testConv(t)
	oldSink, curSink := mapSink{}, mapSink{}
	oldRoot, _, err := SealTree(oldScan, conv, oldSink)
	if err != nil {
		t.Fatal(err)
	}
	curRoot, _, err := SealTree(curScan, conv, curSink)
	if err != nil {
		t.Fatal(err)
	}
	fromTree, err := DiffTreeRoots(oldRoot, curRoot, newDiffFetcher(oldSink, curSink).fetch)
	if err != nil {
		t.Fatal(err)
	}

	fromManifests := Diff(oldScan, curScan)
	if !reflect.DeepEqual(fromTree.Changes, fromManifests.Changes) {
		t.Errorf("changes differ:\n tree      = %+v\n manifests = %+v", fromTree.Changes, fromManifests.Changes)
	}
	if !reflect.DeepEqual(fromTree.Renamed, fromManifests.Renamed) {
		t.Errorf("renames differ:\n tree      = %+v\n manifests = %+v", fromTree.Renamed, fromManifests.Renamed)
	}
	// The fixture must actually exercise every kind, or the equivalence is vacuous.
	for _, k := range []ChangeKind{ChangeAdded, ChangeRemoved, ChangeContent, ChangeMode, ChangeType} {
		if len(fromManifests.Paths(k)) == 0 {
			t.Errorf("fixture produced no %q change", k)
		}
	}
	if len(fromManifests.Renamed) == 0 {
		t.Error("fixture produced no rename")
	}
}
