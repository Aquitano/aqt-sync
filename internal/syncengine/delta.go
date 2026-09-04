// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"sort"
	"strings"
)

// ChangeKind classifies how one path differs between two manifests.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeContent ChangeKind = "content" // file bytes, or a symlink's target
	ChangeMode    ChangeKind = "mode"    // permission bits only; content identical
	ChangeType    ChangeKind = "type"    // file <-> symlink <-> directory
)

// Change is one classified difference at a path. Type is what the path denotes on
// the new side — or what it denoted on the old side, for a removal. Was is set only
// for ChangeType, naming the kind the path used to be.
type Change struct {
	Path string     `json:"path"`
	Kind ChangeKind `json:"kind"`
	Type ChildType  `json:"type"`
	Was  ChildType  `json:"was,omitempty"`
}

// IsDir reports whether the change concerns a tracked directory.
func (c Change) IsDir() bool { return c.Type == ChildDir }

// Delta is the difference between two manifests: every tracked file, symlink, and
// directory that differs, plus delete+add pairs coalesced into renames.
//
// It is the one definition of "changed" the tracked-folder commands share — status,
// both sync adapters' local-change gates, and snapshot diff — so a directory-only or
// mode-only edit cannot be visible to one caller and invisible to another. The
// three-way planners (Plan, PlanDirs) stay separate because they answer a different
// question, but they compare entries through the same rules (see entryDiffers).
type Delta struct {
	Changes []Change `json:"changes"`
	Renamed []Rename `json:"renamed"`
}

// Diff classifies every difference between two manifests. old is the reference side
// (the last-synced base, or the left side of a comparison) and cur the newer one, so
// a path only in cur is an addition and one only in old a removal.
func Diff(old, cur Manifest) Delta {
	d := Delta{Changes: classify(old, cur)}
	d.coalesceRenames(old, cur)
	return d
}

// Empty reports whether the two manifests describe the same tree.
func (d Delta) Empty() bool { return len(d.Changes) == 0 && len(d.Renamed) == 0 }

// Paths returns the sorted paths of the changes matching any of kinds.
func (d Delta) Paths(kinds ...ChangeKind) []string {
	var out []string
	for _, c := range d.Changes {
		for _, k := range kinds {
			if c.Kind == k {
				out = append(out, c.Path)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// tracked is one manifest path reduced to the attributes that decide equality.
type tracked struct {
	typ  ChildType
	mode uint32
	hash string
}

// trackedByPath indexes a manifest's files, symlinks, and directories into one
// keyspace, which is what lets a file-to-directory switch be seen as a single typed
// change rather than an unrelated removal and addition.
func trackedByPath(m Manifest) map[string]tracked {
	out := make(map[string]tracked, len(m.Entries)+len(m.Dirs))
	for _, d := range m.Dirs {
		out[d.Path] = tracked{typ: ChildDir, mode: d.Mode}
	}
	// A scan never records a path as both a directory and an entry. If a manifest ever
	// carries both, the entry wins so its content is not silently dropped from the diff.
	for _, e := range m.Entries {
		t := tracked{typ: ChildFile, mode: e.Mode, hash: e.Hash}
		if e.IsSymlink() {
			t.typ = ChildSymlink
		}
		out[e.Path] = t
	}
	return out
}

func classify(old, cur Manifest) []Change {
	o, c := trackedByPath(old), trackedByPath(cur)
	changes := make([]Change, 0, len(o)+len(c))
	for path, now := range c {
		before, existed := o[path]
		switch {
		case !existed:
			changes = append(changes, Change{Path: path, Kind: ChangeAdded, Type: now.typ})
		case before.typ != now.typ:
			changes = append(changes, Change{Path: path, Kind: ChangeType, Type: now.typ, Was: before.typ})
		case now.typ != ChildDir && before.hash != now.hash:
			// Content subsumes a simultaneous mode edit: one change reported per path.
			changes = append(changes, Change{Path: path, Kind: ChangeContent, Type: now.typ})
		case modeTracked(now.typ) && before.mode != now.mode:
			changes = append(changes, Change{Path: path, Kind: ChangeMode, Type: now.typ})
		}
	}
	for path, before := range o {
		if _, still := c[path]; !still {
			changes = append(changes, Change{Path: path, Kind: ChangeRemoved, Type: before.typ})
		}
	}
	sortChanges(changes)
	return changes
}

// modeTracked reports whether permission bits are a synced attribute of this kind.
// A symlink's own mode is not: a scan never records it and apply never sets it, so
// comparing it would manufacture a difference no side could resolve.
func modeTracked(t ChildType) bool { return t != ChildSymlink }

// entryDiffers is the single rule for "this is not the same entry": its content
// (file bytes or symlink target, both covered by Hash) or its permission bits
// changed. Plan and Diff both compare through it, so the operational planner and the
// reported classification can never disagree about what counts as a change.
func entryDiffers(old, cur Entry) bool {
	if old.IsSymlink() != cur.IsSymlink() {
		return true
	}
	if old.Hash != cur.Hash {
		return true
	}
	return modeTracked(entryType(cur)) && old.Mode != cur.Mode
}

func entryType(e Entry) ChildType {
	if e.IsSymlink() {
		return ChildSymlink
	}
	return ChildFile
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Path != cs[j].Path {
			return cs[i].Path < cs[j].Path
		}
		return cs[i].Kind < cs[j].Kind
	})
}

// coalesceRenames pairs one-sided file changes that only moved unchanged content,
// then drops the changes those renames already explain. A whole-directory move also
// swallows the directory's own add/remove pair: DetectRenames reports one only when
// the tracked directories moved as a set with their modes intact, so the pair says
// nothing the rename does not.
func (d *Delta) coalesceRenames(old, cur Manifest) {
	var added, removed []string
	for _, c := range d.Changes {
		switch {
		case c.IsDir():
		case c.Kind == ChangeAdded:
			added = append(added, c.Path)
		case c.Kind == ChangeRemoved:
			removed = append(removed, c.Path)
		}
	}
	renames, keptAdded, keptRemoved := DetectRenames(added, removed, cur, old)
	if len(renames) == 0 {
		return
	}
	d.Renamed = renames

	survived := make(map[string]bool, len(keptAdded)+len(keptRemoved))
	for _, p := range keptAdded {
		survived[p] = true
	}
	for _, p := range keptRemoved {
		survived[p] = true
	}
	kept := d.Changes[:0]
	for _, c := range d.Changes {
		if !d.explains(c, survived) {
			kept = append(kept, c)
		}
	}
	d.Changes = kept
}

// explains reports whether a detected rename already accounts for this change.
func (d Delta) explains(c Change, survivingFiles map[string]bool) bool {
	if c.Kind != ChangeAdded && c.Kind != ChangeRemoved {
		return false
	}
	if !c.IsDir() {
		return !survivingFiles[c.Path]
	}
	for _, r := range d.Renamed {
		if !r.Dir {
			continue
		}
		side := r.To
		if c.Kind == ChangeRemoved {
			side = r.From
		}
		if c.Path == side || strings.HasPrefix(c.Path, side+"/") {
			return true
		}
	}
	return false
}
