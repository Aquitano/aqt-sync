// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"slices"
	"sort"

	"github.com/charmbracelet/lipgloss"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// changeSet is the rendered view of one manifest-to-manifest delta, shared by
// status's local and incoming halves, the TUI's files panel, and snapshot diff. The
// buckets hold raw paths — what JSON callers have always consumed — while changes
// carries the full classification behind them, including the tracked directories and
// the mode/type edits the buckets flatten into "modified".
type changeSet struct {
	changes  []syncengine.Change
	renamed  []syncengine.Rename
	added    []string
	modified []string
	deleted  []string
}

func newChangeSet(d syncengine.Delta) changeSet {
	return changeSet{
		changes:  d.Changes,
		renamed:  d.Renamed,
		added:    d.Paths(syncengine.ChangeAdded),
		modified: d.Paths(syncengine.ChangeContent, syncengine.ChangeMode, syncengine.ChangeType),
		deleted:  d.Paths(syncengine.ChangeRemoved),
	}
}

// total counts every difference, a rename counting once rather than as the delete and
// add it replaced.
func (s changeSet) total() int { return len(s.changes) + len(s.renamed) }

// kindRank orders the change kinds so the familiar new/modified/deleted grouping
// survives, with mode and type changes slotted next to the edits they refine.
func kindRank(k syncengine.ChangeKind) int {
	switch k {
	case syncengine.ChangeAdded:
		return 0
	case syncengine.ChangeContent:
		return 1
	case syncengine.ChangeMode:
		return 2
	case syncengine.ChangeType:
		return 3
	default:
		return 4
	}
}

// changeLabel is the column label for a classified change.
func changeLabel(k syncengine.ChangeKind) string {
	switch k {
	case syncengine.ChangeAdded:
		return "new"
	case syncengine.ChangeRemoved:
		return "deleted"
	case syncengine.ChangeMode:
		return "mode"
	case syncengine.ChangeType:
		return "type"
	default:
		return "modified"
	}
}

// changeMark is the one-letter marker the TUI puts in its gutter.
func changeMark(k syncengine.ChangeKind) string {
	switch k {
	case syncengine.ChangeAdded:
		return "A"
	case syncengine.ChangeRemoved:
		return "D"
	default:
		return "M"
	}
}

// tuiChangeStyle colors a change's gutter mark, grouping the mode and type edits
// with the content edits they refine.
func tuiChangeStyle(k syncengine.ChangeKind) lipgloss.Style {
	switch k {
	case syncengine.ChangeAdded:
		return tuiStyleAdd
	case syncengine.ChangeRemoved:
		return tuiStyleDel
	default:
		return tuiStyleMod
	}
}

// nameStatusMark is `aqt diff --name-status`'s one-letter column: git's vocabulary
// extended with the two kinds the shared classification made visible — P for a
// permission-only edit and T for a path that changed between file, symlink, and
// directory.
func nameStatusMark(k syncengine.ChangeKind) string {
	switch k {
	case syncengine.ChangeAdded:
		return "A"
	case syncengine.ChangeRemoved:
		return "D"
	case syncengine.ChangeMode:
		return "P"
	case syncengine.ChangeType:
		return "T"
	default:
		return "M"
	}
}

// diffMark is snapshot diff's one-character gutter: the familiar +/-/~ for the three
// buckets, with mode and type edits marked apart from a content edit.
func diffMark(k syncengine.ChangeKind) string {
	switch k {
	case syncengine.ChangeAdded:
		return "+"
	case syncengine.ChangeRemoved:
		return "-"
	case syncengine.ChangeMode:
		return "m"
	case syncengine.ChangeType:
		return "t"
	default:
		return "~"
	}
}

// changePath renders a change's path for humans: a directory gets the trailing slash
// the plan printer uses, and a retyped path names what it turned into.
func changePath(c syncengine.Change) string {
	path := c.Path
	if c.IsDir() {
		path += "/"
	}
	if c.Kind == syncengine.ChangeType {
		return fmt.Sprintf("%s (%s -> %s)", path, c.Was, c.Type)
	}
	return path
}

// orderedChanges sorts a change set for display: by kind, then by path.
func orderedChanges(changes []syncengine.Change) []syncengine.Change {
	out := slices.Clone(changes)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := kindRank(out[i].Kind), kindRank(out[j].Kind); ri != rj {
			return ri < rj
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// printChanges lists a change set for humans. indent groups incoming changes under
// the "incoming:" summary so they never read as top-level local changes.
func printChanges(s changeSet, indent string) {
	for _, c := range orderedChanges(s.changes) {
		fmt.Printf("%s%-9s %s\n", indent, changeLabel(c.Kind), changePath(c))
	}
	for _, r := range s.renamed {
		fmt.Printf("%s%-9s %s\n", indent, "renamed", renameArrow(r))
	}
}

// nonNilChanges and nonNilRenames keep JSON output arrays rather than null, matching
// nonNil's contract for path lists.
func nonNilChanges(c []syncengine.Change) []syncengine.Change {
	if c == nil {
		return []syncengine.Change{}
	}
	return c
}

func nonNilRenames(r []syncengine.Rename) []syncengine.Rename {
	if r == nil {
		return []syncengine.Rename{}
	}
	return r
}
