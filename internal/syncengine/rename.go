// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"cmp"
	"slices"
	"sort"
	"strings"
)

// Rename is a delete+add pair coalesced into one reported move: both paths
// carry the same content address (file hash, or subtree Merkle hash for a
// directory), so the bytes did not change — only the path did. Renames are a
// reporting concept: sync still executes the underlying delete+add, whose
// bytes already dedup under content addressing, so coalescing changes no
// network traffic.
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
	Dir  bool   `json:"dir,omitempty"`
}

// DetectRenames coalesces added/deleted pairs from a manifest-level diff into
// renames. Pairing is conservative: a deleted and an added path pair only when
// hash and mode match and that hash occurs exactly once in each manifest, so
// duplicated content falls back to delete+add rather than a guessed pairing.
// Per-file renames that together move an entire directory are then collapsed
// to a single directory rename. Returns the renames plus the added/deleted
// lists with the paired paths removed.
func DetectRenames(added, deleted []string, cur, old Manifest) ([]Rename, []string, []string) {
	if len(added) == 0 || len(deleted) == 0 {
		return nil, added, deleted
	}
	curBy, oldBy := cur.ByPath(), old.ByPath()
	curCount := make(map[string]int, len(cur.Entries))
	for _, e := range cur.Entries {
		curCount[e.Hash]++
	}
	oldCount := make(map[string]int, len(old.Entries))
	for _, e := range old.Entries {
		oldCount[e.Hash]++
	}

	addedByHash := make(map[string]string, len(added))
	for _, p := range added {
		if e, ok := curBy[p]; ok && curCount[e.Hash] == 1 {
			addedByHash[e.Hash] = p
		}
	}

	var renames []Rename
	renamedFrom := map[string]bool{}
	renamedTo := map[string]bool{}
	for _, p := range deleted {
		e, ok := oldBy[p]
		if !ok || oldCount[e.Hash] != 1 {
			continue
		}
		to, ok := addedByHash[e.Hash]
		if !ok || curBy[to].Mode != e.Mode {
			continue
		}
		renames = append(renames, Rename{From: p, To: to})
		renamedFrom[p] = true
		renamedTo[to] = true
	}
	if len(renames) == 0 {
		return nil, added, deleted
	}
	renames = coalesceDirRenames(renames, cur, old)
	sort.Slice(renames, func(i, j int) bool { return renames[i].From < renames[j].From })
	return renames, withoutPaths(added, renamedTo), withoutPaths(deleted, renamedFrom)
}

func withoutPaths(paths []string, drop map[string]bool) []string {
	out := paths[:0:0]
	for _, p := range paths {
		if !drop[p] {
			out = append(out, p)
		}
	}
	return out
}

// coalesceDirRenames collapses per-file renames that together move an entire
// directory into one directory rename. A prefix pair qualifies only when the
// move is total: every old entry and tracked dir under from maps to the same
// relative path under to (dir modes equal), nothing remains under from, and
// nothing under to predates the move. Partial or mixed moves keep their
// per-file renames.
func coalesceDirRenames(renames []Rename, cur, old Manifest) []Rename {
	type prefixPair struct{ from, to string }
	cands := map[prefixPair]bool{}
	for _, r := range renames {
		fs, ts := strings.Split(r.From, "/"), strings.Split(r.To, "/")
		// Each shared trailing segment run yields a candidate ancestor pair.
		for k := 1; k < len(fs) && k < len(ts); k++ {
			if fs[len(fs)-k] != ts[len(ts)-k] {
				break
			}
			from := strings.Join(fs[:len(fs)-k], "/")
			to := strings.Join(ts[:len(ts)-k], "/")
			if from != to {
				cands[prefixPair{from, to}] = true
			}
		}
	}
	if len(cands) == 0 {
		return renames
	}
	pairs := make([]prefixPair, 0, len(cands))
	for p := range cands {
		pairs = append(pairs, p)
	}
	// Shallowest first, so a whole-tree move wins over its subdirectories.
	sort.Slice(pairs, func(i, j int) bool {
		di, dj := strings.Count(pairs[i].from, "/"), strings.Count(pairs[j].from, "/")
		if di != dj {
			return di < dj
		}
		return pairs[i].from < pairs[j].from
	})

	renameTo := make(map[string]string, len(renames))
	for _, r := range renames {
		renameTo[r.From] = r.To
	}
	oldIdx, curIdx := newTreeIndex(old), newTreeIndex(cur)
	var accepted []Rename
	acceptedFrom, acceptedTo := map[string]bool{}, map[string]bool{}
	for _, p := range pairs {
		if hasProperAncestorIn(p.from, acceptedFrom) || hasProperAncestorIn(p.to, acceptedTo) {
			continue
		}
		if dirMoveComplete(p.from, p.to, renameTo, curIdx, oldIdx) {
			accepted = append(accepted, Rename{From: p.from, To: p.to, Dir: true})
			acceptedFrom[p.from], acceptedTo[p.to] = true, true
		}
	}
	if len(accepted) == 0 {
		return renames
	}
	out := accepted
	for _, r := range renames {
		if !hasProperAncestorIn(r.From, acceptedFrom) {
			out = append(out, r)
		}
	}
	return out
}

// hasProperAncestorIn reports whether any directory strictly above p is in dirs.
// Walking p's O(depth) ancestors keeps rename coalescing linear in the number of
// renames rather than quadratic in the directories a mass move produces.
func hasProperAncestorIn(p string, dirs map[string]bool) bool {
	for i := range len(p) {
		if p[i] == '/' && dirs[p[:i]] {
			return true
		}
	}
	return false
}

// treeIndex holds one manifest's paths sorted, so what sits at or below a directory
// is a binary search away instead of a scan of the whole tree per candidate.
type treeIndex struct {
	entries []string
	dirs    []indexedDir
}

// indexedDir keeps a directory's manifest position, which decides between
// duplicate paths the way a scan in manifest order would.
type indexedDir struct {
	DirEntry
	pos int
}

func newTreeIndex(m Manifest) treeIndex {
	x := treeIndex{entries: make([]string, len(m.Entries)), dirs: make([]indexedDir, len(m.Dirs))}
	for i, e := range m.Entries {
		x.entries[i] = e.Path
	}
	slices.Sort(x.entries)
	for i, d := range m.Dirs {
		x.dirs[i] = indexedDir{d, i}
	}
	slices.SortFunc(x.dirs, func(a, b indexedDir) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), cmp.Compare(a.pos, b.pos))
	})
	return x
}

// sortedSpan returns the half-open index range of the sorted keys in [lo, hi).
// Every path strictly below dir lies in [dir+"/", dir+"0"), '0' being the byte
// after '/', and dir itself is the only string in [dir, dir+"\x00").
func sortedSpan(n int, key func(int) string, lo, hi string) (int, int) {
	return sort.Search(n, func(i int) bool { return key(i) >= lo }), sort.Search(n, func(i int) bool { return key(i) >= hi })
}

func (x treeIndex) entriesUnder(dir string) []string {
	lo, hi := sortedSpan(len(x.entries), func(i int) string { return x.entries[i] }, dir+"/", dir+"0")
	return x.entries[lo:hi]
}

func (x treeIndex) hasEntry(p string) bool {
	_, found := slices.BinarySearch(x.entries, p)
	return found
}

// dirsAtOrUnder returns dir and every tracked directory below it, in manifest order.
func (x treeIndex) dirsAtOrUnder(dir string) []indexedDir {
	key := func(i int) string { return x.dirs[i].Path }
	lo, hi := sortedSpan(len(x.dirs), key, dir, dir+"\x00")
	out := slices.Clone(x.dirs[lo:hi])
	lo, hi = sortedSpan(len(x.dirs), key, dir+"/", dir+"0")
	out = append(out, x.dirs[lo:hi]...)
	slices.SortFunc(out, func(a, b indexedDir) int { return cmp.Compare(a.pos, b.pos) })
	return out
}

func dirMoveComplete(from, to string, renameTo map[string]string, cur, old treeIndex) bool {
	fp, tp := from+"/", to+"/"
	if old.hasEntry(to) || len(old.entriesUnder(to)) > 0 {
		return false // destination predates the move
	}
	moved := old.entriesUnder(from)
	if len(moved) == 0 {
		return false
	}
	for _, p := range moved {
		if renameTo[p] != tp+p[len(fp):] {
			return false
		}
	}
	if cur.hasEntry(from) || len(cur.entriesUnder(from)) > 0 {
		return false // something remains under the source
	}
	if len(cur.entriesUnder(to)) != len(moved) {
		return false // destination gained content from elsewhere
	}

	// Tracked dirs must move as one set, keeping their modes ("" is the moved
	// dir itself).
	if len(old.dirsAtOrUnder(to)) > 0 || len(cur.dirsAtOrUnder(from)) > 0 {
		return false
	}
	oldDirs := relativeDirModes(old.dirsAtOrUnder(from), from)
	curDirs := relativeDirModes(cur.dirsAtOrUnder(to), to)
	if len(oldDirs) != len(curDirs) {
		return false
	}
	for rel, mode := range oldDirs {
		if m, ok := curDirs[rel]; !ok || m != mode {
			return false
		}
	}
	return true
}

func relativeDirModes(dirs []indexedDir, root string) map[string]uint32 {
	out := make(map[string]uint32, len(dirs))
	for _, d := range dirs {
		rel := ""
		if len(d.Path) > len(root) {
			rel = d.Path[len(root)+1:]
		}
		out[rel] = d.Mode
	}
	return out
}
