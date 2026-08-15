// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
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
	var accepted []Rename
	underAccepted := func(from, to string) bool {
		for _, a := range accepted {
			if strings.HasPrefix(from, a.From+"/") || strings.HasPrefix(to, a.To+"/") {
				return true
			}
		}
		return false
	}
	for _, p := range pairs {
		if underAccepted(p.from, p.to) {
			continue
		}
		if dirMoveComplete(p.from, p.to, renameTo, cur, old) {
			accepted = append(accepted, Rename{From: p.from, To: p.to, Dir: true})
		}
	}
	if len(accepted) == 0 {
		return renames
	}
	out := accepted
	for _, r := range renames {
		consumed := false
		for _, a := range accepted {
			if strings.HasPrefix(r.From, a.From+"/") {
				consumed = true
				break
			}
		}
		if !consumed {
			out = append(out, r)
		}
	}
	return out
}

func dirMoveComplete(from, to string, renameTo map[string]string, cur, old Manifest) bool {
	fp, tp := from+"/", to+"/"
	moved := 0
	for _, e := range old.Entries {
		if e.Path == to || strings.HasPrefix(e.Path, tp) {
			return false // destination predates the move
		}
		if strings.HasPrefix(e.Path, fp) {
			if renameTo[e.Path] != tp+e.Path[len(fp):] {
				return false
			}
			moved++
		}
	}
	if moved == 0 {
		return false
	}
	arrived := 0
	for _, e := range cur.Entries {
		if e.Path == from || strings.HasPrefix(e.Path, fp) {
			return false // something remains under the source
		}
		if strings.HasPrefix(e.Path, tp) {
			arrived++
		}
	}
	if arrived != moved {
		return false // destination gained content from elsewhere
	}

	// Tracked dirs must move as one set, keeping their modes ("" is the moved
	// dir itself).
	oldDirs := map[string]uint32{}
	for _, d := range old.Dirs {
		if d.Path == to || strings.HasPrefix(d.Path, tp) {
			return false
		}
		if d.Path == from {
			oldDirs[""] = d.Mode
		} else if strings.HasPrefix(d.Path, fp) {
			oldDirs[d.Path[len(fp):]] = d.Mode
		}
	}
	curDirs := map[string]uint32{}
	for _, d := range cur.Dirs {
		if d.Path == from || strings.HasPrefix(d.Path, fp) {
			return false
		}
		if d.Path == to {
			curDirs[""] = d.Mode
		} else if strings.HasPrefix(d.Path, tp) {
			curDirs[d.Path[len(tp):]] = d.Mode
		}
	}
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
