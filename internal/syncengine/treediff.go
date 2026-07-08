package syncengine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// TreeDiff is the result of DiffTreeRoots: sorted path lists for one-sided and
// changed files, plus delete+add pairs coalesced into renames by content
// address.
type TreeDiff struct {
	Added    []string
	Removed  []string
	Modified []string
	Renamed  []Rename
}

// diffEntry is one one-sided file or directory seen during the walk, kept with
// its content address and mode so renames can be paired afterwards.
type diffEntry struct {
	path string
	hash string
	mode uint32
}

// DiffTreeRoots compares two Merkle-DAG folders by content address alone: a
// directory child whose subtree hash matches on both sides is pruned without
// fetching its node, so the cost is O(changed spines + one-sided subtrees) in
// metadata objects and zero file-content chunks. Regular files are compared by
// their recorded plaintext hash; symlinks and directory modes are not reported,
// matching the on-disk diff this replaces (which hashed only regular files).
// A removed and an added entry with the same content address are coalesced
// into a rename (see coalesceTreeRenames). fetchBatch is called once per tree
// depth with every node id that level needs across both sides, so a
// level-batching transport keeps its round-trip shape.
func DiffTreeRoots(left, right TreeRoot, fetchBatch func(ids []string) (map[string][]byte, error)) (TreeDiff, error) {
	var d TreeDiff
	if left.Root.ID == right.Root.ID {
		return d, nil
	}
	var addedFiles, removedFiles, addedDirs, removedDirs []diffEntry

	// A pair is a directory present on both sides with differing subtree hashes:
	// its two nodes are fetched and their children merged. An enum is a directory
	// present on one side only: its subtree is walked to list the files that were
	// added (right-only) or removed (left-only).
	type pair struct {
		prefix      string
		left, right crypto.Chunk
	}
	type enum struct {
		prefix  string
		node    crypto.Chunk
		asAdded bool
	}
	pairs := []pair{{left: left.Root, right: right.Root}}
	var enums []enum

	for len(pairs) > 0 || len(enums) > 0 {
		ids := make([]string, 0, 2*len(pairs)+len(enums))
		for _, p := range pairs {
			ids = append(ids, p.left.ID, p.right.ID)
		}
		for _, e := range enums {
			ids = append(ids, e.node.ID)
		}
		cts, err := fetchBatch(ids)
		if err != nil {
			return TreeDiff{}, err
		}
		open := func(node crypto.Chunk) ([]TreeChild, error) {
			ct, ok := cts[node.ID]
			if !ok {
				return nil, fmt.Errorf("fetch tree node %s: node not returned", node.ID)
			}
			children, err := openNodeChildren(node, ct)
			if err != nil {
				return nil, err
			}
			// Children are name-sorted by construction; re-sort so the two-pointer
			// merge below cannot be confused by a node that violates the invariant.
			sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
			return children, nil
		}

		var nextPairs []pair
		var nextEnums []enum
		oneSided := func(prefix string, c TreeChild, asAdded bool) error {
			path := joinChild(prefix, c.Name)
			entry := diffEntry{path: path, hash: c.Hash, mode: c.Mode}
			switch c.Type {
			case ChildFile:
				if asAdded {
					addedFiles = append(addedFiles, entry)
				} else {
					removedFiles = append(removedFiles, entry)
				}
			case ChildSymlink:
				// Not reported, matching the on-disk diff.
			case ChildDir:
				if c.Node == nil {
					return fmt.Errorf("directory child %q has no node reference", path)
				}
				if asAdded {
					addedDirs = append(addedDirs, entry)
				} else {
					removedDirs = append(removedDirs, entry)
				}
				nextEnums = append(nextEnums, enum{prefix: path, node: *c.Node, asAdded: asAdded})
			default:
				return fmt.Errorf("unknown child type %q at %q", c.Type, path)
			}
			return nil
		}

		for _, p := range pairs {
			lc, err := open(p.left)
			if err != nil {
				return TreeDiff{}, err
			}
			rc, err := open(p.right)
			if err != nil {
				return TreeDiff{}, err
			}
			i, j := 0, 0
			for i < len(lc) || j < len(rc) {
				switch {
				case j >= len(rc) || (i < len(lc) && lc[i].Name < rc[j].Name):
					if err := oneSided(p.prefix, lc[i], false); err != nil {
						return TreeDiff{}, err
					}
					i++
				case i >= len(lc) || lc[i].Name > rc[j].Name:
					if err := oneSided(p.prefix, rc[j], true); err != nil {
						return TreeDiff{}, err
					}
					j++
				default:
					l, r := lc[i], rc[j]
					i, j = i+1, j+1
					path := joinChild(p.prefix, l.Name)
					switch {
					case l.Type == ChildDir && r.Type == ChildDir:
						if l.Hash == r.Hash {
							continue // identical subtree: pruned, never fetched
						}
						if l.Node == nil || r.Node == nil {
							return TreeDiff{}, fmt.Errorf("directory child %q has no node reference", path)
						}
						nextPairs = append(nextPairs, pair{prefix: path, left: *l.Node, right: *r.Node})
					case l.Type == r.Type:
						if l.Type == ChildFile && l.Hash != r.Hash {
							d.Modified = append(d.Modified, path)
						}
					default:
						// Type changed: whatever was there is gone, the new thing appeared.
						if err := oneSided(p.prefix, l, false); err != nil {
							return TreeDiff{}, err
						}
						if err := oneSided(p.prefix, r, true); err != nil {
							return TreeDiff{}, err
						}
					}
				}
			}
		}
		for _, e := range enums {
			children, err := open(e.node)
			if err != nil {
				return TreeDiff{}, err
			}
			for _, c := range children {
				if err := oneSided(e.prefix, c, e.asAdded); err != nil {
					return TreeDiff{}, err
				}
			}
		}
		pairs, enums = nextPairs, nextEnums
	}
	d.Renamed, d.Added, d.Removed = coalesceTreeRenames(addedFiles, removedFiles, addedDirs, removedDirs)
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	sort.Slice(d.Renamed, func(i, j int) bool { return d.Renamed[i].From < d.Renamed[j].From })
	return d, nil
}

// coalesceTreeRenames pairs one-sided entries whose content address matches.
// Directories pair by subtree Merkle hash — a moved directory keeps its node
// id — and consume every file reported under them; files pair by plaintext
// hash. A hash pairs only when it identifies exactly one entry on each side of
// the diff and the modes match; duplicated content stays delete+add. Unchanged
// subtrees were pruned before this runs, so uniqueness is judged within the
// diff — the conservative choice available without walking both full trees. A
// directory pair with no reported file under it (empty or symlink-only) is
// skipped: such a subtree produces no diff output today, and all empty
// directories share one node id, so a pairing would be a guess.
func coalesceTreeRenames(addedFiles, removedFiles, addedDirs, removedDirs []diffEntry) (renames []Rename, added, removed []string) {
	soleByHash := func(entries []diffEntry) map[string]diffEntry {
		count := make(map[string]int, len(entries))
		for _, e := range entries {
			count[e.hash]++
		}
		sole := make(map[string]diffEntry)
		for _, e := range entries {
			if count[e.hash] == 1 {
				sole[e.hash] = e
			}
		}
		return sole
	}

	filesUnder := func(entries []diffEntry, dir string) int {
		n := 0
		for _, e := range entries {
			if strings.HasPrefix(e.path, dir+"/") {
				n++
			}
		}
		return n
	}

	remDir, addDir := soleByHash(removedDirs), soleByHash(addedDirs)
	type cand struct{ from, to diffEntry }
	var cands []cand
	for h, from := range remDir {
		if to, ok := addDir[h]; ok && from.mode == to.mode {
			cands = append(cands, cand{from, to})
		}
	}
	// Shallowest first, so a whole-tree move wins over its subdirectories.
	sort.Slice(cands, func(i, j int) bool {
		di, dj := strings.Count(cands[i].from.path, "/"), strings.Count(cands[j].from.path, "/")
		if di != dj {
			return di < dj
		}
		return cands[i].from.path < cands[j].from.path
	})
	var dirRenames []Rename
	consumed := func(from, to string) bool {
		for _, r := range dirRenames {
			if strings.HasPrefix(from, r.From+"/") || strings.HasPrefix(to, r.To+"/") {
				return true
			}
		}
		return false
	}
	for _, c := range cands {
		if consumed(c.from.path, c.to.path) {
			continue
		}
		if filesUnder(removedFiles, c.from.path) == 0 {
			continue
		}
		dirRenames = append(dirRenames, Rename{From: c.from.path, To: c.to.path, Dir: true})
	}
	underAny := func(path string, side func(Rename) string) bool {
		for _, r := range dirRenames {
			if strings.HasPrefix(path, side(r)+"/") {
				return true
			}
		}
		return false
	}
	var remainAdded, remainRemoved []diffEntry
	for _, e := range addedFiles {
		if !underAny(e.path, func(r Rename) string { return r.To }) {
			remainAdded = append(remainAdded, e)
		}
	}
	for _, e := range removedFiles {
		if !underAny(e.path, func(r Rename) string { return r.From }) {
			remainRemoved = append(remainRemoved, e)
		}
	}

	remFile, addFile := soleByHash(remainRemoved), soleByHash(remainAdded)
	renames = dirRenames
	pairedTo := map[string]bool{}
	for _, e := range remainRemoved {
		_, fok := remFile[e.hash]
		to, tok := addFile[e.hash]
		if !fok || !tok || e.mode != to.mode {
			removed = append(removed, e.path)
			continue
		}
		renames = append(renames, Rename{From: e.path, To: to.path})
		pairedTo[to.path] = true
	}
	for _, e := range remainAdded {
		if !pairedTo[e.path] {
			added = append(added, e.path)
		}
	}
	return renames, added, removed
}
