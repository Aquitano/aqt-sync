package syncengine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// diffEntry is one one-sided file, symlink, or directory seen during the walk, kept
// with its content address and mode so renames can be paired afterwards.
type diffEntry struct {
	path string
	typ  ChildType
	hash string
	mode uint32
}

// DiffTreeRoots compares two Merkle-DAG folders by content address alone: a
// directory child whose subtree hash matches on both sides is pruned without
// fetching its node, so the cost is O(changed spines + one-sided subtrees) in
// metadata objects and zero file-content chunks.
//
// It reports the same classification Diff derives from two flat manifests — files,
// symlinks, and directories across additions, removals, content, mode, and type
// changes — so a caller cannot get a different answer depending on which side of the
// wire it compared. A removed and an added entry with the same content address are
// coalesced into a rename (see coalesceTreeRenames). fetchBatch is called once per
// tree depth with every node id that level needs across both sides, so a
// level-batching transport keeps its round-trip shape.
func DiffTreeRoots(left, right TreeRoot, fetchBatch func(ids []string) (map[string][]byte, error)) (Delta, error) {
	var d Delta
	if left.Root.ID == right.Root.ID {
		return d, nil
	}
	var added, removed []diffEntry

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
			return Delta{}, err
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
		descend := func(path string, c TreeChild, asAdded bool) error {
			if c.Type != ChildDir {
				return nil
			}
			if c.Node == nil {
				return fmt.Errorf("directory child %q has no node reference", path)
			}
			nextEnums = append(nextEnums, enum{prefix: path, node: *c.Node, asAdded: asAdded})
			return nil
		}
		oneSided := func(prefix string, c TreeChild, asAdded bool) error {
			path := joinChild(prefix, c.Name)
			switch c.Type {
			case ChildFile, ChildSymlink, ChildDir:
			default:
				return fmt.Errorf("unknown child type %q at %q", c.Type, path)
			}
			e := diffEntry{path: path, typ: c.Type, hash: c.Hash, mode: c.Mode}
			if asAdded {
				added = append(added, e)
			} else {
				removed = append(removed, e)
			}
			return descend(path, c, asAdded)
		}
		reconcileMatchedChildren := func(prefix string, l, r TreeChild) error {
			path := joinChild(prefix, l.Name)
			if l.Type != r.Type {
				// The path itself is retyped; whatever hung below an old directory is
				// gone and whatever hangs below a new one arrived, which is exactly how
				// the flat-manifest diff reports the same edit.
				d.Changes = append(d.Changes, Change{Path: path, Kind: ChangeType, Type: r.Type, Was: l.Type})
				if err := descend(path, l, false); err != nil {
					return err
				}
				return descend(path, r, true)
			}
			if l.Type == ChildDir {
				// A directory's own mode is not folded into its subtree hash, so it must
				// be compared before the identical-subtree prune, not after it.
				if l.Mode != r.Mode {
					d.Changes = append(d.Changes, Change{Path: path, Kind: ChangeMode, Type: ChildDir})
				}
				if l.Hash == r.Hash {
					return nil // identical subtree: pruned, never fetched
				}
				if l.Node == nil || r.Node == nil {
					return fmt.Errorf("directory child %q has no node reference", path)
				}
				nextPairs = append(nextPairs, pair{prefix: path, left: *l.Node, right: *r.Node})
				return nil
			}
			switch {
			case l.Hash != r.Hash:
				d.Changes = append(d.Changes, Change{Path: path, Kind: ChangeContent, Type: r.Type})
			case modeTracked(r.Type) && l.Mode != r.Mode:
				d.Changes = append(d.Changes, Change{Path: path, Kind: ChangeMode, Type: r.Type})
			}
			return nil
		}

		for _, p := range pairs {
			lc, err := open(p.left)
			if err != nil {
				return Delta{}, err
			}
			rc, err := open(p.right)
			if err != nil {
				return Delta{}, err
			}
			i, j := 0, 0
			for i < len(lc) || j < len(rc) {
				switch {
				case j >= len(rc) || (i < len(lc) && lc[i].Name < rc[j].Name):
					if err := oneSided(p.prefix, lc[i], false); err != nil {
						return Delta{}, err
					}
					i++
				case i >= len(lc) || lc[i].Name > rc[j].Name:
					if err := oneSided(p.prefix, rc[j], true); err != nil {
						return Delta{}, err
					}
					j++
				default:
					l, r := lc[i], rc[j]
					i, j = i+1, j+1
					if err := reconcileMatchedChildren(p.prefix, l, r); err != nil {
						return Delta{}, err
					}
				}
			}
		}
		for _, e := range enums {
			children, err := open(e.node)
			if err != nil {
				return Delta{}, err
			}
			for _, c := range children {
				if err := oneSided(e.prefix, c, e.asAdded); err != nil {
					return Delta{}, err
				}
			}
		}
		pairs, enums = nextPairs, nextEnums
	}

	var keptAdded, keptRemoved []diffEntry
	d.Renamed, keptAdded, keptRemoved = coalesceTreeRenames(added, removed)
	for _, e := range keptAdded {
		d.Changes = append(d.Changes, Change{Path: e.path, Kind: ChangeAdded, Type: e.typ})
	}
	for _, e := range keptRemoved {
		d.Changes = append(d.Changes, Change{Path: e.path, Kind: ChangeRemoved, Type: e.typ})
	}
	sortChanges(d.Changes)
	sort.Slice(d.Renamed, func(i, j int) bool { return d.Renamed[i].From < d.Renamed[j].From })
	return d, nil
}

// coalesceTreeRenames pairs one-sided entries whose content address matches and
// returns the entries no rename explained. Directories pair by subtree Merkle hash —
// a moved directory keeps its node id — and consume everything reported under them;
// files and symlinks pair by content hash. A hash pairs only when it identifies
// exactly one entry on each side of the diff and the modes match; duplicated content
// stays delete+add. Unchanged subtrees were pruned before this runs, so uniqueness is
// judged within the diff — the conservative choice available without walking both
// full trees. A directory pair with no reported file under it (empty, or symlink-only)
// is skipped: all empty directories share one node id, so a pairing would be a guess.
func coalesceTreeRenames(added, removed []diffEntry) (renames []Rename, keptAdded, keptRemoved []diffEntry) {
	split := func(es []diffEntry) (files, dirs []diffEntry) {
		for _, e := range es {
			if e.typ == ChildDir {
				dirs = append(dirs, e)
			} else {
				files = append(files, e)
			}
		}
		return files, dirs
	}
	addedFiles, addedDirs := split(added)
	removedFiles, removedDirs := split(removed)

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
	atOrUnder := func(path, dir string) bool {
		return path == dir || strings.HasPrefix(path, dir+"/")
	}
	survives := func(es []diffEntry, side func(Rename) string) []diffEntry {
		var out []diffEntry
		for _, e := range es {
			covered := false
			for _, r := range dirRenames {
				if atOrUnder(e.path, side(r)) {
					covered = true
					break
				}
			}
			if !covered {
				out = append(out, e)
			}
		}
		return out
	}
	toSide := func(r Rename) string { return r.To }
	fromSide := func(r Rename) string { return r.From }
	remainAdded := survives(addedFiles, toSide)
	remainRemoved := survives(removedFiles, fromSide)

	remFile, addFile := soleByHash(remainRemoved), soleByHash(remainAdded)
	renames = dirRenames
	pairedTo := map[string]bool{}
	for _, e := range remainRemoved {
		_, fok := remFile[e.hash]
		to, tok := addFile[e.hash]
		if !fok || !tok || e.mode != to.mode {
			keptRemoved = append(keptRemoved, e)
			continue
		}
		renames = append(renames, Rename{From: e.path, To: to.path})
		pairedTo[to.path] = true
	}
	for _, e := range remainAdded {
		if !pairedTo[e.path] {
			keptAdded = append(keptAdded, e)
		}
	}
	keptAdded = append(keptAdded, survives(addedDirs, toSide)...)
	keptRemoved = append(keptRemoved, survives(removedDirs, fromSide)...)
	return renames, keptAdded, keptRemoved
}
