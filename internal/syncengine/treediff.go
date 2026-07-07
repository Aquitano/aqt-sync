package syncengine

import (
	"fmt"
	"sort"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// DiffTreeRoots compares two Merkle-DAG folders by content address alone: a
// directory child whose subtree hash matches on both sides is pruned without
// fetching its node, so the cost is O(changed spines + one-sided subtrees) in
// metadata objects and zero file-content chunks. Regular files are compared by
// their recorded plaintext hash; symlinks and directory modes are not reported,
// matching the on-disk diff this replaces (which hashed only regular files).
// fetchBatch is called once per tree depth with every node id that level needs
// across both sides, so a level-batching transport keeps its round-trip shape.
func DiffTreeRoots(left, right TreeRoot, fetchBatch func(ids []string) (map[string][]byte, error)) (added, removed, modified []string, err error) {
	if left.Root.ID == right.Root.ID {
		return nil, nil, nil, nil
	}
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
			return nil, nil, nil, err
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
			switch c.Type {
			case ChildFile:
				if asAdded {
					added = append(added, path)
				} else {
					removed = append(removed, path)
				}
			case ChildSymlink:
				// Not reported, matching the on-disk diff.
			case ChildDir:
				if c.Node == nil {
					return fmt.Errorf("directory child %q has no node reference", path)
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
				return nil, nil, nil, err
			}
			rc, err := open(p.right)
			if err != nil {
				return nil, nil, nil, err
			}
			i, j := 0, 0
			for i < len(lc) || j < len(rc) {
				switch {
				case j >= len(rc) || (i < len(lc) && lc[i].Name < rc[j].Name):
					if err := oneSided(p.prefix, lc[i], false); err != nil {
						return nil, nil, nil, err
					}
					i++
				case i >= len(lc) || lc[i].Name > rc[j].Name:
					if err := oneSided(p.prefix, rc[j], true); err != nil {
						return nil, nil, nil, err
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
							return nil, nil, nil, fmt.Errorf("directory child %q has no node reference", path)
						}
						nextPairs = append(nextPairs, pair{prefix: path, left: *l.Node, right: *r.Node})
					case l.Type == r.Type:
						if l.Type == ChildFile && l.Hash != r.Hash {
							modified = append(modified, path)
						}
					default:
						// Type changed: whatever was there is gone, the new thing appeared.
						if err := oneSided(p.prefix, l, false); err != nil {
							return nil, nil, nil, err
						}
						if err := oneSided(p.prefix, r, true); err != nil {
							return nil, nil, nil, err
						}
					}
				}
			}
		}
		for _, e := range enums {
			children, err := open(e.node)
			if err != nil {
				return nil, nil, nil, err
			}
			for _, c := range children {
				if err := oneSided(e.prefix, c, e.asAdded); err != nil {
					return nil, nil, nil, err
				}
			}
		}
		pairs, enums = nextPairs, nextEnums
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(modified)
	return added, removed, modified, nil
}
