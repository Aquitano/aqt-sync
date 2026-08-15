// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// ErrPathNotFound marks a subpath that does not exist inside a folder's tree.
var ErrPathNotFound = errors.New("path not found in folder")

// TreeChildren fetches and opens one directory node's children, verifying the
// ciphertext against the node's content address.
func TreeChildren(node crypto.Chunk, fetchBatch func(ids []string) (map[string][]byte, error)) ([]TreeChild, error) {
	cts, err := fetchBatch([]string{node.ID})
	if err != nil {
		return nil, err
	}
	ct, ok := cts[node.ID]
	if !ok {
		return nil, fmt.Errorf("fetch tree node %s: node not returned", node.ID)
	}
	return openNodeChildren(node, ct)
}

// ResolveTreePath descends from root along the slash-separated path, fetching only
// the nodes on that spine — one per path segment — so addressing a single entry in
// a large folder costs O(depth) node fetches and no file content. The empty path
// resolves to a synthetic directory child for the root node. A missing segment
// (including one that descends into a file) reports ErrPathNotFound.
func ResolveTreePath(root TreeRoot, path string, fetchBatch func(ids []string) (map[string][]byte, error)) (TreeChild, error) {
	node := root.Root
	cur := TreeChild{Type: ChildDir, Hash: node.ID, Node: &node}
	path = strings.Trim(path, "/")
	if path == "" {
		return cur, nil
	}
	prefix := ""
	for _, seg := range strings.Split(path, "/") {
		at := joinChild(prefix, seg)
		if cur.Type != ChildDir || cur.Node == nil {
			return TreeChild{}, fmt.Errorf("%q: %w", at, ErrPathNotFound)
		}
		children, err := TreeChildren(*cur.Node, fetchBatch)
		if err != nil {
			return TreeChild{}, err
		}
		found := false
		for _, c := range children {
			if c.Name == seg {
				cur = c
				found = true
				break
			}
		}
		if !found {
			return TreeChild{}, fmt.Errorf("%q: %w", at, ErrPathNotFound)
		}
		prefix = at
	}
	return cur, nil
}

// EntryFromChild converts a file or symlink child into a flat Entry at path,
// resolving an indirect chunk list (ChunksRef) via fetch the same way a full tree
// walk does. A directory child is the caller's branch to handle.
func EntryFromChild(path string, c TreeChild, fetch func(id string) ([]byte, error)) (Entry, error) {
	switch c.Type {
	case ChildSymlink:
		return Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Link: c.Link}, nil
	case ChildFile:
		chunks := c.Chunks
		if len(c.ChunksRef) > 0 {
			var err error
			chunks, err = openChunkList(c.ChunksRef, fetch)
			if err != nil {
				return Entry{}, fmt.Errorf("file %q: %w", path, err)
			}
		}
		return Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Inline: c.Inline, InlineAlg: c.InlineAlg, Chunks: chunks}, nil
	default:
		return Entry{}, fmt.Errorf("child %q is not a file or symlink", path)
	}
}
