// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Phase 4 Merkle-DAG manifests. A tracked folder is a tree of directory nodes
// rather than one flat entry list: each directory node lists its immediate
// children (name-sorted) and is sealed through the convergent pipeline, so the
// node's content address (crypto.Chunk.ID) is the subtree's Merkle hash. Two
// identical subtrees seal to the same object id and dedup on the server for free;
// a three-way diff skips any subtree whose hashes agree. See
// docs/protocol/folder-sync.md (Merkle DAG of directory nodes).

// TreeManifestVersion is the Merkle-DAG manifest version, bumped from the flat
// manifest's 1 so the format is detectable.
const TreeManifestVersion = 2

// ChildType discriminates a directory child, the way Entry.IsSymlink does for a
// flat entry. Stored as a short self-describing string.
type ChildType string

const (
	ChildFile    ChildType = "file"
	ChildDir     ChildType = "dir"
	ChildSymlink ChildType = "symlink"
)

// TreeChild is one entry inside a directory node: a single path segment plus its
// mode, type, and a type-specific content reference (mirroring how Entry overloads
// Link/Inline/Chunks). Children are name-sorted, so a node's serialization — and
// therefore its content address — is a pure function of the subtree it describes.
type TreeChild struct {
	Name string    `json:"name"` // single path segment, never a slash
	Type ChildType `json:"type"`
	Mode uint32    `json:"mode,omitempty"`
	Size int64     `json:"size,omitempty"`
	// Hash drives change detection and equality, exactly like Entry.Hash: a file's
	// plaintext sha256, a symlink's domain-separated target hash, or for a directory
	// the child node's content address (== the subtree Merkle hash).
	Hash      string         `json:"hash,omitempty"`
	Link      string         `json:"link,omitempty"`      // symlink target
	Inline    []byte         `json:"inline,omitempty"`    // file bytes when Size <= chunker.Min
	InlineAlg string         `json:"inlineAlg,omitempty"` // compression of Inline; empty = raw
	Chunks    []crypto.Chunk `json:"chunks,omitempty"`    // file content objects when larger
	// ChunksRef replaces Chunks for a file whose chunk list is too large to inline:
	// the sealed chunk-list segments that recover it (see chunklist.go). Absent on
	// nodes written before indirection existed, so old nodes still open.
	ChunksRef []crypto.Chunk `json:"chunksRef,omitempty"`
	Node      *crypto.Chunk  `json:"node,omitempty"` // dir: the child node object to fetch+open; Node.ID == Hash
}

// MaxNodeBytes caps one directory node's serialized size. A node seals to a single
// object that must fit one pack (the server caps pack bodies at 32 MiB), and the
// uploader may batch it with up to a pack target of other objects; 24 MiB leaves
// that headroom. With chunk lists indirected, only a directory with an enormous
// number of direct children can hit this.
const MaxNodeBytes = 24 << 20

// TreeNode is a directory: its children, name-sorted. One node seals to exactly one
// convergent object whose id is the subtree Merkle hash.
type TreeNode struct {
	Version  int         `json:"version"`
	Children []TreeChild `json:"children"`
}

// TreeRoot is the tiny resource blob for a DAG folder: a pointer at the root
// directory node's object. It replaces ManifestRoot for v2 folders.
type TreeRoot struct {
	Version int          `json:"version"`
	Root    crypto.Chunk `json:"root"` // Root.ID is the whole-tree hash
}

// SealTreeRoot serializes and encrypts a tree root under the folder content key
// (the resource blob), domain-separated from the flat ManifestRoot's AADBlob and the
// pack root's AADPackRoot. The distinct tag is mandatory, not cosmetic: a TreeRoot
// and a ManifestRoot are byte-compatible JSON under the same key, so without it an
// old client could open a v2 root as an empty manifest and delete the whole tree —
// the same footgun SealPackRoot guards. With it, the cross-open fails the AEAD check.
// The seal also binds the resource id when known (empty on create, before the
// server assigns one).
func SealTreeRoot(r TreeRoot, ck crypto.ContentKey, resourceID string) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.SealBound(b, ck, crypto.AADTreeRoot, resourceID)
}

// OpenTreeRoot decrypts and parses a sealed tree root.
func OpenTreeRoot(blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string) (TreeRoot, error) {
	var r TreeRoot
	plain, err := crypto.OpenBound(blob, ck, crypto.AADTreeRoot, resourceID)
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(plain, &r)
}

// --- building the in-memory tree from a flat manifest ---

type dirBuild struct {
	mode    uint32
	files   map[string]Entry // file/symlink leaves by segment name
	subdirs map[string]*dirBuild
}

func newDirBuild() *dirBuild {
	return &dirBuild{files: map[string]Entry{}, subdirs: map[string]*dirBuild{}}
}

func (d *dirBuild) child(name string) *dirBuild {
	s, ok := d.subdirs[name]
	if !ok {
		s = newDirBuild()
		d.subdirs[name] = s
	}
	return s
}

func splitSegments(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// buildDirTree expands a flat manifest (files/symlinks + tracked directories) into a
// nested directory structure ready to seal bottom-up.
func buildDirTree(m Manifest) *dirBuild {
	root := newDirBuild()
	for _, e := range m.Entries {
		segs := splitSegments(e.Path)
		cur := root
		for _, s := range segs[:len(segs)-1] {
			cur = cur.child(s)
		}
		cur.files[segs[len(segs)-1]] = e
	}
	for _, d := range m.Dirs {
		segs := splitSegments(d.Path)
		cur := root
		for _, s := range segs {
			cur = cur.child(s)
		}
		cur.mode = d.Mode
	}
	return root
}

// sealer seals a dirBuild bottom-up, feeding node ciphertexts to a sink and collecting
// every reachable object id (node ids + file chunk ids) as the resource's GC roots.
type sealer struct {
	conv crypto.ConvergenceKey
	sink ChunkSink
	refs map[string]struct{}
}

func (s *sealer) addRef(id string) { s.refs[id] = struct{}{} }

func (s *sealer) refList() []string {
	out := make([]string, 0, len(s.refs))
	for id := range s.refs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *sealer) sealNode(d *dirBuild, path string) (crypto.Chunk, error) {
	children := make([]TreeChild, 0, len(d.files)+len(d.subdirs))
	for name, e := range d.files {
		tc := TreeChild{Name: name, Mode: e.Mode, Size: e.Size, Hash: e.Hash}
		if e.IsSymlink() {
			tc.Type = ChildSymlink
			tc.Link = e.Link
		} else {
			tc.Type = ChildFile
			switch {
			case len(e.Chunks) > chunkListInlineMax:
				refs, err := sealChunkList(e.Chunks, s.conv, s.sink)
				if err != nil {
					return crypto.Chunk{}, err
				}
				tc.ChunksRef = refs
				for _, seg := range refs {
					s.addRef(seg.ID)
				}
				for _, ch := range e.Chunks {
					s.addRef(ch.ID)
				}
			case len(e.Chunks) > 0:
				tc.Chunks = e.Chunks
				for _, ch := range e.Chunks {
					s.addRef(ch.ID)
				}
			default:
				tc.Inline = e.Inline
				tc.InlineAlg = e.InlineAlg
			}
		}
		children = append(children, tc)
	}
	for name, sub := range d.subdirs {
		ch, err := s.sealNode(sub, joinChild(path, name))
		if err != nil {
			return crypto.Chunk{}, err
		}
		node := ch
		children = append(children, TreeChild{Name: name, Type: ChildDir, Mode: sub.mode, Hash: ch.ID, Node: &node})
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })

	n := TreeNode{Version: TreeManifestVersion, Children: children}
	b, err := json.Marshal(n)
	if err != nil {
		return crypto.Chunk{}, err
	}
	if len(b) > MaxNodeBytes {
		if path == "" {
			path = "."
		}
		return crypto.Chunk{}, fmt.Errorf("directory %q has too much metadata to sync (%d bytes, limit %d): it has too many direct children; split it into subdirectories",
			path, len(b), MaxNodeBytes)
	}
	ct, ch, err := crypto.SealNode(b, s.conv)
	if err != nil {
		return crypto.Chunk{}, err
	}
	s.addRef(ch.ID)
	if err := s.sink.Add(ch, ct); err != nil {
		return crypto.Chunk{}, err
	}
	return ch, nil
}

// SealTree builds a manifest's directory DAG, seals every node through the
// convergent pipeline into sink (so the objects the server lacks can be packed and
// uploaded), and returns the tree root plus the full set of GC roots: every node
// object id unioned with every file-chunk id reachable from the root.
func SealTree(m Manifest, conv crypto.ConvergenceKey, sink ChunkSink) (TreeRoot, []string, error) {
	if sink == nil {
		sink = nopSink{}
	}
	s := &sealer{conv: conv, sink: sink, refs: map[string]struct{}{}}
	root, err := s.sealNode(buildDirTree(m), "")
	if err != nil {
		return TreeRoot{}, nil, err
	}
	return TreeRoot{Version: TreeManifestVersion, Root: root}, s.refList(), nil
}

// ctSink captures each sealed node's ciphertext keyed by its content address. Because
// nodes are content-addressed, the same id always carries the same bytes, so a repeated
// Add is a harmless overwrite.
type ctSink map[string][]byte

func (s ctSink) Add(ch crypto.Chunk, ct []byte) error {
	s[ch.ID] = append([]byte(nil), ct...)
	return nil
}

// SealTreeCiphertexts seals a manifest's directory DAG in memory (no upload) and returns
// every node's ciphertext keyed by its content address. A reconcile uses it to serve any
// remote node the base tree already contains without a server round-trip: because nodes
// are content-addressed, a node id shared with base is byte-identical, so an unchanged
// subtree is reconstructed entirely from memory. Memory is O(number of directory nodes).
func SealTreeCiphertexts(m Manifest, conv crypto.ConvergenceKey) (map[string][]byte, error) {
	sink := ctSink{}
	if _, _, err := SealTree(m, conv, sink); err != nil {
		return nil, err
	}
	return sink, nil
}

// OpenTree reassembles a flat manifest from a DAG, fetching each directory node's
// ciphertext by id via fetch and verifying it on open. It is the full-reassembly
// reader used by clone, snapshot restore/diff, and the no-base reconcile path.
func OpenTree(root TreeRoot, fetch func(id string) ([]byte, error)) (Manifest, error) {
	m := Manifest{Version: root.Version}
	if err := walkTree(root.Root, "", fetch, &m); err != nil {
		return Manifest{}, err
	}
	sortEntries(m.Entries)
	sortDirs(m.Dirs)
	return m, nil
}

// OpenTreeBatched reassembles a flat manifest from a DAG the same way OpenTree does,
// but walks it level by level instead of depth-first: it hands the whole frontier of
// directory-node ids to fetchBatch in one call, so the transport can locate them in a
// single round-trip and range-fetch their packs grouped, rather than paying 2 RTTs per
// node. Node contents are verified against their address exactly as in OpenTree, so the
// result is identical — batching only changes how the ciphertexts are fetched, never
// what is accepted. Used by clone, reconcile, snapshot restore/diff, and find.
func OpenTreeBatched(root TreeRoot, fetchBatch func(ids []string) (map[string][]byte, error)) (Manifest, error) {
	m := Manifest{Version: root.Version}
	// A file whose chunk list is indirected (ChunksRef) needs its list segments fetched
	// by id; adapt the level-batch fetcher to a single-id fetch so an indirect list opens
	// exactly as it does in the depth-first walkTree.
	fetchOne := func(id string) ([]byte, error) {
		got, err := fetchBatch([]string{id})
		if err != nil {
			return nil, err
		}
		b, ok := got[id]
		if !ok {
			return nil, fmt.Errorf("fetch chunk-list object %s: not returned", id)
		}
		return b, nil
	}
	type pending struct {
		node   crypto.Chunk
		prefix string
	}
	frontier := []pending{{node: root.Root, prefix: ""}}
	for len(frontier) > 0 {
		ids := make([]string, len(frontier))
		for i, p := range frontier {
			ids[i] = p.node.ID
		}
		cts, err := fetchBatch(ids)
		if err != nil {
			return Manifest{}, err
		}
		var next []pending
		for _, p := range frontier {
			ct, ok := cts[p.node.ID]
			if !ok {
				return Manifest{}, fmt.Errorf("fetch tree node %s: node not returned", p.node.ID)
			}
			children, err := openNodeChildren(p.node, ct)
			if err != nil {
				return Manifest{}, err
			}
			for _, c := range children {
				path := joinChild(p.prefix, c.Name)
				switch c.Type {
				case ChildFile:
					chunks := c.Chunks
					if len(c.ChunksRef) > 0 {
						chunks, err = openChunkList(c.ChunksRef, fetchOne)
						if err != nil {
							return Manifest{}, fmt.Errorf("file %q: %w", path, err)
						}
					}
					m.Entries = append(m.Entries, Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Inline: c.Inline, InlineAlg: c.InlineAlg, Chunks: chunks})
				case ChildSymlink:
					m.Entries = append(m.Entries, Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Link: c.Link})
				case ChildDir:
					m.Dirs = append(m.Dirs, DirEntry{Path: path, Mode: c.Mode})
					if c.Node == nil {
						return Manifest{}, fmt.Errorf("directory child %q has no node reference", path)
					}
					next = append(next, pending{node: *c.Node, prefix: path})
				default:
					return Manifest{}, fmt.Errorf("unknown child type %q at %q", c.Type, path)
				}
			}
		}
		frontier = next
	}
	sortEntries(m.Entries)
	sortDirs(m.Dirs)
	return m, nil
}

// openNodeChildren decrypts and parses one directory node, verifying its ciphertext
// against the node's content address before trusting the children.
func openNodeChildren(node crypto.Chunk, ct []byte) ([]TreeChild, error) {
	plain, err := crypto.OpenNode(ct, node)
	if err != nil {
		return nil, err
	}
	var n TreeNode
	if err := json.Unmarshal(plain, &n); err != nil {
		return nil, err
	}
	if n.Version > TreeManifestVersion {
		return nil, fmt.Errorf("tree node %s has version %d, newer than this client supports (%d); upgrade aqt", node.ID, n.Version, TreeManifestVersion)
	}
	return n.Children, nil
}

func walkTree(node crypto.Chunk, prefix string, fetch func(id string) ([]byte, error), m *Manifest) error {
	ct, err := fetch(node.ID)
	if err != nil {
		return fmt.Errorf("fetch tree node %s: %w", node.ID, err)
	}
	plain, err := crypto.OpenNode(ct, node)
	if err != nil {
		return err
	}
	var n TreeNode
	if err := json.Unmarshal(plain, &n); err != nil {
		return err
	}
	if n.Version > TreeManifestVersion {
		return fmt.Errorf("tree node %s has version %d, newer than this client supports (%d); upgrade aqt", node.ID, n.Version, TreeManifestVersion)
	}
	for _, c := range n.Children {
		path := joinChild(prefix, c.Name)
		switch c.Type {
		case ChildFile:
			chunks := c.Chunks
			if len(c.ChunksRef) > 0 {
				chunks, err = openChunkList(c.ChunksRef, fetch)
				if err != nil {
					return fmt.Errorf("file %q: %w", path, err)
				}
			}
			m.Entries = append(m.Entries, Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Inline: c.Inline, InlineAlg: c.InlineAlg, Chunks: chunks})
		case ChildSymlink:
			m.Entries = append(m.Entries, Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Link: c.Link})
		case ChildDir:
			m.Dirs = append(m.Dirs, DirEntry{Path: path, Mode: c.Mode})
			if c.Node == nil {
				return fmt.Errorf("directory child %q has no node reference", path)
			}
			if err := walkTree(*c.Node, path, fetch, m); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown child type %q at %q", c.Type, path)
		}
	}
	return nil
}

func joinChild(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}
