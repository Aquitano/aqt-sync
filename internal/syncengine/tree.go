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
// a three-way diff skips any subtree whose hashes agree. See docs/phase4-merkle-dag.md.

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
	Hash   string         `json:"hash,omitempty"`
	Link   string         `json:"link,omitempty"`   // symlink target
	Inline []byte         `json:"inline,omitempty"` // file bytes when Size <= chunker.Min
	Chunks []crypto.Chunk `json:"chunks,omitempty"` // file content objects when larger
	Node   *crypto.Chunk  `json:"node,omitempty"`   // dir: the child node object to fetch+open; Node.ID == Hash
}

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
func SealTreeRoot(r TreeRoot, ck crypto.ContentKey) (crypto.SealedBlob, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return crypto.SealedBlob{}, err
	}
	return crypto.Seal(b, ck, crypto.AADTreeRoot)
}

// OpenTreeRoot decrypts and parses a sealed tree root.
func OpenTreeRoot(blob crypto.SealedBlob, ck crypto.ContentKey) (TreeRoot, error) {
	var r TreeRoot
	plain, err := crypto.Open(blob, ck, crypto.AADTreeRoot)
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

// sealer seals a dirBuild bottom-up, feeding node ciphertexts to a sink, collecting
// every reachable object id (node ids + file chunk ids) as the resource's GC roots,
// and optionally recording each decoded node in reg for in-memory diffing.
type sealer struct {
	conv crypto.ConvergenceKey
	sink ChunkSink
	refs map[string]struct{}
	reg  map[string]*TreeNode
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

func (s *sealer) sealNode(d *dirBuild) (crypto.Chunk, error) {
	children := make([]TreeChild, 0, len(d.files)+len(d.subdirs))
	for name, e := range d.files {
		tc := TreeChild{Name: name, Mode: e.Mode, Size: e.Size, Hash: e.Hash}
		if e.IsSymlink() {
			tc.Type = ChildSymlink
			tc.Link = e.Link
		} else {
			tc.Type = ChildFile
			if len(e.Chunks) > 0 {
				tc.Chunks = e.Chunks
				for _, ch := range e.Chunks {
					s.addRef(ch.ID)
				}
			} else {
				tc.Inline = e.Inline
			}
		}
		children = append(children, tc)
	}
	for name, sub := range d.subdirs {
		ch, err := s.sealNode(sub)
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
	ct, ch, err := crypto.SealNode(b, s.conv)
	if err != nil {
		return crypto.Chunk{}, err
	}
	s.addRef(ch.ID)
	if s.reg != nil {
		node := n
		s.reg[ch.ID] = &node
	}
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
	root, err := s.sealNode(buildDirTree(m))
	if err != nil {
		return TreeRoot{}, nil, err
	}
	return TreeRoot{Version: TreeManifestVersion, Root: root}, s.refList(), nil
}

// buildTreeRegistry seals a manifest's DAG in memory (no upload) and returns the
// root node plus a registry mapping every node id to its decoded node, so a diff can
// resolve local/base subtrees without any I/O.
func buildTreeRegistry(m Manifest, conv crypto.ConvergenceKey) (crypto.Chunk, map[string]*TreeNode, error) {
	s := &sealer{conv: conv, sink: nopSink{}, refs: map[string]struct{}{}, reg: map[string]*TreeNode{}}
	root, err := s.sealNode(buildDirTree(m))
	return root, s.reg, err
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
	for _, c := range n.Children {
		path := joinChild(prefix, c.Name)
		switch c.Type {
		case ChildFile:
			m.Entries = append(m.Entries, Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Inline: c.Inline, Chunks: c.Chunks})
		case ChildSymlink:
			m.Entries = append(m.Entries, Entry{Path: path, Size: c.Size, Hash: c.Hash, Link: c.Link})
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

func childEntry(c TreeChild, path string) Entry {
	return Entry{Path: path, Mode: c.Mode, Size: c.Size, Hash: c.Hash, Link: c.Link, Inline: c.Inline, Chunks: c.Chunks}
}

func childDir(c TreeChild, path string) DirEntry {
	return DirEntry{Path: path, Mode: c.Mode}
}
