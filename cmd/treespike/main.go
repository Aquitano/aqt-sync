//go:build phase4spike

// Command treespike is a throwaway prototype for Phase 4 (Merkle-DAG manifests). It
// is NOT wired into the CLI and is excluded from the default build by the phase4spike
// tag. Run it with:
//
//	go run -tags phase4spike ./cmd/treespike
//
// It demonstrates, entirely in-process (no server, no network):
//   - building a directory-node DAG from an in-memory file list and computing each
//     subtree's content address with the real convergent pipeline (crypto.SealChunk),
//   - that moving a whole directory yields IDENTICAL subtree object ids (dedup),
//   - that an unrelated edit changes only the spine of node ids up to the root (locality),
//   - a recursive three-way diff that skips subtrees whose hashes match.
//
// The real types will live in internal/syncengine; here they are inlined and a file's
// content is sealed as one object instead of CDC-split, to keep the prototype small.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// inlineCutoff mirrors the FastCDC minimum (the flat manifest's inline threshold). A
// file at or below it is stored inline in its parent node; a larger one is sealed as
// a content object through the real convergent pipeline.
const inlineCutoff = 2 << 10

const rootPath = "(root)"

// --- in-memory source tree ---

type file struct {
	path    string // POSIX, relative to the tracked root
	mode    uint32
	content []byte
}

// node is an in-memory directory built from a flat file list, before sealing.
type node struct {
	children map[string]*treeEntry
}

type treeEntry struct {
	mode    uint32
	isDir   bool
	sub     *node  // dir
	content []byte // file plaintext
}

func newNode() *node { return &node{children: map[string]*treeEntry{}} }

// buildTree expands a flat file list into a nested directory tree.
func buildTree(files []file) *node {
	root := newNode()
	for _, f := range files {
		segs := splitPath(f.path)
		cur := root
		for i, seg := range segs {
			last := i == len(segs)-1
			if last {
				cur.children[seg] = &treeEntry{mode: f.mode, content: f.content}
				continue
			}
			e, ok := cur.children[seg]
			if !ok {
				e = &treeEntry{isDir: true, sub: newNode(), mode: 0o755}
				cur.children[seg] = e
			}
			cur = e.sub
		}
	}
	return root
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	if start < len(p) {
		out = append(out, p[start:])
	}
	return out
}

func joinPath(parent, name string) string {
	if parent == rootPath {
		return name
	}
	return parent + "/" + name
}

// --- wire format (the proposed TreeNode / TreeChild, inlined) ---

type wireChild struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"` // "file" | "dir"
	Mode    uint32        `json:"mode"`
	Size    int64         `json:"size,omitempty"`
	Hash    string        `json:"hash"`              // dir: child node id; file: plaintext sha256
	Inline  []byte        `json:"inline,omitempty"`  // file <= inlineCutoff
	Content *crypto.Chunk `json:"content,omitempty"` // file content object (real SealChunk)
	Node    *crypto.Chunk `json:"node,omitempty"`    // dir child node object; Node.ID == Hash
}

type wireNode struct {
	Version  int         `json:"version"`
	Children []wireChild `json:"children"`
}

// sealNode serializes a directory node (children name-sorted), seals it with the real
// convergent pipeline, and returns the node's Chunk — whose ID is the subtree Merkle
// hash. It recurses bottom-up, so a node's bytes embed its whole subtree. reg maps a
// node id back to its node (a shared content-addressed store, so identical subtrees
// occupy one entry); ids maps a human path to its node id, for the demo's reporting.
func sealNode(n *node, conv crypto.ConvergenceKey, path string, reg map[string]*wireNode, ids map[string]string) crypto.Chunk {
	wn := &wireNode{Version: syncengine.FileRootVersion + 1} // v2: bumped from the flat manifest
	for _, name := range sortedKeys(n.children) {
		e := n.children[name]
		wc := wireChild{Name: name, Mode: e.mode}
		if e.isDir {
			child := sealNode(e.sub, conv, joinPath(path, name), reg, ids)
			wc.Type = "dir"
			wc.Hash = child.ID
			c := child
			wc.Node = &c
		} else {
			sum := sha256.Sum256(e.content)
			wc.Type = "file"
			wc.Hash = hex.EncodeToString(sum[:])
			wc.Size = int64(len(e.content))
			if len(e.content) <= inlineCutoff {
				wc.Inline = e.content
			} else {
				_, ch, err := crypto.SealChunk(e.content, conv) // real convergent pipeline for file content
				if err != nil {
					panic(err)
				}
				c := ch
				wc.Content = &c
			}
		}
		wn.Children = append(wn.Children, wc)
	}
	b, err := json.Marshal(wn)
	if err != nil {
		panic(err)
	}
	_, ch, err := crypto.SealChunk(b, conv) // node id == hex(sha256(ciphertext)) == subtree Merkle hash
	if err != nil {
		panic(err)
	}
	reg[ch.ID] = wn
	ids[path] = ch.ID
	return ch
}

func sortedKeys(m map[string]*treeEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- recursive three-way diff over the DAG ---

type diffStats struct {
	fetched int // dir nodes whose children we had to look at (hashes differed)
	skipped int // dir subtrees skipped wholesale because their hashes matched
}

// diffTree walks local/base/remote DAGs in lockstep and returns the same Action set
// Plan would over the equivalent flat manifests, skipping any subtree whose three
// hashes agree. An empty id means the directory is absent on that side.
func diffTree(localID, baseID, remoteID, path string, reg map[string]*wireNode, st *diffStats) []syncengine.Action {
	if localID == baseID && baseID == remoteID {
		fmt.Printf("  skip subtree %-22s (local==base==remote; not fetched)\n", path)
		st.skipped++
		return nil
	}
	st.fetched++
	fmt.Printf("  descend %-24s (hashes differ)\n", path)

	lc := childrenOf(localID, reg)
	bc := childrenOf(baseID, reg)
	rc := childrenOf(remoteID, reg)

	var actions []syncengine.Action
	for _, name := range unionNames(lc, bc, rc) {
		l, lok := lc[name]
		b, bok := bc[name]
		r, rok := rc[name]
		childPath := joinPath(path, name)

		if isDirAll(l, lok, r, rok, b, bok) {
			lh, bh, rh := nodeID(l, lok), nodeID(b, bok), nodeID(r, rok)
			if lh == bh && bh == rh {
				fmt.Printf("  skip subtree %-22s (hashes match on all sides; not fetched)\n", childPath)
				st.skipped++
				continue
			}
			actions = append(actions, diffTree(lh, bh, rh, childPath, reg, st)...)
			continue
		}
		if a, ok := leafAction(childPath, l, lok, b, bok, r, rok); ok {
			fmt.Printf("  leaf %-29s -> %s\n", childPath, a.Kind)
			actions = append(actions, a)
		}
	}
	return actions
}

// leafAction reproduces plan.go's `changed()`: a path changed if its hash differs from
// base; a both-sides change with unequal hashes is a Conflict, equal is a no-op.
func leafAction(path string, l wireChild, lok bool, b wireChild, bok bool, r wireChild, rok bool) (syncengine.Action, bool) {
	lh, bh, rh := hashOf(l, lok), hashOf(b, bok), hashOf(r, rok)
	localChanged := lh != bh
	remoteChanged := rh != bh
	switch {
	case !localChanged && !remoteChanged:
		return syncengine.Action{}, false
	case localChanged && !remoteChanged:
		if lok {
			return syncengine.Action{Path: path, Kind: syncengine.Upload}, true
		}
		return syncengine.Action{Path: path, Kind: syncengine.DeleteRemote}, true
	case remoteChanged && !localChanged:
		if rok {
			return syncengine.Action{Path: path, Kind: syncengine.Download}, true
		}
		return syncengine.Action{Path: path, Kind: syncengine.DeleteLocal}, true
	default:
		if lok && rok && lh == rh {
			return syncengine.Action{}, false // converged independently
		}
		return syncengine.Action{Path: path, Kind: syncengine.Conflict}, true
	}
}

func childrenOf(id string, reg map[string]*wireNode) map[string]wireChild {
	out := map[string]wireChild{}
	if wn, ok := reg[id]; ok && id != "" {
		for _, c := range wn.Children {
			out[c.Name] = c
		}
	}
	return out
}

func unionNames(sets ...map[string]wireChild) []string {
	seen := map[string]struct{}{}
	for _, s := range sets {
		for name := range s {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isDirAll(l wireChild, lok bool, r wireChild, rok bool, b wireChild, bok bool) bool {
	any := false
	for _, p := range []struct {
		c  wireChild
		ok bool
	}{{l, lok}, {r, rok}, {b, bok}} {
		if !p.ok {
			continue
		}
		any = true
		if p.c.Type != "dir" {
			return false
		}
	}
	return any
}

func nodeID(c wireChild, ok bool) string {
	if !ok {
		return ""
	}
	return c.Hash
}

func hashOf(c wireChild, ok bool) string {
	if !ok {
		return ""
	}
	return c.Hash
}

// --- demonstration ---

func main() {
	var mk crypto.MasterKey
	copy(mk[:], []byte("phase4-spike-deterministic-master-key"))
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()

	reg := map[string]*wireNode{} // shared content-addressed node store

	// A small project tree. util.go is padded past inlineCutoff so it exercises the
	// real SealChunk content path, not just the inline path.
	base := []file{
		{"project/main.go", 0o644, []byte("package main\nfunc main() {}\n")},
		{"project/lib/util.go", 0o644, body("util", 4096)},
		{"project/lib/math.go", 0o644, body("math", 4096)},
		{"project/docs/readme.md", 0o644, []byte("# project\n")},
	}

	fmt.Println("=== Phase 4 Merkle-DAG spike (throwaway) ===")

	// --- Demo 1: moving a whole directory dedups its subtree object ids ---
	moved := []file{
		{"project/main.go", 0o644, []byte("package main\nfunc main() {}\n")},
		{"project/vendor/lib/util.go", 0o644, body("util", 4096)},
		{"project/vendor/lib/math.go", 0o644, body("math", 4096)},
		{"project/docs/readme.md", 0o644, []byte("# project\n")},
	}
	idsBase := map[string]string{}
	idsMoved := map[string]string{}
	sealNode(buildTree(base), conv, rootPath, reg, idsBase)
	sealNode(buildTree(moved), conv, rootPath, reg, idsMoved)

	fmt.Println("\n--- Demo 1: move project/lib -> project/vendor/lib (subtree dedup) ---")
	libBefore := idsBase["project/lib"]
	libAfter := idsMoved["project/vendor/lib"]
	fmt.Printf("project/lib node id          : %s\n", short(libBefore))
	fmt.Printf("project/vendor/lib node id   : %s\n", short(libAfter))
	fmt.Printf("=> identical subtree id?     : %v (the moved directory re-uploads ZERO objects)\n", libBefore == libAfter)
	fmt.Printf("=> in shared object store?   : %v (server stores one copy, no new logic)\n", reg[libBefore] != nil && libBefore == libAfter)

	// --- Demo 2: an unrelated edit only changes the spine up to the root ---
	edited := []file{
		{"project/main.go", 0o644, []byte("package main\nfunc main() {}\n")},
		{"project/lib/util.go", 0o644, body("util-EDITED", 4096)}, // only this file changes
		{"project/lib/math.go", 0o644, body("math", 4096)},
		{"project/docs/readme.md", 0o644, []byte("# project\n")},
	}
	idsEdited := map[string]string{}
	sealNode(buildTree(edited), conv, rootPath, reg, idsEdited)

	fmt.Println("\n--- Demo 2: edit project/lib/util.go (locality) ---")
	for _, p := range []string{rootPath, "project", "project/lib", "project/docs"} {
		bID, eID := idsBase[p], idsEdited[p]
		marker := "same"
		if bID != eID {
			marker = "CHANGED"
		}
		fmt.Printf("%-14s %s -> %s  %s\n", p, short(bID), short(eID), marker)
	}
	fmt.Println("=> only the edited file's spine (root, project, project/lib) re-seals; project/docs is untouched")

	// --- Demo 3: recursive three-way diff that skips matching subtrees ---
	fmt.Println("\n--- Demo 3: three-way diff  local=edited  base=original  remote=original ---")
	st := &diffStats{}
	actions := diffTree(idsEdited[rootPath], idsBase[rootPath], idsBase[rootPath], rootPath, reg, st)

	fmt.Println("\nresulting actions (same shape as syncengine.Plan):")
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	if len(actions) == 0 {
		fmt.Println("  (none)")
	}
	for _, a := range actions {
		fmt.Printf("  %-13s %s\n", a.Kind, a.Path)
	}
	fmt.Printf("\ndiff walked %d changed dir node(s), skipped %d unchanged subtree(s)\n", st.fetched, st.skipped)
}

// body returns n deterministic bytes seeded by s, so identical seeds across file lists
// produce byte-identical content (and therefore identical convergent object ids).
func body(s string, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, s...)
		out = append(out, '\n')
	}
	return out[:n]
}

func short(id string) string {
	if len(id) < 12 {
		return id
	}
	return id[:12]
}
