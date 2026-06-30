package syncengine

import (
	"sort"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// DirAction is a planned change to a tracked directory (mode update, empty-dir
// create, or removal). It is kept separate from the file/symlink Action stream so
// the hardened file apply path is untouched; directories are applied in a dedicated
// pass after files.
type DirAction struct {
	Path string
	Kind ActionKind
}

// TreeDiff is the result of a three-way DAG diff: the same file/symlink Action set
// Plan produces, plus directory changes, plus the remote entries the apply needs for
// the paths it touched (an unchanged subtree is never fetched, so its entries never
// appear here — but it also never produces an action that would need them).
type TreeDiff struct {
	Actions    []Action
	DirActions []DirAction
	Remote     map[string]Entry
	RemoteDirs map[string]DirEntry
}

// NodeFetch resolves a directory-node object to its decoded TreeNode. Local and base
// sources are backed by an in-memory registry; the remote source fetches and
// decrypts node objects lazily, so an unchanged subtree never round-trips.
type NodeFetch func(node crypto.Chunk) (*TreeNode, error)

func registryFetch(reg map[string]*TreeNode) NodeFetch {
	return func(node crypto.Chunk) (*TreeNode, error) {
		n, ok := reg[node.ID]
		if !ok {
			return nil, errMissingNode(node.ID)
		}
		return n, nil
	}
}

type errMissingNode string

func (e errMissingNode) Error() string { return "tree node not in registry: " + string(e) }

// DiffManifests builds in-memory DAGs for local and base, then diffs them against a
// remote DAG read lazily via remoteFetch. It is the v2 three-way reconcile: the file
// Action set is identical to Plan(local, base, remote), computed only over the
// subtrees whose hashes differ.
func DiffManifests(local, base Manifest, conv crypto.ConvergenceKey, remoteRoot crypto.Chunk, remoteFetch NodeFetch) (TreeDiff, error) {
	lRoot, lReg, err := buildTreeRegistry(local, conv)
	if err != nil {
		return TreeDiff{}, err
	}
	bRoot, bReg, err := buildTreeRegistry(base, conv)
	if err != nil {
		return TreeDiff{}, err
	}
	return DiffTree(&lRoot, &bRoot, &remoteRoot, registryFetch(lReg), registryFetch(bReg), remoteFetch)
}

// DiffTree walks the local, base, and remote DAGs in lockstep from their root nodes
// (a nil root means that side is absent) and returns the reconciliation. A subtree
// whose local and remote node ids agree is skipped wholesale — never fetched, never
// recursed — which is the lazy-diff win.
func DiffTree(localRoot, baseRoot, remoteRoot *crypto.Chunk, local, base, remote NodeFetch) (TreeDiff, error) {
	w := &treeWalk{
		local:  local,
		base:   base,
		remote: remote,
		out:    TreeDiff{Remote: map[string]Entry{}, RemoteDirs: map[string]DirEntry{}},
	}
	if err := w.walk(localRoot, baseRoot, remoteRoot, ""); err != nil {
		return TreeDiff{}, err
	}
	sort.Slice(w.out.Actions, func(i, j int) bool { return w.out.Actions[i].Path < w.out.Actions[j].Path })
	sort.Slice(w.out.DirActions, func(i, j int) bool { return w.out.DirActions[i].Path < w.out.DirActions[j].Path })
	return w.out, nil
}

type treeWalk struct {
	local, base, remote NodeFetch
	out                 TreeDiff
}

func (w *treeWalk) walk(l, b, r *crypto.Chunk, path string) error {
	// The whole-subtree short-circuit: when local, base, and remote node ids all
	// agree, nothing changed anywhere below here on either side, so there is nothing
	// to transfer and nothing to fetch — the lazy-fetch / CPU win. It must be all
	// three: local==remote alone is not enough, because a path present in base but
	// deleted on both sides is a Conflict in Plan, not a no-op, and only base carries
	// that signal.
	if l != nil && b != nil && r != nil && l.ID == b.ID && b.ID == r.ID {
		return nil
	}

	lc, err := childrenOf(l, w.local)
	if err != nil {
		return err
	}
	bc, err := childrenOf(b, w.base)
	if err != nil {
		return err
	}
	rc, err := childrenOf(r, w.remote)
	if err != nil {
		return err
	}

	for _, name := range unionNames(lc, bc, rc) {
		childPath := joinChild(path, name)
		lch, lok := lc[name]
		bch, bok := bc[name]
		rch, rok := rc[name]

		// File/symlink namespace: a directory child counts as absent here, so a
		// dir<->file type change reconciles as a leaf add/remove exactly as the flat
		// Plan does over the equivalent path set.
		lf, lfok := leafChild(lch, lok)
		bf, bfok := leafChild(bch, bok)
		rf, rfok := leafChild(rch, rok)
		if rfok {
			w.out.Remote[childPath] = childEntry(rf, childPath)
		}
		if a, ok := leafAction(childPath, lf, lfok, bf, bfok, rf, rfok); ok {
			w.out.Actions = append(w.out.Actions, a)
		}

		// Directory namespace: a file/symlink child counts as absent here, so the
		// dir side of a type change still emits delete/download actions for its
		// contents (via the recursion) and its own mode/existence reconciliation.
		ld, ldok := dirChild(lch, lok)
		bd, bdok := dirChild(bch, bok)
		rd, rdok := dirChild(rch, rok)
		if !ldok && !bdok && !rdok {
			continue
		}
		if rdok {
			w.out.RemoteDirs[childPath] = childDir(rd, childPath)
		}
		if a, ok := dirAction(childPath, ld, ldok, bd, bdok, rd, rdok); ok {
			w.out.DirActions = append(w.out.DirActions, a)
		}
		if err := w.walk(nodeRef(ld, ldok), nodeRef(bd, bdok), nodeRef(rd, rdok), childPath); err != nil {
			return err
		}
	}
	return nil
}

func childrenOf(node *crypto.Chunk, fetch NodeFetch) (map[string]TreeChild, error) {
	out := map[string]TreeChild{}
	if node == nil {
		return out, nil
	}
	n, err := fetch(*node)
	if err != nil {
		return nil, err
	}
	for _, c := range n.Children {
		out[c.Name] = c
	}
	return out, nil
}

func unionNames(sets ...map[string]TreeChild) []string {
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

// leafChild returns the child as a file/symlink leaf, treating a directory as absent.
func leafChild(c TreeChild, ok bool) (TreeChild, bool) {
	if !ok || c.Type == ChildDir {
		return TreeChild{}, false
	}
	return c, true
}

// dirChild returns the child as a directory, treating a file/symlink as absent.
func dirChild(c TreeChild, ok bool) (TreeChild, bool) {
	if !ok || c.Type != ChildDir {
		return TreeChild{}, false
	}
	return c, true
}

func nodeRef(c TreeChild, ok bool) *crypto.Chunk {
	if !ok {
		return nil
	}
	return c.Node
}

// leafAction reproduces plan.go's three-way reconciliation for one file/symlink
// path, byte-for-byte: a path changed if its hash or mode differs from base; a
// both-sides change with unequal hashes is a Conflict, equal hashes is a no-op.
func leafAction(path string, l TreeChild, lok bool, b TreeChild, bok bool, r TreeChild, rok bool) (Action, bool) {
	localChanged := leafChanged(l, lok, b, bok)
	remoteChanged := leafChanged(r, rok, b, bok)
	switch {
	case !localChanged && !remoteChanged:
		return Action{}, false
	case localChanged && !remoteChanged:
		if lok {
			return Action{path, Upload}, true
		}
		return Action{path, DeleteRemote}, true
	case remoteChanged && !localChanged:
		if rok {
			return Action{path, Download}, true
		}
		return Action{path, DeleteLocal}, true
	default:
		if lok && rok && l.Hash == r.Hash {
			return Action{}, false // converged to the same content independently
		}
		return Action{path, Conflict}, true
	}
}

func leafChanged(cur TreeChild, curOK bool, base TreeChild, baseOK bool) bool {
	if curOK != baseOK {
		return true
	}
	if !curOK {
		return false
	}
	return cur.Hash != base.Hash || cur.Mode != base.Mode
}

// dirAction reconciles a directory's existence and mode three-way, mirroring
// leafAction's structure. Directory content changes are handled by the recursion,
// not here; this is only the directory node itself.
func dirAction(path string, l TreeChild, lok bool, b TreeChild, bok bool, r TreeChild, rok bool) (DirAction, bool) {
	localChanged := dirChanged(l, lok, b, bok)
	remoteChanged := dirChanged(r, rok, b, bok)
	switch {
	case !localChanged && !remoteChanged:
		return DirAction{}, false
	case localChanged && !remoteChanged:
		if lok {
			return DirAction{path, Upload}, true
		}
		return DirAction{path, DeleteRemote}, true
	case remoteChanged && !localChanged:
		if rok {
			return DirAction{path, Download}, true
		}
		return DirAction{path, DeleteLocal}, true
	default:
		if lok && rok && l.Mode == r.Mode {
			return DirAction{}, false
		}
		return DirAction{path, Conflict}, true
	}
}

func dirChanged(cur TreeChild, curOK bool, base TreeChild, baseOK bool) bool {
	if curOK != baseOK {
		return true
	}
	if !curOK {
		return false
	}
	return cur.Mode != base.Mode
}
