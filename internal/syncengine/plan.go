package syncengine

import "sort"

// ActionKind is one reconciliation outcome for a path in a three-way sync.
type ActionKind string

const (
	Upload       ActionKind = "upload"        // changed locally -> push to the remote manifest
	Download     ActionKind = "download"      // changed remotely -> write to disk
	DeleteRemote ActionKind = "delete-remote" // removed locally -> drop from the remote manifest
	DeleteLocal  ActionKind = "delete-local"  // removed remotely -> delete the local file
	Conflict     ActionKind = "conflict"      // changed on both sides since base
)

// Action is a single planned step for one path.
type Action struct {
	Path string
	Kind ActionKind
}

// Plan computes a three-way reconciliation of local and remote against base (the
// last manifest synced from this machine). A path changed on both sides is a
// Conflict and is never auto-resolved — the caller decides (e.g. --force).
func Plan(local, base, remote Manifest) []Action {
	lp, bp, rp := local.byPath(), base.byPath(), remote.byPath()

	paths := map[string]struct{}{}
	for p := range lp {
		paths[p] = struct{}{}
	}
	for p := range rp {
		paths[p] = struct{}{}
	}
	for p := range bp {
		paths[p] = struct{}{}
	}

	var actions []Action
	for p := range paths {
		l, lok := lp[p]
		b, bok := bp[p]
		r, rok := rp[p]

		localChanged := changed(l, lok, b, bok)
		remoteChanged := changed(r, rok, b, bok)

		switch {
		case !localChanged && !remoteChanged:
			// already in sync
		case localChanged && !remoteChanged:
			if lok {
				actions = append(actions, Action{p, Upload})
			} else {
				actions = append(actions, Action{p, DeleteRemote})
			}
		case remoteChanged && !localChanged:
			if rok {
				actions = append(actions, Action{p, Download})
			} else {
				actions = append(actions, Action{p, DeleteLocal})
			}
		default: // both changed
			if lok && rok && l.Hash == r.Hash {
				break // converged to the same content independently; nothing to do
			}
			actions = append(actions, Action{p, Conflict})
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	return actions
}

// changed reports whether an entry differs from its base (added, removed, or
// content-changed).
func changed(cur Entry, curOK bool, base Entry, baseOK bool) bool {
	if curOK != baseOK {
		return true
	}
	if !curOK {
		return false
	}
	return cur.Hash != base.Hash
}
