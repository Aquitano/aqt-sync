// SPDX-License-Identifier: AGPL-3.0-or-later

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

// DirAction is a planned change to a tracked directory (mode update, empty-dir create,
// or removal). It is kept separate from the file/symlink Action stream so the hardened
// file apply path is untouched; directories are applied in a dedicated pass after files.
type DirAction struct {
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
			// Deleted on both sides is agreement, not conflict: there is exactly one
			// possible outcome and both sides already reached it. Reporting it as a
			// Conflict wedged every sync with exit 4 after a crash in the PUT->saveBase
			// window, when the push had landed but the base still recorded the path.
			if !lok && !rok {
				break
			}
			// Mode is part of the comparison: hash-identical entries with divergent
			// modes have not converged (entryDiffers counts a mode edit as a change,
			// and PlanDirs compares its whole attribute set the same way).
			if lok && rok && !entryDiffers(l, r) {
				break // converged to the same content independently; nothing to do
			}
			actions = append(actions, Action{p, Conflict})
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	return actions
}

// PlanReconcile reconciles local against remote with no trusted base (e.g.
// base.json is missing or corrupt). Without a base a one-sided difference is
// ambiguous — it could be an add or a delete — so every difference is reported as
// a Conflict for the caller to resolve (review, or --force = local wins) rather
// than silently treated as an add, which would resurrect deletions. Paths that
// already match on both sides need no action.
func PlanReconcile(local, remote Manifest) []Action {
	lp, rp := local.byPath(), remote.byPath()

	paths := map[string]struct{}{}
	for p := range lp {
		paths[p] = struct{}{}
	}
	for p := range rp {
		paths[p] = struct{}{}
	}

	var actions []Action
	for p := range paths {
		l, lok := lp[p]
		r, rok := rp[p]
		if lok && rok && !entryDiffers(l, r) {
			continue // identical on both sides; nothing to reconcile
		}
		actions = append(actions, Action{p, Conflict})
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	return actions
}

// changed reports whether an entry differs from its base (added, removed,
// content-changed, or mode-changed), deferring to entryDiffers so the planner and
// Diff share one definition of a changed entry.
func changed(cur Entry, curOK bool, base Entry, baseOK bool) bool {
	if curOK != baseOK {
		return true
	}
	if !curOK {
		return false
	}
	return entryDiffers(base, cur)
}

// PlanDirs is the directory counterpart of Plan: a three-way reconcile of tracked
// directories keyed by path, where the only synced attribute is the mode (a
// directory has no content). It lets empty directories and directory permission
// changes propagate alongside files. A directory present in base but gone on both
// sides converged (like a file deleted on both sides) and needs no action.
func PlanDirs(local, base, remote Manifest) []DirAction {
	lp, bp, rp := local.dirsByPath(), base.dirsByPath(), remote.dirsByPath()
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

	var actions []DirAction
	for p := range paths {
		l, lok := lp[p]
		b, bok := bp[p]
		r, rok := rp[p]
		localChanged := dirEntryChanged(l, lok, b, bok)
		remoteChanged := dirEntryChanged(r, rok, b, bok)
		switch {
		case !localChanged && !remoteChanged:
		case localChanged && !remoteChanged:
			if lok {
				actions = append(actions, DirAction{p, Upload})
			} else {
				actions = append(actions, DirAction{p, DeleteRemote})
			}
		case remoteChanged && !localChanged:
			if rok {
				actions = append(actions, DirAction{p, Download})
			} else {
				actions = append(actions, DirAction{p, DeleteLocal})
			}
		default:
			if !lok && !rok {
				break // deleted on both sides independently; converged (see Plan)
			}
			if lok && rok && l.Mode == r.Mode {
				break
			}
			actions = append(actions, DirAction{p, Conflict})
		}
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	return actions
}

// PlanDirsReconcile reconciles directories with no trusted base: every difference
// becomes a Conflict, mirroring PlanReconcile for files.
func PlanDirsReconcile(local, remote Manifest) []DirAction {
	lp, rp := local.dirsByPath(), remote.dirsByPath()
	paths := map[string]struct{}{}
	for p := range lp {
		paths[p] = struct{}{}
	}
	for p := range rp {
		paths[p] = struct{}{}
	}
	var actions []DirAction
	for p := range paths {
		l, lok := lp[p]
		r, rok := rp[p]
		if lok && rok && l.Mode == r.Mode {
			continue
		}
		actions = append(actions, DirAction{p, Conflict})
	}
	sort.Slice(actions, func(i, j int) bool { return actions[i].Path < actions[j].Path })
	return actions
}

func dirEntryChanged(cur DirEntry, curOK bool, base DirEntry, baseOK bool) bool {
	if curOK != baseOK {
		return true
	}
	if !curOK {
		return false
	}
	return cur.Mode != base.Mode
}
