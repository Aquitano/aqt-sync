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

// Plan reconciles local and remote against the last-synced base. A path changed
// on both sides is a Conflict unless the two sides have converged.
func Plan(local, base, remote Manifest) []Action {
	return plan(local.ByPath(), base.ByPath(), remote.ByPath(), entryDiffers)
}

// PlanDirs reconciles directory existence and modes separately from file content.
func PlanDirs(local, base, remote Manifest) []Action {
	return plan(local.DirsByPath(), base.DirsByPath(), remote.DirsByPath(), dirDiffers)
}

func plan[T any](local, base, remote map[string]T, differs func(T, T) bool) []Action {
	var actions []Action
	for _, path := range unionPaths(local, base, remote) {
		l, lok := local[path]
		b, bok := base[path]
		r, rok := remote[path]
		localChanged := changed(l, lok, b, bok, differs)
		remoteChanged := changed(r, rok, b, bok, differs)
		var kind ActionKind
		switch {
		case !localChanged && !remoteChanged:
			continue
		case localChanged && !remoteChanged:
			kind = DeleteRemote
			if lok {
				kind = Upload
			}
		case remoteChanged && !localChanged:
			kind = DeleteLocal
			if rok {
				kind = Download
			}
		default:
			// Matching entries or a deletion on both sides need no action. In particular,
			// replaying a committed deletion after a crash must not create a conflict.
			if !changed(l, lok, r, rok, differs) {
				continue
			}
			kind = Conflict
		}
		actions = append(actions, Action{path, kind})
	}
	return actions
}

// PlanReconcile has no trusted base, so every difference is a Conflict. A one-sided
// path could be either an addition or a deletion; choosing would risk resurrecting
// a deleted file or discarding an added one.
func PlanReconcile(local, remote Manifest) []Action {
	return planReconcile(local.ByPath(), remote.ByPath(), entryDiffers)
}

// PlanDirsReconcile is the directory counterpart of PlanReconcile.
func PlanDirsReconcile(local, remote Manifest) []Action {
	return planReconcile(local.DirsByPath(), remote.DirsByPath(), dirDiffers)
}

func planReconcile[T any](local, remote map[string]T, differs func(T, T) bool) []Action {
	var actions []Action
	for _, path := range unionPaths(local, remote) {
		l, lok := local[path]
		r, rok := remote[path]
		if changed(l, lok, r, rok, differs) {
			actions = append(actions, Action{path, Conflict})
		}
	}
	return actions
}

func changed[T any](cur T, curOK bool, base T, baseOK bool, differs func(T, T) bool) bool {
	if curOK != baseOK {
		return true
	}
	return curOK && differs(cur, base)
}

func dirDiffers(a, b DirEntry) bool { return a.Mode != b.Mode }

// unionPaths gives planners a stable traversal order.
func unionPaths[E any](sets ...map[string]E) []string {
	seen := map[string]struct{}{}
	for _, set := range sets {
		for p := range set {
			seen[p] = struct{}{}
		}
	}
	paths := make([]string, 0, len(seen))
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
