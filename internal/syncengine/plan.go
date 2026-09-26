// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"path"
	"sort"
)

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

// MarkTypeClashes turns every download that cannot coexist with what the local side
// keeps into a Conflict: a remote file where local keeps a directory or anything
// inside one, and a remote entry or directory beneath a file or symlink local keeps.
// Plan decides each path on its own, so without this both sides land in the merged
// manifest — a file x beside x/y, which no filesystem can hold. The conflict then
// resolves like any other: local keeps the path, and a resolving mode preserves the
// remote side as a conflict copy. Run it before KeepParents, so a directory a kept
// local change needs is not removed by the remote's file replacing it.
func MarkTypeClashes(actions, dirActions []Action, local Manifest) {
	files, dirs := local.ByPath(), local.DirsByPath()
	keptFiles := map[string]bool{}
	keptDirs := map[string]bool{}
	keptUnder := map[string]bool{}
	keep := func(set map[string]bool, p string) {
		set[p] = true
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			keptUnder[dir] = true
		}
	}
	for _, a := range actions {
		if _, ok := files[a.Path]; ok && (a.Kind == Upload || a.Kind == Conflict) {
			keep(keptFiles, a.Path)
		}
	}
	for _, a := range dirActions {
		if _, ok := dirs[a.Path]; ok && (a.Kind == Upload || a.Kind == Conflict) {
			keep(keptDirs, a.Path)
		}
	}
	underKeptFile := func(p string) bool {
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			if keptFiles[dir] {
				return true
			}
		}
		return false
	}
	for i, a := range actions {
		if a.Kind == Download && (keptDirs[a.Path] || keptUnder[a.Path] || underKeptFile(a.Path)) {
			actions[i].Kind = Conflict
		}
	}
	for i, a := range dirActions {
		if a.Kind == Download && (keptFiles[a.Path] || underKeptFile(a.Path)) {
			dirActions[i].Kind = Conflict
		}
	}
}

// KeepParents stops a directory from being deleted while the merge keeps an entry
// inside it. Plan and PlanDirs decide each path on their own, so a file added under
// a directory another device deleted would be pushed without its directory's entry:
// the tree then records that directory with no mode, and every later sync on the
// adding device reports it as a directory conflict. A directory the remote removed
// stays with the local entry when a local change survives inside it, and one removed
// locally stays with the remote entry when a download lands inside it.
func KeepParents(actions, dirActions []Action, local Manifest) {
	keptUnder := map[string]bool{}
	incomingUnder := map[string]bool{}
	mark := func(set map[string]bool, p string) {
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			set[dir] = true
		}
	}
	scan := func(acts []Action, localHas func(string) bool) {
		for _, a := range acts {
			switch {
			case a.Kind == Upload, a.Kind == Conflict && localHas(a.Path):
				mark(keptUnder, a.Path)
			case a.Kind == Download:
				mark(incomingUnder, a.Path)
			}
		}
	}
	files, dirs := local.ByPath(), local.DirsByPath()
	scan(actions, func(p string) bool { _, ok := files[p]; return ok })
	scan(dirActions, func(p string) bool { _, ok := dirs[p]; return ok })
	for i, a := range dirActions {
		switch {
		case a.Kind == DeleteLocal && keptUnder[a.Path]:
			dirActions[i].Kind = Upload
		case a.Kind == DeleteRemote && incomingUnder[a.Path]:
			dirActions[i].Kind = Download
		}
	}
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
