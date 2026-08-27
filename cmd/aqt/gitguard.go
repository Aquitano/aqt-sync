// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// errStopWalk short-circuits the tree walk once a busy repo is found.
var errStopWalk = errors.New("stop")

// gitInProgressMarkers name the sentinels git leaves for an operation that is
// paused mid-flight: a conflicted merge / interrupted rebase / stopped
// cherry-pick or revert releases index.lock when the command *returns*, but
// leaves the working tree half-applied (conflict markers, partial state). That is
// exactly the half-written tree the guard must not push, and there is no lock
// file to catch it — so these are checked explicitly. (Bisect is excluded: it
// leaves a clean checkout between steps and can run for a long time.)
var gitInProgressMarkers = []string{
	"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD",
	"rebase-merge", "rebase-apply", // directories, not *.lock files
}

// gitBusy reports whether any git repository under root is mid-operation, and the
// working-tree path of the first one found. A repo is "busy" when its git
// directory either holds a lock file — git takes index.lock for any command that
// mutates the working tree (commit, checkout, merge, rebase, reset, stash) and a
// top-level *.lock (HEAD.lock, config.lock, packed-refs.lock) for ref/config
// updates — or carries an in-progress-operation marker (see gitInProgressMarkers).
// Pushing then could capture a half-written tree, so the watcher waits.
//
// Both nested .git directories and the .git pointer files that submodules and
// linked worktrees use are resolved. The control directory is skipped; git
// internals are never descended into. The walk is best-effort: a subtree it
// cannot read is skipped rather than aborting the whole scan (an aborted scan
// would otherwise be read by the caller as "nothing busy" and bypass the guard).
func gitBusy(root string) (busy bool, repoDir string, err error) {
	ig, _ := syncengine.LoadIgnore(root) // root .aqtignore rules; nested files are not consulted here
	walkErr := walkGitRepos(root, ig, func(gitPath string) bool {
		gitDir, ok := resolveGitDir(gitPath)
		if !ok || !gitDirBusy(gitDir) {
			return false
		}
		repoDir = filepath.Dir(gitPath)
		return true
	})
	if errors.Is(walkErr, errStopWalk) {
		return true, repoDir, nil
	}
	return false, "", walkErr
}

// walkGitRepos calls visit for every .git entry under root — a git directory, or the
// pointer file a submodule or linked worktree leaves — and stops at the first one visit
// accepts. The control directory is skipped and git internals are never descended into;
// when ig is non-nil, the subtrees it ignores are skipped too.
//
// Best-effort: a subtree that cannot be read is skipped rather than aborting the scan,
// since an aborted scan would be read by a caller as "nothing found" and bypass its guard.
func walkGitRepos(root string, ig *syncengine.Ignore, visit func(gitPath string) bool) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case syncengine.ControlDir:
				return filepath.SkipDir
			case ".git":
				if visit(path) {
					return errStopWalk
				}
				return filepath.SkipDir // never descend into git internals
			}
			// Skip subtrees the sync ignores (node_modules, build output, …): those
			// files are never pushed, so a git op inside one cannot produce the
			// half-written push the guard exists to prevent. .git is handled above, so
			// the default ignore's .git rule does not hide a real busy repo here.
			if ig != nil {
				if rel, relErr := filepath.Rel(root, path); relErr == nil {
					if rel = filepath.ToSlash(rel); rel != "." && ig.Match(rel, true) {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		// A .git entry that is not a directory is either a symlink to the real git
		// dir or a pointer file ("gitdir: <path>") for submodules/worktrees.
		if d.Name() == ".git" && visit(path) {
			return errStopWalk
		}
		return nil
	})
}

// resolveGitDir names the git directory a .git entry points at: the entry itself when it
// is a directory (or a symlink to one), else the target of its "gitdir: <path>" pointer.
func resolveGitDir(gitPath string) (string, bool) {
	if info, err := os.Stat(gitPath); err == nil && info.IsDir() {
		return gitPath, true
	}
	return resolveGitFile(gitPath)
}

// trackedGitBusy reports whether any git repository whose .git is *tracked* (synced
// via a `!.git/` re-include, not ignored) is mid git-operation, plus that repo's
// working-tree path. It is the manual-sync guard's predicate: only a tracked .git can
// be pushed half-written, so a busy repo whose .git is ignored — the default, or a
// nested vendored repo re-ignored under a tracked root — must not defer the sync.
//
// This is deliberately narrower than gitBusy, which the watch daemon uses to defer on
// ANY busy repo (an in-progress merge/rebase leaves a half-written working tree that
// even an ignored-.git repo should not auto-push); the manual guard is scoped to the
// tracked-.git torn-write this addresses. It scans every repo — not just the first —
// so a tracked .git that is not lexically first still arms the guard. Best-effort: an
// unreadable subtree or ignore file yields "not busy" rather than blocking the sync.
func trackedGitBusy(root string) (busy bool, repoDir string) {
	ig, err := syncengine.LoadIgnore(root)
	if err != nil {
		return false, ""
	}
	// gitTracked consults only these root-level rules, and the built-in .git/ rule
	// excludes every .git path — so unless some rule negates, no repository can be
	// tracked and the whole-tree walk below cannot find anything. This runs on
	// every guarded sync, so skipping the walk matters on a large tree.
	if !ig.HasNegation() {
		return false, ""
	}
	walkErr := walkGitRepos(root, ig, func(gitPath string) bool {
		if !gitTracked(ig, root, gitPath) {
			return false
		}
		gitDir, ok := resolveGitDir(gitPath)
		if !ok || !gitDirBusy(gitDir) {
			return false
		}
		repoDir = filepath.Dir(gitPath)
		return true
	})
	return errors.Is(walkErr, errStopWalk), repoDir
}

// gitTracked reports whether the .git entry at gitPath (a working tree's .git dir or
// pointer) is synced rather than ignored, per the tracked-root ignore rules.
func gitTracked(ig *syncengine.Ignore, root, gitPath string) bool {
	rel, err := filepath.Rel(root, gitPath)
	if err != nil {
		return false
	}
	return !ig.Match(filepath.ToSlash(rel), true)
}

// firstGitRepo returns the tracked-tree-relative path of the first git working
// tree found under root ("." for the root itself), and whether one exists. It
// recognizes both a .git directory and the .git pointer files submodules and
// linked worktrees use, skips the control directory, and never descends into a
// git directory's internals. Best-effort: an unreadable subtree is skipped.
func firstGitRepo(root string) (rel string, found bool) {
	// nil ignore: this reports what exists on disk, not what the sync would push, so an
	// ignored subtree still counts.
	walkErr := walkGitRepos(root, nil, func(gitPath string) bool {
		rel = repoRel(root, gitPath)
		return true
	})
	return rel, errors.Is(walkErr, errStopWalk)
}

// repoRel names the working tree holding gitPath, relative to root (POSIX, "."
// for the root itself).
func repoRel(root, gitPath string) string {
	r, err := filepath.Rel(root, filepath.Dir(gitPath))
	if err != nil {
		return "."
	}
	return filepath.ToSlash(r)
}

// gitDirBusy reports whether gitDir shows a running or paused git operation: a
// top-level lock file, or an in-progress-operation marker. Refs locks
// (refs/**/*.lock) are deliberately not scanned — index.lock already covers every
// command that touches the working tree, and ref churn shouldn't defer a sync.
func gitDirBusy(gitDir string) bool {
	entries, err := os.ReadDir(gitDir)
	if err != nil {
		return false
	}
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".lock") {
			return true
		}
		present[e.Name()] = true
	}
	for _, m := range gitInProgressMarkers {
		if present[m] {
			return true
		}
	}
	return false
}

// resolveGitFile reads a `.git` pointer file ("gitdir: <path>") and returns the
// absolute git directory it names, resolving a relative target against the
// pointer's own location.
func resolveGitFile(gitFilePath string) (string, bool) {
	b, err := os.ReadFile(gitFilePath)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "gitdir:"); ok {
			gitDir := strings.TrimSpace(rest)
			if gitDir == "" {
				return "", false
			}
			if !filepath.IsAbs(gitDir) {
				gitDir = filepath.Join(filepath.Dir(gitFilePath), gitDir)
			}
			return gitDir, true
		}
	}
	return "", false
}
