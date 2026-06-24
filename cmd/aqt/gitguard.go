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
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
				if gitDirBusy(path) {
					repoDir = filepath.Dir(path)
					return errStopWalk
				}
				return filepath.SkipDir
			}
			return nil
		}
		// A .git entry that is not a directory is either a symlink to the real git
		// dir or a pointer file ("gitdir: <path>") for submodules/worktrees.
		if d.Name() == ".git" {
			if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
				if gitDirBusy(path) {
					repoDir = filepath.Dir(path)
					return errStopWalk
				}
				return nil
			}
			if gitDir, ok := resolveGitFile(path); ok && gitDirBusy(gitDir) {
				repoDir = filepath.Dir(path)
				return errStopWalk
			}
		}
		return nil
	})
	if errors.Is(walkErr, errStopWalk) {
		return true, repoDir, nil
	}
	return false, "", walkErr
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
