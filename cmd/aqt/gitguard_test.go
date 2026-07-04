package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mkGitDir creates dir/.git with the given files inside it.
func mkGitDir(t *testing.T, dir string, files ...string) {
	t.Helper()
	gd := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gd, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(gd, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// By default .git is ignored, so a busy repo is not a tracked-.git risk and must not
// arm the guard (a folder that merely contains a repo must not defer on git activity).
func TestTrackedGitBusyDefaultIgnored(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock") // busy, but .git is ignored
	if busy, _ := trackedGitBusy(root); busy {
		t.Fatal("a busy repo whose .git is ignored (default) must not count as tracked-busy")
	}
}

// A `!.git/` re-include tracks the repo, so a busy tracked repo is reported with its
// working-tree path.
func TestTrackedGitBusyTrackedRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\n")
	busy, repo := trackedGitBusy(root)
	if !busy {
		t.Fatal("a busy repo with a tracked .git must be reported")
	}
	if repo != root {
		t.Fatalf("repo = %q, want %q", repo, root)
	}
}

// An idle tracked repo is not busy.
func TestTrackedGitBusyIdleTrackedRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD") // no lock
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\n")
	if busy, _ := trackedGitBusy(root); busy {
		t.Fatal("an idle tracked repo must not be busy")
	}
}

func TestTrackedGitBusyNoRepo(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "data")
	if busy, _ := trackedGitBusy(root); busy {
		t.Fatal("no repo present, nothing to guard")
	}
}

// Regression: a busy nested repo whose .git is re-ignored (under a tracked root) must
// NOT count as busy — its torn .git is never pushed, so it must not defer the sync,
// even though the root .git is tracked. This is the over-defer the split
// hasTrackedGit+gitBusy check produced.
func TestTrackedGitBusyIgnoresNestedIgnoredRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")                                  // tracked root, idle
	mkGitDir(t, filepath.Join(root, "vendored"), "index.lock") // nested, busy
	// Track the root .git but re-ignore the vendored repo's .git.
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\nvendored/.git/\n")
	if busy, repo := trackedGitBusy(root); busy {
		t.Fatalf("a busy nested repo with an ignored .git must not defer the sync (repo=%q)", repo)
	}
}

// Regression: a tracked repo that is not the first one found must still arm the guard.
// The old first-repo-only check missed it and pushed its half-written .git.
func TestTrackedGitBusyScansAllRepos(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, filepath.Join(root, "aaa"), "HEAD")       // lexically first, .git ignored (default)
	mkGitDir(t, filepath.Join(root, "zzz"), "index.lock") // later, busy, tracked below
	writeFile(t, filepath.Join(root, ".aqtignore"), "!zzz/.git/\n")
	busy, repo := trackedGitBusy(root)
	if !busy {
		t.Fatal("a tracked busy repo that is not the first found must still be detected")
	}
	if repo != filepath.Join(root, "zzz") {
		t.Fatalf("repo = %q, want %q", repo, filepath.Join(root, "zzz"))
	}
}

// A tracked .git caught mid-operation defers the push rather than capturing a
// half-written repo. errWatchSkipped maps to the deferred exit code.
func TestGuardTrackedGitDefersOnBusyTrackedRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\n")
	err := guardTrackedGitWait(root, syncOptions{}, 20*time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, errWatchSkipped) {
		t.Fatalf("busy tracked repo: err = %v, want errWatchSkipped", err)
	}
}

// The same busy repo with .git ignored (the default) must NOT defer: an ignored
// .git is never pushed, so its torn state cannot leak into the backup.
func TestGuardTrackedGitProceedsWhenGitIgnored(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	if err := guardTrackedGitWait(root, syncOptions{}, 20*time.Millisecond, 5*time.Millisecond); err != nil {
		t.Fatalf("ignored .git must not gate the sync, got %v", err)
	}
}

// A tracked root repo must not defer just because an unrelated nested repo (whose
// .git is ignored) is busy — the guard is scoped to tracked-.git torn writes.
func TestGuardTrackedGitProceedsWhenOnlyNestedIgnoredRepoBusy(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")                                  // tracked root, idle
	mkGitDir(t, filepath.Join(root, "vendored"), "index.lock") // nested, busy, ignored below
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\nvendored/.git/\n")
	if err := guardTrackedGitWait(root, syncOptions{}, 20*time.Millisecond, 5*time.Millisecond); err != nil {
		t.Fatalf("a busy nested ignored repo must not defer a tracked-root sync, got %v", err)
	}
}

// A pull-only or dry-run pushes nothing, so it is exempt even with a busy tracked repo.
func TestGuardTrackedGitExemptsNonPush(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\n")
	for _, opts := range []syncOptions{{pullOnly: true}, {dryRun: true}} {
		if err := guardTrackedGitWait(root, opts, 20*time.Millisecond, 5*time.Millisecond); err != nil {
			t.Fatalf("non-push sync must be exempt, got %v for %+v", err, opts)
		}
	}
}

// watch.gitGuard=false in .aqtconfig disables the guard for manual sync too.
func TestGuardTrackedGitDisabledByConfig(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	writeFile(t, filepath.Join(root, ".aqtignore"), "!.git/\n")
	writeFile(t, filepath.Join(root, ".aqtconfig"), `{"watch":{"gitGuard":false}}`)
	if err := guardTrackedGitWait(root, syncOptions{}, 20*time.Millisecond, 5*time.Millisecond); err != nil {
		t.Fatalf("gitGuard=false must disable the guard, got %v", err)
	}
}

func TestFirstGitRepoRoot(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")
	rel, ok := firstGitRepo(root)
	if !ok {
		t.Fatal("a repo at the root must be detected")
	}
	if rel != "." {
		t.Fatalf("rel = %q, want \".\"", rel)
	}
}

func TestFirstGitRepoNested(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, filepath.Join(root, "vendored"), "HEAD")
	rel, ok := firstGitRepo(root)
	if !ok {
		t.Fatal("a nested repo must be detected")
	}
	if rel != "vendored" {
		t.Fatalf("rel = %q, want \"vendored\"", rel)
	}
}

func TestFirstGitRepoSubmodulePointer(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../.git/modules/sub\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, ok := firstGitRepo(root)
	if !ok {
		t.Fatal("a submodule (.git pointer file) must be detected")
	}
	if rel != "sub" {
		t.Fatalf("rel = %q, want \"sub\"", rel)
	}
}

func TestFirstGitRepoNoneAndControlDirSkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A .git buried under the control dir must not count.
	mkGitDir(t, filepath.Join(root, ".aqt"), "HEAD")
	if _, ok := firstGitRepo(root); ok {
		t.Fatal("no real repo present; .aqt/.git must be skipped")
	}
}

func TestGitBusyCleanRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "config") // a normal repo with no lock
	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if busy {
		t.Fatal("a repo with no lock files must not be reported busy")
	}
}

func TestGitBusyIndexLock(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "index.lock")
	busy, repo, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("index.lock must mark the repo busy")
	}
	if repo != root {
		t.Fatalf("repo = %q, want %q", repo, root)
	}
}

// A *.lock in .git (HEAD.lock, config.lock, packed-refs.lock) also counts.
func TestGitBusyTopLevelLock(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD", "packed-refs.lock")
	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("a top-level *.lock must mark the repo busy")
	}
}

func TestGitBusyNestedRepo(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")              // clean repo at the root
	sub := filepath.Join(root, "vendored") // a busy nested repo
	mkGitDir(t, sub, "index.lock")

	busy, repo, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("a busy nested repo must be detected")
	}
	if repo != sub {
		t.Fatalf("repo = %q, want %q", repo, sub)
	}
}

// A .lock under refs/ must not count: it does not gate working-tree writes, and
// scanning it would block syncing on unrelated ref churn.
func TestGitBusyIgnoresRefsLock(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")
	refs := filepath.Join(root, ".git", "refs", "heads")
	if err := os.MkdirAll(refs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(refs, "main.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if busy {
		t.Fatal("a refs/**/*.lock must not mark the repo busy")
	}
}

// A submodule's .git is a file pointing at the real git dir; its lock must still
// be found.
func TestGitBusySubmodulePointer(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	realGit := filepath.Join(root, ".git", "modules", "sub")
	if err := os.MkdirAll(realGit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realGit, "index.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Relative gitdir, resolved against the pointer file's directory.
	pointer := "gitdir: ../.git/modules/sub\n"
	if err := os.WriteFile(filepath.Join(sub, ".git"), []byte(pointer), 0o644); err != nil {
		t.Fatal(err)
	}

	busy, repo, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("a busy submodule (via .git pointer file) must be detected")
	}
	if repo != sub {
		t.Fatalf("repo = %q, want %q", repo, sub)
	}
}

func TestGitBusySkipsControlDir(t *testing.T) {
	root := t.TempDir()
	// A stray lock under .aqt/ must never be mistaken for a git lock.
	stray := filepath.Join(root, ".aqt", ".git")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, "index.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if busy {
		t.Fatal(".aqt must be skipped, so a lock under it is ignored")
	}
}

// A conflicted merge / interrupted rebase releases index.lock but leaves the
// working tree half-applied; the marker files must still mark the repo busy.
func TestGitBusyInProgressStates(t *testing.T) {
	for _, marker := range []string{"MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD"} {
		root := t.TempDir()
		mkGitDir(t, root, "HEAD", marker) // marker present, NO *.lock
		busy, _, err := gitBusy(root)
		if err != nil {
			t.Fatal(err)
		}
		if !busy {
			t.Fatalf("%s must mark the repo busy even without index.lock", marker)
		}
	}
}

func TestGitBusyRebaseInProgress(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "HEAD")
	// rebase state is a directory, not a *.lock file.
	if err := os.MkdirAll(filepath.Join(root, ".git", "rebase-merge"), 0o755); err != nil {
		t.Fatal(err)
	}
	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("an in-progress rebase (rebase-merge/) must mark the repo busy")
	}
}

// A repo whose .git is a symlink to the real git directory must still be checked.
func TestGitBusySymlinkedGitDir(t *testing.T) {
	realParent := t.TempDir()
	realGit := filepath.Join(realParent, "g")
	if err := os.MkdirAll(realGit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realGit, "index.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realGit, filepath.Join(repo, ".git")); err != nil {
		t.Fatal(err)
	}
	busy, got, err := gitBusy(root)
	if err != nil {
		t.Fatal(err)
	}
	if !busy {
		t.Fatal("a busy repo behind a symlinked .git must be detected")
	}
	if got != repo {
		t.Fatalf("repo = %q, want %q", got, repo)
	}
}

// One unreadable subdirectory must not abort the whole scan and hide a busy repo
// that sorts after it (an aborted scan would be read as "nothing busy").
func TestGitBusyBestEffortOnUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "aaa-blocked") // sorts before the busy repo
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(blocked, 0o755) })
	mkGitDir(t, filepath.Join(root, "zzz-repo"), "index.lock")

	busy, _, err := gitBusy(root)
	if err != nil {
		t.Fatalf("walk must be best-effort, got error: %v", err)
	}
	if !busy {
		t.Fatal("a busy repo after an unreadable dir must still be found")
	}
}
