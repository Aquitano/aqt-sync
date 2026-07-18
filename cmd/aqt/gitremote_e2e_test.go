package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func TestGitRemotePushAndClone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	buildTestBinary(t, filepath.Join(bin, "aqt"), ".")
	buildTestBinary(t, filepath.Join(bin, "git-remote-aqt"), "../git-remote-aqt")
	h := newE2E(t)
	_ = h
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runRepoCreate("brain", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "e2e@example.com")
	gitRun(t, source, "config", "user.name", "AQT E2E")
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("encrypted remote\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "README.md")
	gitRun(t, source, "commit", "-m", "initial")
	gitRun(t, source, "remote", "add", "origin", "aqt::brain")
	gitRun(t, source, "push", "-u", "origin", "main")

	cloneParent := t.TempDir()
	gitRun(t, cloneParent, "clone", "aqt::brain", "clone")
	clone := filepath.Join(cloneParent, "clone")
	want := gitOutput(t, source, "rev-parse", "refs/heads/main")
	if got := gitOutput(t, clone, "rev-parse", "refs/heads/main"); got != want {
		t.Fatalf("cloned main = %s, want %s", got, want)
	}
	gitRun(t, clone, "fsck", "--full")

	gitRun(t, source, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(source, "feature.txt"), []byte("feature\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "feature.txt")
	gitRun(t, source, "commit", "-m", "feature")
	gitRun(t, source, "tag", "-a", "v1", "-m", "version one")
	gitRun(t, source, "push", "origin", "feature", "refs/tags/v1")
	gitRun(t, clone, "fetch", "origin")
	if got := gitOutput(t, clone, "rev-parse", "refs/remotes/origin/feature"); got == "" {
		t.Fatal("feature branch was not fetched")
	}
	if got := gitOutput(t, clone, "rev-parse", "refs/tags/v1"); got == "" {
		t.Fatal("tag was not fetched")
	}
	gitRun(t, source, "push", "origin", ":refs/heads/feature", ":refs/tags/v1")
	gitRun(t, clone, "fetch", "--prune", "--prune-tags", "origin")
	gitMustFail(t, clone, "rev-parse", "--verify", "refs/remotes/origin/feature")
	gitMustFail(t, clone, "rev-parse", "--verify", "refs/tags/v1")

	gitRun(t, source, "checkout", "main")
	if err := os.WriteFile(filepath.Join(source, "normal.txt"), []byte("normal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "normal.txt")
	gitRun(t, source, "commit", "-m", "normal update")
	gitRun(t, source, "push", "origin", "main")
	gitRun(t, source, "reset", "--hard", "HEAD~1")
	if err := os.WriteFile(filepath.Join(source, "rewritten.txt"), []byte("rewritten\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "rewritten.txt")
	gitRun(t, source, "commit", "-m", "rewritten update")
	gitRun(t, source, "push", "--force", "origin", "main")
	gitRun(t, clone, "fetch", "origin")
	if got, want := gitOutput(t, clone, "rev-parse", "refs/remotes/origin/main"), gitOutput(t, source, "rev-parse", "refs/heads/main"); got != want {
		t.Fatalf("force-pushed main = %s, want %s", got, want)
	}
	gitRun(t, clone, "fsck", "--full")

	gitRun(t, clone, "config", "user.email", "clone@example.com")
	gitRun(t, clone, "config", "user.name", "AQT Clone")
	if err := os.WriteFile(filepath.Join(clone, "clone.txt"), []byte("clone edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, clone, "add", "clone.txt")
	gitRun(t, clone, "commit", "-m", "clone edit")
	if output := gitMustFail(t, clone, "push", "origin", "main"); !strings.Contains(output, "non-fast-forward") {
		t.Fatalf("non-fast-forward push did not explain rejection:\n%s", output)
	}
	gitRun(t, clone, "pull", "--rebase", "origin", "main")
	gitRun(t, clone, "push", "origin", "main")
	gitRun(t, source, "fetch", "origin")
	if got := gitOutput(t, source, "show", "refs/remotes/origin/main:rewritten.txt"); got != "rewritten" {
		t.Fatalf("force-push content was lost: %q", got)
	}
	if got := gitOutput(t, source, "show", "refs/remotes/origin/main:clone.txt"); got != "clone edit" {
		t.Fatalf("rebased clone content was lost: %q", got)
	}
}

func TestGitRemotePushRetriesVersionConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	buildTestBinary(t, filepath.Join(bin, "aqt"), ".")
	buildTestBinary(t, filepath.Join(bin, "git-remote-aqt"), "../git-remote-aqt")
	var injected atomic.Bool
	newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/resources" && injected.CompareAndSwap(false, true) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(api.ErrorResponse{Error: "injected version conflict", Code: api.ErrCodeVersionConflict})
			return
		}
		pass(w, r)
	})
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("retry", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "e2e@example.com")
	gitRun(t, source, "config", "user.name", "AQT E2E")
	if err := os.WriteFile(filepath.Join(source, "retry.txt"), []byte("retry\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "retry.txt")
	gitRun(t, source, "commit", "-m", "retry push")
	gitRun(t, source, "remote", "add", "origin", "aqt::retry")
	gitRun(t, source, "push", "origin", "main")
	if !injected.Load() {
		t.Fatal("test proxy did not inject the version conflict")
	}
}

func TestGitRemoteCompactionAndExistingClone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	buildTestBinary(t, filepath.Join(bin, "aqt"), ".")
	buildTestBinary(t, filepath.Join(bin, "git-remote-aqt"), "../git-remote-aqt")
	newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("compact", 2); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "e2e@example.com")
	gitRun(t, source, "config", "user.name", "AQT E2E")
	if err := os.WriteFile(filepath.Join(source, "history.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "history.txt")
	gitRun(t, source, "commit", "-m", "one")
	gitRun(t, source, "remote", "add", "origin", "aqt::compact")
	gitRun(t, source, "push", "-u", "origin", "main")

	preexistingParent := t.TempDir()
	gitRun(t, preexistingParent, "clone", "aqt::compact", "preexisting")
	preexisting := filepath.Join(preexistingParent, "preexisting")
	if err := os.WriteFile(filepath.Join(source, "history.txt"), []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "history.txt")
	gitRun(t, source, "commit", "-m", "two")
	gitRun(t, source, "push", "origin", "main") // reaches threshold and compacts

	remote := openRemoteForTest(t, "compact")
	if len(remote.root.Bundles) != 1 || remote.root.Generation != 1 {
		remote.close()
		t.Fatalf("compacted root = bundles %d generation %d", len(remote.root.Bundles), remote.root.Generation)
	}
	snapshots, err := remote.client.ListSnapshots(remote.res.ID)
	remote.close()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || !snapshots[0].Automatic {
		t.Fatalf("pre-compaction snapshots = %+v", snapshots)
	}

	if err := os.RemoveAll(filepath.Join(preexisting, ".git", "aqt")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, preexisting, "fetch", "origin")
	want := gitOutput(t, source, "rev-parse", "refs/heads/main")
	if got := gitOutput(t, preexisting, "rev-parse", "refs/remotes/origin/main"); got != want {
		t.Fatalf("pre-existing clone fetched %s, want %s", got, want)
	}
	freshParent := t.TempDir()
	gitRun(t, freshParent, "clone", "aqt::compact", "fresh")
	gitRun(t, filepath.Join(freshParent, "fresh"), "fsck", "--full")

	oldGeneration := 1
	t.Chdir(source)
	if err := runRepoGC("compact", false); err != nil {
		t.Fatalf("explicit repo gc: %v", err)
	}
	remote = openRemoteForTest(t, "compact")
	if len(remote.root.Bundles) != 1 || remote.root.Generation != oldGeneration+1 {
		remote.close()
		t.Fatalf("explicitly compacted root = bundles %d generation %d", len(remote.root.Bundles), remote.root.Generation)
	}
	remote.close()
	if err := runRepoRemove("compact", true); err != nil {
		t.Fatalf("repo rm: %v", err)
	}
	h := &remoteHelper{remoteName: "origin", rawURL: "compact", errOut: os.Stderr}
	if remote, err := h.openRemote(); err == nil {
		remote.close()
		t.Fatal("deleted git remote is still resolvable")
	}
}

func TestGitRemoteConcurrentPushRace(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	buildTestBinary(t, filepath.Join(bin, "aqt"), ".")
	buildTestBinary(t, filepath.Join(bin, "git-remote-aqt"), "../git-remote-aqt")
	newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("race", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	first := t.TempDir()
	gitRun(t, first, "init", "-b", "main")
	gitRun(t, first, "config", "user.email", "first@example.com")
	gitRun(t, first, "config", "user.name", "First Writer")
	if err := os.WriteFile(filepath.Join(first, "base.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, first, "add", "base.txt")
	gitRun(t, first, "commit", "-m", "base")
	gitRun(t, first, "remote", "add", "origin", "aqt::race")
	gitRun(t, first, "push", "-u", "origin", "main")

	secondParent := t.TempDir()
	gitRun(t, secondParent, "clone", "aqt::race", "second")
	second := filepath.Join(secondParent, "second")
	gitRun(t, second, "config", "user.email", "second@example.com")
	gitRun(t, second, "config", "user.name", "Second Writer")
	if err := os.WriteFile(filepath.Join(first, "first.txt"), []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, first, "add", "first.txt")
	gitRun(t, first, "commit", "-m", "first writer")
	if err := os.WriteFile(filepath.Join(second, "second.txt"), []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, second, "add", "second.txt")
	gitRun(t, second, "commit", "-m", "second writer")

	start := make(chan struct{})
	results := make(chan gitCommandResult, 2)
	for _, dir := range []string{first, second} {
		dir := dir
		go func() {
			<-start
			results <- runGitCommand(dir, "push", "origin", "main")
		}()
	}
	close(start)
	a, b := <-results, <-results
	successes := 0
	if a.err == nil {
		successes++
	}
	if b.err == nil {
		successes++
	}
	if successes != 1 {
		t.Fatalf("concurrent pushes: successes=%d\nfirst: %v\n%s\nsecond: %v\n%s", successes, a.err, a.output, b.err, b.output)
	}
	loserResult := a
	if a.err == nil {
		loserResult = b
	}
	if !strings.Contains(loserResult.output, "non-fast-forward") {
		t.Fatalf("losing push did not report non-fast-forward:\n%s", loserResult.output)
	}
	gitRun(t, loserResult.dir, "pull", "--rebase", "origin", "main")
	gitRun(t, loserResult.dir, "push", "origin", "main")
	gitRun(t, first, "fetch", "origin")
	if got := gitOutput(t, first, "show", "refs/remotes/origin/main:first.txt"); got != "first" {
		t.Fatalf("first writer commit was lost: %q", got)
	}
	if got := gitOutput(t, first, "show", "refs/remotes/origin/main:second.txt"); got != "second" {
		t.Fatalf("second writer commit was lost: %q", got)
	}
}

func TestGitRemoteCrashAfterUploadLeavesRootUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	buildTestBinary(t, filepath.Join(bin, "aqt"), ".")
	buildTestBinary(t, filepath.Join(bin, "git-remote-aqt"), "../git-remote-aqt")
	harness := newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("crash", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "crash@example.com")
	gitRun(t, source, "config", "user.name", "Crash Writer")
	if err := os.WriteFile(filepath.Join(source, "crash.txt"), []byte("survives\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "crash.txt")
	gitRun(t, source, "commit", "-m", "crash boundary")
	gitRun(t, source, "remote", "add", "origin", "aqt::crash")

	t.Setenv("AQT_TEST_GITREMOTE_EXIT_AFTER_UPLOAD", "1")
	gitMustFail(t, source, "push", "origin", "main")
	remote := openRemoteForTest(t, "crash")
	if remote.res.Version != 1 || len(remote.root.Refs) != 0 || len(remote.root.Bundles) != 0 {
		remote.close()
		t.Fatalf("root changed after helper crash: version=%d refs=%v bundles=%d", remote.res.Version, remote.root.Refs, len(remote.root.Bundles))
	}
	remote.close()
	profile, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	removed, removedBytes, err := harness.store.GCPacks(profile.OwnerHandle, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 || removedBytes == 0 {
		t.Fatalf("orphan upload was not GC-eligible: packs=%d bytes=%d", removed, removedBytes)
	}

	t.Setenv("AQT_TEST_GITREMOTE_EXIT_AFTER_UPLOAD", "")
	gitRun(t, source, "push", "origin", "main")
	cloneParent := t.TempDir()
	gitRun(t, cloneParent, "clone", "aqt::crash", "clone")
	gitRun(t, filepath.Join(cloneParent, "clone"), "fsck", "--full")
}

type gitCommandResult struct {
	dir    string
	output string
	err    error
}

func runGitCommand(dir string, args ...string) gitCommandResult {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	data, err := cmd.CombinedOutput()
	return gitCommandResult{dir: dir, output: strings.TrimSpace(string(data)), err: err}
}

func openRemoteForTest(t *testing.T, ref string) *openedGitRemote {
	t.Helper()
	h := &remoteHelper{remoteName: "origin", rawURL: ref, errOut: os.Stderr}
	remote, err := h.openRemote()
	if err != nil {
		t.Fatalf("open remote %s: %v", ref, err)
	}
	return remote
}

func configureGitTestEnv(t *testing.T) {
	t.Helper()
	// Prevent background auto-maintenance racing an immediate fsck over temporary
	// pack names while this test deliberately creates dangling force-push objects.
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "gc.auto")
	t.Setenv("GIT_CONFIG_VALUE_0", "0")
	t.Setenv("GIT_CONFIG_KEY_1", "maintenance.auto")
	t.Setenv("GIT_CONFIG_VALUE_1", "false")
}

func buildTestBinary(t *testing.T, output, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", output, pkg)
	cmd.Dir = "."
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, data)
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = gitOutput(t, dir, args...)
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, data)
	}
	return strings.TrimSpace(string(data))
}

func gitMustFail(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	data, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("git %s unexpectedly succeeded in %s\n%s", strings.Join(args, " "), dir, data)
	}
	return strings.TrimSpace(string(data))
}
