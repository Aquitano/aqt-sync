// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	installGitRemoteHelper(t, bin)
	newE2E(t)
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

	// The tag object itself is new even though its peeled commit is already on
	// main. A fresh clone proves the standalone tag push uploaded that object.
	gitRun(t, source, "tag", "-a", "v0", "-m", "version zero", "main")
	gitRun(t, source, "push", "origin", "refs/tags/v0")
	tagCloneParent := t.TempDir()
	gitRun(t, tagCloneParent, "clone", "aqt::brain", "tag-clone")
	tagClone := filepath.Join(tagCloneParent, "tag-clone")
	if got, want := gitOutput(t, tagClone, "rev-parse", "refs/tags/v0^{object}"), gitOutput(t, source, "rev-parse", "refs/tags/v0^{object}"); got != want {
		t.Fatalf("cloned annotated tag = %s, want %s", got, want)
	}
	gitRun(t, tagClone, "fsck", "--full")

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
	installGitRemoteHelper(t, bin)
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

func TestGitRemoteSHA256PushAndClone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	installGitRemoteHelper(t, bin)
	newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("sha256", 64); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	source := t.TempDir()
	gitRun(t, source, "init", "--object-format=sha256", "-b", "main")
	gitRun(t, source, "config", "user.email", "sha256@example.com")
	gitRun(t, source, "config", "user.name", "SHA256 Writer")
	writeTree(t, source, "README.md", "sha256\n")
	gitRun(t, source, "add", "README.md")
	gitRun(t, source, "commit", "-m", "sha256")
	gitRun(t, source, "remote", "add", "origin", "aqt::sha256")
	gitRun(t, source, "push", "origin", "main")

	cloneParent := t.TempDir()
	gitRun(t, cloneParent, "clone", "aqt::sha256", "clone")
	clone := filepath.Join(cloneParent, "clone")
	if got := gitOutput(t, clone, "rev-parse", "--show-object-format"); got != "sha256" {
		t.Fatalf("cloned object format = %q, want sha256", got)
	}
	if got, want := gitOutput(t, clone, "rev-parse", "refs/heads/main"), gitOutput(t, source, "rev-parse", "refs/heads/main"); got != want {
		t.Fatalf("cloned SHA-256 main = %s, want %s", got, want)
	}
	gitRun(t, clone, "fsck", "--full")
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
	installGitRemoteHelper(t, bin)
	var armed, injected atomic.Bool
	var resourcePuts atomic.Int32
	newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if armed.Load() && r.Method == http.MethodPut && r.URL.Path == "/v1/resources" {
			if resourcePuts.Add(1) == 2 && injected.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		pass(w, r)
	})
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
	gitRun(t, source, "branch", "feature")
	gitRun(t, source, "remote", "add", "origin", "aqt::compact")
	gitRun(t, source, "push", "-u", "origin", "main", "feature")

	preexistingParent := t.TempDir()
	gitRun(t, preexistingParent, "clone", "aqt::compact", "preexisting")
	preexisting := filepath.Join(preexistingParent, "preexisting")
	if err := os.WriteFile(filepath.Join(source, "history.txt"), []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, source, "add", "history.txt")
	gitRun(t, source, "commit", "-m", "two")
	armed.Store(true)
	gitRun(t, source, "push", "origin", "main") // reaches threshold and compacts
	if !injected.Load() {
		t.Fatal("compaction retry was not exercised")
	}

	remote := openRemoteForTest(t, "compact")
	if len(remote.root.Bundles) != 1 || !remote.root.Bundles[0].Full || remote.root.Generation != 1 {
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

	gitRun(t, preexisting, "fetch", "origin")
	want := gitOutput(t, source, "rev-parse", "refs/heads/main")
	if got := gitOutput(t, preexisting, "rev-parse", "refs/remotes/origin/main"); got != want {
		t.Fatalf("pre-existing clone fetched %s, want %s", got, want)
	}
	gitRun(t, preexisting, "fetch", "origin") // object-presence checks make this idempotent
	gitMustFail(t, preexisting, "rev-parse", "--verify", "refs/heads/feature")
	if got := gitOutput(t, preexisting, "rev-parse", "refs/remotes/origin/feature"); got == "" {
		t.Fatal("fresh clone is missing the feature remote-tracking ref")
	}
	gitRun(t, preexisting, "branch", "wip") // unrelated local refs must not block or enter compaction
	freshParent := t.TempDir()
	gitRun(t, freshParent, "clone", "aqt::compact", "fresh")
	gitRun(t, filepath.Join(freshParent, "fresh"), "fsck", "--full")

	t.Chdir(preexisting)
	if err := runRepoGC("compact", false); err != nil {
		t.Fatalf("explicit repo gc: %v", err)
	}
	remote = openRemoteForTest(t, "compact")
	if len(remote.root.Bundles) != 1 || !remote.root.Bundles[0].Full || remote.root.Generation != 1 {
		remote.close()
		t.Fatalf("no-op compacted root = bundles %d generation %d", len(remote.root.Bundles), remote.root.Generation)
	}
	if _, exists := remote.root.Refs["refs/heads/wip"]; exists {
		remote.close()
		t.Fatal("local WIP branch leaked into compacted remote refs")
	}
	snapshots, err = remote.client.ListSnapshots(remote.res.ID)
	remote.close()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("no-op gc created snapshots: got %d, want 1", len(snapshots))
	}
	if err := runRepoRemove("compact", true); err != nil {
		t.Fatalf("repo rm: %v", err)
	}
	h := &remoteHelper{remoteName: "origin", rawURL: "compact", errOut: os.Stderr}
	if remote, err := h.openRemote(); err == nil {
		remote.close()
		t.Fatal("deleted git remote is still resolvable")
	}
}

func TestGitRemoteRestorePreCompactionSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	installGitRemoteHelper(t, bin)
	newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := runRepoCreate("restore", 2); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "restore@example.com")
	gitRun(t, source, "config", "user.name", "Restore Writer")
	writeTree(t, source, "history.txt", "one\n")
	gitRun(t, source, "add", "history.txt")
	gitRun(t, source, "commit", "-m", "one")
	gitRun(t, source, "remote", "add", "origin", "aqt::restore")
	gitRun(t, source, "push", "-u", "origin", "main")
	writeTree(t, source, "history.txt", "one\ntwo\n")
	gitRun(t, source, "add", "history.txt")
	gitRun(t, source, "commit", "-m", "two")
	gitRun(t, source, "push", "origin", "main")

	remote := openRemoteForTest(t, "restore")
	snapshots, err := remote.client.ListSnapshots(remote.res.ID)
	remote.close()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || !snapshots[0].Automatic {
		t.Fatalf("pre-compaction snapshots = %+v", snapshots)
	}
	if err := runRepoRestore(snapshots[0].ID, true, false); err != nil {
		t.Fatalf("repo restore: %v", err)
	}
	remote = openRemoteForTest(t, "restore")
	if len(remote.root.Bundles) != 2 || remote.root.Generation != 0 {
		remote.close()
		t.Fatalf("restored root = bundles %d generation %d, want 2/0", len(remote.root.Bundles), remote.root.Generation)
	}
	postRestoreSnapshots, err := remote.client.ListSnapshots(remote.res.ID)
	remote.close()
	if err != nil {
		t.Fatal(err)
	}
	if len(postRestoreSnapshots) != 2 {
		t.Fatalf("restore safety snapshots = %d, want 2", len(postRestoreSnapshots))
	}

	cloneParent := t.TempDir()
	gitRun(t, cloneParent, "clone", "aqt::restore", "clone")
	clone := filepath.Join(cloneParent, "clone")
	if got := readTree(t, clone, "history.txt"); got != "one\ntwo\n" {
		t.Fatalf("restored remote content = %q", got)
	}
	gitRun(t, clone, "fsck", "--full")
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
	installGitRemoteHelper(t, bin)
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
	installGitRemoteHelper(t, bin)
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
	// The orphaned upload is invisible to every root, so a prune reclaims it.
	profile, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.store.BackdatePacksForTest(profile.OwnerHandle, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	objectsBefore := harness.usageObjects()
	if err := runPrune(false, false); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if after := harness.usageObjects(); after >= objectsBefore {
		t.Fatalf("orphan upload was not prune-eligible: %d objects before, %d after", objectsBefore, after)
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
	t.Setenv("GIT_CONFIG_COUNT", "3")
	t.Setenv("GIT_CONFIG_KEY_0", "gc.auto")
	t.Setenv("GIT_CONFIG_VALUE_0", "0")
	t.Setenv("GIT_CONFIG_KEY_1", "maintenance.auto")
	t.Setenv("GIT_CONFIG_VALUE_1", "false")
	// Git for Windows defaults core.autocrlf to true, which would rewrite the LF
	// these tests write into CRLF on checkout and break byte comparisons against
	// the working tree.
	t.Setenv("GIT_CONFIG_KEY_2", "core.autocrlf")
	t.Setenv("GIT_CONFIG_VALUE_2", "false")
}

// installGitRemoteHelper wires Git up the way an install does: one aqt binary and
// the git-remote-aqt link `aqt git setup` creates beside it.
func installGitRemoteHelper(t *testing.T, bin string) {
	t.Helper()
	src, err := sharedAqtBinary()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, filepath.Base(src))
	if _, err := linkHelper(src, exe); err != nil {
		t.Fatalf("install aqt: %v", err)
	}
	if _, err := linkHelper(exe, filepath.Join(bin, helperLinkName())); err != nil {
		t.Fatalf("link %s: %v", helperName, err)
	}
}

// The nine tests that install the Git helper all want the same aqt binary. Its
// compile is cached but its link is not, so building per test spent about half a
// second each on Linux and considerably more on Windows. Build it once per package
// run and link that into each test's bin directory.
var (
	sharedAqtOnce sync.Once
	sharedAqtExe  string
	sharedAqtErr  error
	sharedAqtDir  string
)

func sharedAqtBinary() (string, error) {
	sharedAqtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aqt-helper-*")
		if err != nil {
			sharedAqtErr = err
			return
		}
		sharedAqtDir = dir
		// Git discovers the helper by PATH lookup, which on Windows only considers
		// PATHEXT suffixes. An extensionless git-remote-aqt is invisible to it.
		exe := filepath.Join(dir, "aqt")
		if runtime.GOOS == "windows" {
			exe += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", exe, ".")
		cmd.Dir = "."
		if data, err := cmd.CombinedOutput(); err != nil {
			sharedAqtErr = fmt.Errorf("build aqt: %v\n%s", err, data)
			return
		}
		sharedAqtExe = exe
	})
	return sharedAqtExe, sharedAqtErr
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

// Each compaction anchors a pre-compaction checkpoint, and an anchor is exempt from
// every retention path — so a checkpoint the next compaction does not release pins a
// full copy of the repository forever. Successive compactions must converge on one.
func TestGitRemoteCompactionReleasesOldCheckpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries and runs Git end to end")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	configureGitTestEnv(t)
	bin := t.TempDir()
	installGitRemoteHelper(t, bin)
	newE2E(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runRepoCreate("repeat", 2); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	source := t.TempDir()
	gitRun(t, source, "init", "-b", "main")
	gitRun(t, source, "config", "user.email", "e2e@example.com")
	gitRun(t, source, "config", "user.name", "AQT E2E")
	gitRun(t, source, "remote", "add", "origin", "aqt::repeat")

	// A user checkpoint is anchored too. Releasing one would hand a snapshot the user
	// explicitly pinned back to retention, so the sweep must leave it alone.
	commit := func(body string) {
		if err := os.WriteFile(filepath.Join(source, "f.txt"), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRun(t, source, "add", "f.txt")
		gitRun(t, source, "commit", "-m", body)
		gitRun(t, source, "push", "origin", "main")
	}
	commit("one")

	remote := openRemoteForTest(t, "repeat")
	resourceID, cl := remote.res.ID, remote.client
	remote.close()
	manual, err := cl.CreateSnapshot(resourceID, nil, true)
	if err != nil {
		t.Fatalf("create manual checkpoint: %v", err)
	}

	// compactAt is 2, so every push after the first compacts the chain again.
	for _, body := range []string{"two", "three", "four", "five"} {
		commit(body)
	}

	snaps, err := cl.ListSnapshots(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	var automatic, manualAnchored int
	for _, snap := range snaps {
		switch {
		case snap.ID == manual.ID:
			if !snap.Anchored {
				t.Errorf("compaction released the user's checkpoint %s", snap.ID)
			}
			manualAnchored++
		case snap.Automatic && snap.Anchored:
			automatic++
		}
	}
	if automatic != 1 {
		t.Errorf("anchored pre-compaction checkpoints = %d, want 1 (of %d snapshots)", automatic, len(snaps))
	}
	if manualAnchored != 1 {
		t.Errorf("user checkpoint survived = %d, want 1", manualAnchored)
	}

	// The surviving checkpoint must still be a usable rollback.
	remote = openRemoteForTest(t, "repeat")
	generation := remote.root.Generation
	remote.close()
	for _, snap := range snaps {
		if snap.Automatic && snap.Anchored {
			if err := runRepoRestore(snap.ID, true, false); err != nil {
				t.Fatalf("restore from surviving checkpoint: %v", err)
			}
		}
	}
	remote = openRemoteForTest(t, "repeat")
	restored := remote.root.Generation
	remote.close()
	if restored >= generation {
		t.Errorf("restore did not roll the chain back: generation %d, was %d", restored, generation)
	}
}
