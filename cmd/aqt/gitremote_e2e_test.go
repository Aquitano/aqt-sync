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

	"github.com/aquitano/aqt-sync/internal/api"
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
