// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTreeWatcher(t *testing.T, root string) *TreeWatcher {
	t.Helper()
	w, err := WatchTree(root)
	if err != nil {
		t.Fatalf("WatchTree: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func expectSignal(t *testing.T, w *TreeWatcher, what string) {
	t.Helper()
	select {
	case <-w.Events():
	case <-time.After(3 * time.Second):
		t.Fatalf("no signal for %s", what)
	}
}

func expectQuiet(t *testing.T, w *TreeWatcher, what string) {
	t.Helper()
	select {
	case <-w.Events():
		t.Fatalf("unexpected signal for %s", what)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestTreeWatcherSignalsOnChange(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w := newTreeWatcher(t, root)

	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, w, "a new file in the root")
}

// Churn in an ignored subtree (here .git, always ignored) must produce no signal:
// the subtree is never watched, so a busy repo cannot wake the daemon.
func TestTreeWatcherIgnoresIgnoredSubtree(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".aqtignore"), []byte("build/\n*.log\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".git", "build"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w := newTreeWatcher(t, root)

	if err := os.WriteFile(filepath.Join(root, ".git", "index"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build", "out"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectQuiet(t, w, "churn in ignored subtrees")

	// A file ignored by a rule in a *watched* dir is filtered at event time.
	if err := os.WriteFile(filepath.Join(root, "noise.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectQuiet(t, w, "an ignored file in a watched dir")

	if err := os.WriteFile(filepath.Join(root, "kept.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, w, "a tracked file next to the ignored churn")
}

// A directory created while watching must itself be watched, so edits inside it
// keep signaling without waiting for the safety rescan.
func TestTreeWatcherFollowsNewSubdir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	w := newTreeWatcher(t, root)

	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, w, "a new directory") // received => the subtree watch is in place

	if err := os.WriteFile(filepath.Join(root, "sub", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectSignal(t, w, "a file inside the new directory")
}
