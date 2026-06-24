package syncengine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFingerprintStableThenDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	fp := func() string {
		t.Helper()
		s, err := Fingerprint(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	base := fp()
	if base != fp() {
		t.Fatal("an unchanged tree must yield a stable fingerprint")
	}

	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if fp() == base {
		t.Fatal("a mode change must move the fingerprint")
	}
}

// .git is ignored by default, so a watcher does not churn on git's internal
// writes (lock files, objects) — which is what makes the git-lock guard useful.
func TestFingerprintIgnoresGitDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tracked.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Fingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}

	git := filepath.Join(dir, ".git")
	if err := os.MkdirAll(git, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(git, "index.lock"), []byte("lock"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after != base {
		t.Fatal(".git churn must not change the fingerprint")
	}
}
