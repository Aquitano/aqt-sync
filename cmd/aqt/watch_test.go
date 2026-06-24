package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// fakeWatcher wires a watcher to test-controlled state: sig is the current tree
// fingerprint, busy is the git-guard answer, and syncs counts committed syncs.
type fakeWatcher struct {
	sig   string
	busy  bool
	syncs int
}

func newFakeWatcher(f *fakeWatcher) *watcher {
	return &watcher{
		root:    "/root",
		scan:    func() (string, error) { return f.sig, nil },
		gitBusy: func() (bool, string, error) { return f.busy, "/root/sub", nil },
		sync:    func() error { f.syncs++; return nil },
		logf:    func(string, ...any) {},
	}
}

func TestWatcherSyncsOnceWhenQuiet(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	var st watchState

	w.step(&st) // prime
	if f.syncs != 0 {
		t.Fatalf("priming must not sync; syncs=%d", f.syncs)
	}
	w.step(&st) // quiet tick -> the initial convergence sync
	if f.syncs != 1 {
		t.Fatalf("a quiet tick must sync once; syncs=%d", f.syncs)
	}
	w.step(&st) // still quiet -> nothing
	if f.syncs != 1 {
		t.Fatalf("an unchanged tree must not re-sync; syncs=%d", f.syncs)
	}
}

// A change is not pushed on the tick it appears; it waits one quiet tick (the
// debounce) before syncing.
func TestWatcherDebouncesChange(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	var st watchState

	w.step(&st) // prime
	w.step(&st) // initial sync
	if f.syncs != 1 {
		t.Fatalf("setup: syncs=%d", f.syncs)
	}

	f.sig = "b"
	w.step(&st) // change observed
	if f.syncs != 1 {
		t.Fatalf("a change must not sync on the tick it appears; syncs=%d", f.syncs)
	}
	w.step(&st) // tree quiet -> sync
	if f.syncs != 2 {
		t.Fatalf("a settled change must sync; syncs=%d", f.syncs)
	}
}

// While any sub-repo holds a git lock, the sync is held back and retried until
// git goes idle.
func TestWatcherDefersWhileGitBusy(t *testing.T) {
	f := &fakeWatcher{sig: "a", busy: true}
	w := newFakeWatcher(f)
	var st watchState

	w.step(&st) // prime
	w.step(&st) // would sync, but git is busy
	w.step(&st) // still busy
	if f.syncs != 0 {
		t.Fatalf("must not sync while git is busy; syncs=%d", f.syncs)
	}

	f.busy = false
	w.step(&st) // git idle -> the held-back sync runs
	if f.syncs != 1 {
		t.Fatalf("must sync once git is idle; syncs=%d", f.syncs)
	}
}

// TestWatchGuardGatesRealSync drives the watcher with the real scan/gitBusy/sync
// against the live server: a push must be held back while a sub-repo holds a git
// lock, then go through once the lock clears.
func TestWatchGuardGatesRealSync(t *testing.T) {
	h := newE2E(t)
	root := t.TempDir()
	h.init(root)
	writeTree(t, root, "secret.env", "API_KEY=1")

	// A repo mid-commit: .git is ignored by the starter .aqtignore, so its churn
	// never moves the signature, but the lock must still gate the push.
	mkGitDir(t, root, "index.lock")

	f := &fakeWatcher{} // reused only for the sync counter
	w := &watcher{
		root:    root,
		scan:    func() (string, error) { return scanSignature(root) },
		gitBusy: func() (bool, string, error) { return gitBusy(root) },
		sync:    func() error { f.syncs++; return runSync(root, syncOptions{}) },
		logf:    func(string, ...any) {},
	}
	tracked := func(path string) bool {
		t.Helper()
		base, err := loadBase(root)
		if err != nil {
			t.Fatal(err)
		}
		_, ok := base.Lookup(path)
		return ok
	}

	var st watchState
	w.step(&st) // prime
	w.step(&st) // would sync, but git is locked
	if f.syncs != 0 {
		t.Fatalf("a locked sub-repo must hold back the sync; syncs=%d", f.syncs)
	}
	if tracked("secret.env") {
		t.Fatal("secret.env must not be pushed while git is locked")
	}

	if err := os.Remove(filepath.Join(root, ".git", "index.lock")); err != nil {
		t.Fatal(err)
	}
	w.step(&st) // git idle -> the held-back push runs
	if f.syncs != 1 {
		t.Fatalf("the push must run once git is idle; syncs=%d", f.syncs)
	}
	if !tracked("secret.env") {
		t.Fatal("secret.env must be pushed once git is idle")
	}
}

// A file edited *during* a (slow) sync must not be baselined as already synced;
// it has to stay pending and sync again. This is the rebaseline data-loss guard.
func TestWatcherKeepsEditMadeDuringSync(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	first := true
	w.sync = func() error {
		f.syncs++
		if first { // an edit lands while the sync is running
			f.sig = "b"
			first = false
		}
		return nil
	}
	var st watchState

	w.step(&st) // prime
	w.step(&st) // sync #1; tree changes to "b" mid-sync
	if f.syncs != 1 {
		t.Fatalf("syncs=%d", f.syncs)
	}
	if !st.pending {
		t.Fatal("an edit made during the sync was dropped (pending cleared)")
	}
	w.step(&st) // tree quiet at "b" -> the edit is synced
	if f.syncs != 2 {
		t.Fatalf("concurrent edit was not synced; syncs=%d", f.syncs)
	}
}

func TestWatcherRunExitsOnCancel(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, ticks) }()

	ticks <- time.Time{} // prime ran before the first receive; this drives the sync
	ticks <- time.Time{} // drain: guarantees the previous tick was fully processed
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error on clean cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not exit after cancel")
	}
	if f.syncs == 0 {
		t.Fatal("expected at least one sync before cancel")
	}
}

// A session that can no longer be unlocked is fatal: the loop must stop rather
// than retry an impossible unlock forever (the detached-daemon wedge).
func TestWatcherRunStopsOnFatalSync(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	w.sync = func() error { return errSessionRequired }
	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, ticks) }()

	ticks <- time.Time{} // initial sync attempt -> fatal
	select {
	case err := <-done:
		if !errors.Is(err, errSessionRequired) {
			t.Fatalf("want errSessionRequired, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop on a fatal session error")
	}
}

func TestResolveInterval(t *testing.T) {
	cases := []struct {
		name    string
		opts    watchOptions
		wc      syncengine.WatchConfig
		want    time.Duration
		wantErr bool
	}{
		{"flag overrides config", watchOptions{interval: 5 * time.Second, intervalSet: true}, syncengine.WatchConfig{Interval: "1m"}, 5 * time.Second, false},
		{"config when no flag", watchOptions{}, syncengine.WatchConfig{Interval: "10s"}, 10 * time.Second, false},
		{"default when neither", watchOptions{}, syncengine.WatchConfig{}, defaultInterval, false},
		{"nonpositive flag falls back", watchOptions{interval: 0, intervalSet: true}, syncengine.WatchConfig{}, defaultInterval, false},
		{"bad config value errors", watchOptions{}, syncengine.WatchConfig{Interval: "nope"}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveInterval(c.opts, c.wc)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestWaitGitIdle(t *testing.T) {
	root := t.TempDir()
	mkGitDir(t, root, "index.lock")
	if waitGitIdle(root, 30*time.Millisecond, 5*time.Millisecond) {
		t.Fatal("waitGitIdle must time out while a lock is held")
	}
	if err := os.Remove(filepath.Join(root, ".git", "index.lock")); err != nil {
		t.Fatal(err)
	}
	if !waitGitIdle(root, 30*time.Millisecond, 5*time.Millisecond) {
		t.Fatal("waitGitIdle must return true once the lock clears")
	}
}

// gitGuard disabled in .aqtconfig lets --once sync even with a lock present.
func TestWatchOnceGuardOffSyncsDespiteLock(t *testing.T) {
	h := newE2E(t)
	root := t.TempDir()
	h.init(root)
	writeTree(t, root, "secret.env", "API_KEY=1")
	mkGitDir(t, root, "index.lock")

	if err := runWatchOnce(root, 10*time.Millisecond, false); err != nil {
		t.Fatalf("runWatchOnce(guard off): %v", err)
	}
	base, err := loadBase(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.Lookup("secret.env"); !ok {
		t.Fatal("with gitGuard off, --once must push despite the lock")
	}
}

func TestScanSignatureDetectsChanges(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sig := func() string {
		t.Helper()
		s, err := scanSignature(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	write("a.txt", "hello")
	base := sig()
	if base != sig() {
		t.Fatal("an unchanged tree must yield a stable signature")
	}

	write("a.txt", "hello world")
	if sig() == base {
		t.Fatal("an edit must change the signature")
	}

	edited := sig()
	write("b.txt", "new")
	if sig() == edited {
		t.Fatal("a new file must change the signature")
	}
}
