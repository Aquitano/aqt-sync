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

// fakeWaiter is a test-driven tick source: tick() fires one loop iteration and Reset
// records the backoff interval the loop asked for.
type fakeWaiter struct {
	ch     chan time.Time
	resets []time.Duration
}

func newFakeWaiter() *fakeWaiter            { return &fakeWaiter{ch: make(chan time.Time, 1)} }
func (f *fakeWaiter) C() <-chan time.Time   { return f.ch }
func (f *fakeWaiter) Reset(d time.Duration) { f.resets = append(f.resets, d) }
func (f *fakeWaiter) Stop()                 {}
func (f *fakeWaiter) tick()                 { f.ch <- time.Time{} }

func TestBackoffInterval(t *testing.T) {
	base, max := 2*time.Second, 30*time.Second
	cases := []struct {
		idle int
		want time.Duration
	}{
		{0, 2 * time.Second},
		{1, 4 * time.Second},
		{2, 8 * time.Second},
		{3, 16 * time.Second},
		{4, 30 * time.Second}, // 32s clamped to max
		{10, 30 * time.Second},
	}
	for _, c := range cases {
		if got := backoffInterval(base, max, c.idle); got != c.want {
			t.Errorf("backoffInterval(idle=%d) = %s, want %s", c.idle, got, c.want)
		}
	}
	if got := backoffInterval(time.Minute, 30*time.Second, 5); got != time.Minute {
		t.Errorf("base >= max must disable backoff: got %s", got)
	}
}

// The idle streak grows on quiet ticks (so the poll interval backs off) and resets
// to 0 on activity — a sync or a detected change — so a change snaps polling back to
// the base interval.
func TestWatcherIdleStreakBacksOffAndResets(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	var st watchState

	w.step(&st) // prime
	if st.idle != 0 {
		t.Fatalf("prime idle=%d, want 0", st.idle)
	}
	w.step(&st) // quiet -> initial sync (activity)
	if f.syncs != 1 || st.idle != 0 {
		t.Fatalf("after sync syncs=%d idle=%d, want 1/0", f.syncs, st.idle)
	}
	w.step(&st) // quiet, nothing pending -> idle grows
	w.step(&st)
	if st.idle != 2 {
		t.Fatalf("idle=%d after two quiet ticks, want 2", st.idle)
	}
	f.sig = "b"
	w.step(&st) // a change resets the streak
	if st.idle != 0 {
		t.Fatalf("a change must reset the idle streak, got %d", st.idle)
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

// A file event must snap the loop out of its idle backoff: the timer rearms to the
// base interval and the idle streak restarts from zero. Unbuffered channels make
// every handshake deterministic: a send returning means the loop received it, and
// the sequential loop processed everything before it.
func TestWatcherRunEventRearmsToBase(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	wait := &fakeWaiter{ch: make(chan time.Time)}
	events := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	base, max := 2*time.Second, 30*time.Second
	go func() { done <- w.run(ctx, wait, base, max, events) }()

	wait.tick()          // initial sync -> Reset(base)
	wait.tick()          // quiet: idle 1 -> Reset(4s)
	wait.tick()          // quiet: idle 2 -> Reset(8s)
	events <- struct{}{} // event -> Reset(base), idle reset
	events <- struct{}{} // handshake: the first event's Reset is recorded
	wait.tick()          // quiet: idle restarts at 1 -> Reset(4s)
	events <- struct{}{} // handshake: the tick's Reset is recorded
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	r := wait.resets
	if len(r) < 7 {
		t.Fatalf("recorded %d resets, want at least 7: %v", len(r), r)
	}
	if r[3] != 8*time.Second {
		t.Fatalf("backoff before the event = %s, want 8s (resets %v)", r[3], r)
	}
	if r[4] != base {
		t.Fatalf("an event must rearm to base: got %s (resets %v)", r[4], r)
	}
	if r[6] != 4*time.Second {
		t.Fatalf("idle streak must restart after an event: got %s, want 4s (resets %v)", r[6], r)
	}
}

func TestWatcherRunExitsOnCancel(t *testing.T) {
	f := &fakeWatcher{sig: "a"}
	w := newFakeWatcher(f)
	wait := newFakeWaiter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, wait, defaultInterval, maxWatchInterval, nil) }()

	wait.tick() // prime ran before the first receive; this drives the sync
	wait.tick() // drain: guarantees the previous tick was fully processed
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
	wait := newFakeWaiter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.run(ctx, wait, defaultInterval, maxWatchInterval, nil) }()

	wait.tick() // initial sync attempt -> fatal
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
