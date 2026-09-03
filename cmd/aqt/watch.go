// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

const (
	defaultInterval = 2 * time.Second
	// maxWatchInterval caps the adaptive poll backoff: while a folder stays idle the
	// watcher doubles its interval toward this, so a quiet tree is lstat-walked every
	// ~30s instead of every 2s, cutting the O(tree) background scan. A change
	// snaps it back to the base interval.
	maxWatchInterval = 30 * time.Second
	// watchRescanInterval replaces maxWatchInterval as the idle cap when kernel file
	// events are active: changes arrive as events, so the stat-walk drops to a slow
	// safety-net rescan that catches whatever the events missed (an unwatchable new
	// subtree, a queue overflow, stale ignore rules).
	watchRescanInterval = 5 * time.Minute
	// gitIdleWaitOnce bounds how long `--once` waits for an in-progress git
	// operation before it skips, so a cron run can't block forever on a stale lock.
	gitIdleWaitOnce = 30 * time.Second
	agentPIDFile    = "agent.pid"
	agentLogFile    = "agent.log"
)

// backoffInterval returns the poll interval for a watcher that has seen idleStreak
// consecutive quiet ticks: the base interval while the tree is active, doubling toward
// max as it stays idle. step resets the streak to 0 on any change, snapping the
// interval back to base. A base already >= max disables backoff.
func backoffInterval(base, max time.Duration, idleStreak int) time.Duration {
	if base >= max || idleStreak <= 0 {
		return base
	}
	d := base
	for range idleStreak {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}

// waiter is the watcher loop's tick source, abstracted so tests can drive ticks
// deterministically while the production path uses a resettable timer for the
// adaptive backoff.
type waiter interface {
	C() <-chan time.Time
	Reset(d time.Duration)
	Stop()
}

type realWaiter struct{ t *time.Timer }

func newRealWaiter(d time.Duration) *realWaiter {
	t := time.NewTimer(d)
	t.Stop()
	return &realWaiter{t: t}
}

func (r *realWaiter) C() <-chan time.Time { return r.t.C }

func (r *realWaiter) Reset(d time.Duration) {
	if !r.t.Stop() {
		select {
		case <-r.t.C:
		default:
		}
	}
	r.t.Reset(d)
}

func (r *realWaiter) Stop() { r.t.Stop() }

// errWatchSkipped reports that `--once` declined to sync because git stayed busy
// past the wait cap. It maps to a dedicated exit code so cron can tell "synced"
// from "deferred, retry later".
var errWatchSkipped = errors.New("deferred: a git operation is still in progress; sync skipped (retry later)")

type watchOptions struct {
	daemon      bool
	once        bool
	interval    time.Duration
	intervalSet bool // whether --interval was passed (vs. taken from .aqtconfig/default)
}

func watchCmd() *cobra.Command {
	var opts watchOptions
	cmd := &cobra.Command{
		Use:   "watch [dir]",
		Short: "Watch a tracked folder and sync on change (debounced)",
		Long: "Watch a tracked folder and sync when it changes, debounced by --interval.\n\n" +
			"A sync is held back while any git repository under the folder is mid-operation\n" +
			"(a git lock or an in-progress merge/rebase), so a push never captures a\n" +
			"half-written working tree. Per-folder defaults live in .aqtconfig (watch.interval,\n" +
			"watch.gitGuard); --interval overrides them.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The dispatch below takes --once first, so accepting both would detach
			// nothing and exit after one sync — with -d silently doing nothing.
			if opts.once && opts.daemon {
				return errors.New("--once and -d/--daemon are mutually exclusive: --once syncs once in the foreground, -d watches in the background")
			}
			opts.intervalSet = cmd.Flags().Changed("interval")
			return runWatch(dirArg(args), opts)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&opts.daemon, "daemon", "d", false, "detach and watch in the background")
	f.BoolVar(&opts.once, "once", false, "sync once and exit (cron-friendly)")
	f.DurationVar(&opts.interval, "interval", defaultInterval, "debounce floor between syncs")
	markProgressSupported(cmd) // every sync it runs draws the sync bars
	return cmd
}

func runWatch(dir string, opts watchOptions) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	interval, err := resolveInterval(opts, cfg.Watch)
	if err != nil {
		return err
	}
	gitGuard := cfg.Watch.GitGuardEnabled()
	switch {
	case opts.once:
		return runWatchOnce(root, interval, gitGuard)
	case opts.daemon:
		return startWatchDaemon(root, interval)
	default:
		return runWatchLoop(root, interval, gitGuard)
	}
}

// resolveInterval applies the precedence: explicit --interval > .aqtconfig
// watch.interval > built-in default.
func resolveInterval(opts watchOptions, wc syncengine.WatchConfig) (time.Duration, error) {
	if opts.intervalSet {
		if opts.interval <= 0 {
			return defaultInterval, nil
		}
		return opts.interval, nil
	}
	if wc.Interval != "" {
		d, err := time.ParseDuration(wc.Interval)
		if err != nil {
			return 0, fmt.Errorf("invalid .aqtconfig watch.interval %q: %w", wc.Interval, err)
		}
		if d > 0 {
			return d, nil
		}
	}
	return defaultInterval, nil
}

// runWatchOnce performs a single guarded sync. With the guard on it waits a
// bounded time for any in-progress git operation to finish first; if git is still
// busy past the cap it returns errWatchSkipped rather than push a half-written
// tree (a later run picks the change up).
func runWatchOnce(root string, interval time.Duration, gitGuard bool) error {
	if !gitGuard || waitGitIdle(root, gitIdleWaitOnce, interval) {
		return runSync(root, syncOptions{})
	}
	return errWatchSkipped
}

func waitGitIdle(root string, timeout, poll time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if busy, _, err := gitBusy(root); err != nil || !busy {
			return true // err: can't confirm a lock, so don't block the sync
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(poll)
	}
}

// runWatchLoop runs the foreground watch loop until interrupted. It owns the
// agent pid file (so a second watcher on the same folder is refused and `aqt
// agent` can find this one) and confirms a usable session up front so a detached
// daemon never wedges on an un-promptable passphrase mid-loop.
func runWatchLoop(root string, interval time.Duration, gitGuard bool) error {
	release, err := acquireAgentLock(root)
	if err != nil {
		return err
	}
	defer release()
	// The per-folder lock above says whether this folder has an agent; the global
	// registry is what lets an update started somewhere else see that it does.
	registerWatchAgent(root)
	defer unregisterWatchAgent(root)
	if err := ensureSession(); err != nil {
		return err
	}

	// The root signal context already covers SIGINT/SIGTERM; registering a second
	// handler here would swallow the "second ^C force-kills" escape main arranges.
	ctx := rootCtx

	logger := log.New(os.Stdout, "", log.LstdFlags)
	w := &watcher{
		root:    root,
		scan:    func() (string, error) { return scanSignature(root) },
		gitBusy: gitGuardFunc(root, gitGuard),
		sync:    func() error { return runSync(root, syncOptions{}) },
		logf:    logger.Printf,
	}
	// Prefer kernel file events over the poll walk; the poll survives as a slow
	// safety-net rescan. A tree the OS can't watch (e.g. over the inotify budget)
	// keeps the original polling behavior.
	var events <-chan struct{}
	max := maxWatchInterval
	if tw, err := syncengine.WatchTree(root); err != nil {
		logger.Printf("file events unavailable (%v); polling every %s (backing off to %s while idle)", err, interval, maxWatchInterval)
	} else {
		defer func() { _ = tw.Close() }()
		events = tw.Events()
		max = watchRescanInterval
		logger.Printf("file events active (debounce %s, safety rescan every %s)", interval, watchRescanInterval)
	}
	logger.Printf("watching %s (git-guard %s)", root, onOff(gitGuard))
	wait := newRealWaiter(interval)
	if err := w.run(ctx, wait, interval, max, events); err != nil {
		logger.Printf("stopping: %v", err)
		return err
	}
	logger.Printf("stopped watching %s", root)
	return nil
}

// gitGuardFunc returns the watcher's busy-check: the real git scan, or a constant
// "idle" when the folder disabled the guard in .aqtconfig.
func gitGuardFunc(root string, enabled bool) func() (bool, string, error) {
	if !enabled {
		return func() (bool, string, error) { return false, "", nil }
	}
	return func() (bool, string, error) { return gitBusy(root) }
}

// ensureSession confirms (and, on a terminal, prompts to establish) an unlocked
// session, warming the on-disk cache so a later runSync — including in a detached
// daemon with no tty — can unlock without prompting.
func ensureSession() error {
	prof, err := loadProfile()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	mk.Wipe()
	return nil
}

// watcher decides when to sync. It is driven by a tick source so the loop is
// deterministic to test; scan/gitBusy/sync are injected for the same reason.
type watcher struct {
	root    string
	scan    func() (string, error)       // tree fingerprint for change detection
	gitBusy func() (bool, string, error) // git-lock guard
	sync    func() error                 // one two-way reconcile
	logf    func(format string, args ...any)

	deferred    bool // holding back on a git lock (rate-limits the log)
	failing     bool // last sync failed (rate-limits the log)
	guardBroken bool // git check itself is erroring (rate-limits the log)
}

// watchState is the loop state threaded between ticks, kept separate so a single
// step is testable without running the loop. idle counts consecutive quiet ticks and
// drives the adaptive poll backoff; step resets it to 0 on any activity.
type watchState struct {
	sig     string
	pending bool
	primed  bool
	idle    int
}

// run drives the loop until the context is cancelled, or returns a fatal error
// (e.g. the session can no longer be unlocked) so the caller can stop the agent. After
// each step it rearms wait with the backoff interval for the current idle streak, so a
// settled tree is polled less often while any change snaps the interval back to base.
//
// events, when non-nil, carries kernel file-event signals: each one rearms the timer
// to the base interval so the next scan runs one debounce after the burst, instead of
// waiting out the idle backoff. A nil channel blocks forever, leaving the pure
// polling behavior.
func (w *watcher) run(ctx context.Context, wait waiter, base, max time.Duration, events <-chan struct{}) error {
	defer wait.Stop()
	var st watchState
	if err := w.step(&st); err != nil { // prime the baseline + queue initial sync
		return err
	}
	wait.Reset(backoffInterval(base, max, st.idle))
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-events:
			st.idle = 0
			wait.Reset(base)
		case <-wait.C():
			if err := w.step(&st); err != nil {
				return err
			}
			wait.Reset(backoffInterval(base, max, st.idle))
		}
	}
}

// step advances the loop by one tick: it fingerprints the tree, and once the
// fingerprint has settled (no change since the previous tick) it syncs — unless a
// git operation is in progress, in which case it keeps the work pending and
// retries on the next tick. The one-tick settle is the debounce.
func (w *watcher) step(st *watchState) error {
	sig, err := w.scan()
	if err != nil {
		w.logf("scan failed: %v", err)
		return nil
	}
	if !st.primed {
		st.sig, st.pending, st.primed = sig, true, true
		return nil
	}
	if sig != st.sig {
		if !st.pending {
			w.logf("change detected")
		}
		st.sig, st.pending, st.idle = sig, true, 0
		return nil
	}
	if !st.pending {
		st.idle++ // a quiet tick with nothing to do: let the poll interval back off
		return nil
	}
	synced := st.sig
	ok, fatal := w.trySync()
	if fatal != nil {
		return fatal
	}
	if !ok {
		// Deferred or failed over an unchanged tree: stay pending so the retry
		// happens, but let the interval back off — a standing conflict would
		// otherwise re-run a full failing sync at the base interval forever. Any
		// tree change (e.g. the conflict being resolved) resets the streak above.
		st.idle++
		return nil
	}
	st.idle = 0 // a completed sync is activity; keep polling at the base interval to follow up
	// Rebaseline against a fresh scan, but only declare convergence if the tree
	// still matches what we just synced. An edit that landed *during* the sync (or
	// files pulled from the remote) makes fresh != synced, so keep it pending and
	// sync again — otherwise that edit would be baselined as synced and lost.
	fresh, err := w.scan()
	if err != nil {
		return nil // keep pending; rebaseline next tick (a no-op re-sync is cheap)
	}
	if fresh == synced {
		st.pending = false
	} else {
		st.sig, st.pending = fresh, true
	}
	return nil
}

// trySync runs one sync unless a sub-repo is mid-operation. It returns whether a
// sync committed, plus a fatal error that should stop the watcher entirely
// (currently: the session can no longer be unlocked, which retrying can't fix).
func (w *watcher) trySync() (synced bool, fatal error) {
	if busy, repo, err := w.gitBusy(); err != nil {
		if !w.guardBroken {
			w.logf("git check failed (%v); syncing without the guard", err)
			w.guardBroken = true
		}
	} else {
		w.guardBroken = false
		if busy {
			if !w.deferred {
				w.logf("deferred: git operation in progress in %s "+
					"(resumes when git finishes; remove a stale .git/index.lock if git crashed)", w.repoLabel(repo))
				w.deferred = true
			}
			return false, nil
		}
	}
	if w.deferred {
		w.logf("git idle; resuming")
		w.deferred = false
	}
	if err := w.sync(); err != nil {
		if errors.Is(err, errSessionRequired) {
			return false, fmt.Errorf("%w; run `aqt login`, then restart the watcher", err)
		}
		if !w.failing {
			w.logf("sync failed: %v (will retry)", err)
			w.failing = true
		}
		return false, nil
	}
	if w.failing {
		w.logf("sync recovered")
		w.failing = false
	}
	return true, nil
}

func (w *watcher) repoLabel(repo string) string {
	if rel, err := filepath.Rel(w.root, repo); err == nil {
		if rel == "." {
			return "this folder"
		}
		return rel
	}
	return repo
}

// scanSignature fingerprints the tracked tree (path/size/mtime/mode, no content
// read) for change detection. It reuses the same ignore rules as sync, so churn
// in ignored paths (a .git directory, always ignored) never triggers a sync.
func scanSignature(root string) (string, error) {
	return syncengine.Fingerprint(root)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// --- background agent ---

func acquireAgentLock(root string) (func(), error) {
	path := controlPath(root, agentPIDFile)
	return acquirePIDFile(path, func(pid int) error {
		return fmt.Errorf("a watch agent is already running here (pid %d); stop it with `aqt agent stop`", pid)
	})
}

// startWatchDaemon re-execs this binary as a detached foreground watcher with its
// output redirected to .aqt/agent.log. The session is unlocked here (on this
// terminal) first, so the child inherits a warm cache and never needs a tty. The
// child owns the pid file; we wait for it so a caller who immediately runs `aqt
// agent status` sees a consistent state.
func startWatchDaemon(root string, interval time.Duration) error {
	if pid, ok := readLockPID(controlPath(root, agentPIDFile)); ok && processAlive(pid) {
		return fmt.Errorf("a watch agent is already running here (pid %d)", pid)
	}
	if err := ensureSession(); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(controlPath(root, agentLogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()

	args := []string{"watch", root, "--interval", interval.String()}
	if flagServer != "" {
		args = append(args, "--server", flagServer)
	}
	if flagProfile != "" {
		args = append(args, "--profile", flagProfile)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	detachAgent(cmd) // run the watcher in its own session/group, free of this terminal
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	if !waitForAgent(root, 3*time.Second) {
		return fmt.Errorf("watch agent (pid %d) did not come up; check `aqt agent logs`", pid)
	}
	fmt.Printf("watching %s in background (pid %d)\nlogs: aqt agent logs\n", root, pid)
	return nil
}

// waitForAgent blocks until the child has written a live pid file, or timeout.
func waitForAgent(root string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if pid, ok := readLockPID(controlPath(root, agentPIDFile)); ok && processAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage background watch agents",
	}
	var (
		startOpts  watchOptions
		foreground bool
	)
	start := &cobra.Command{
		Use:   "start [dir]",
		Short: "Start the watch agent for a tracked folder (detached; alias for `aqt watch -d`)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			startOpts.daemon = !foreground
			startOpts.intervalSet = cmd.Flags().Changed("interval")
			return runWatch(dirArg(args), startOpts)
		},
	}
	start.Flags().DurationVar(&startOpts.interval, "interval", defaultInterval, "debounce floor between syncs")
	start.Flags().BoolVar(&foreground, "foreground", false, "stay attached to this terminal instead of detaching")
	markProgressSupported(start) // --foreground runs the same watch loop as `aqt watch`
	cmd.AddCommand(start)
	cmd.AddCommand(
		&cobra.Command{
			Use:   "status [dir]",
			Short: "Show whether a watch agent is running here",
			Args:  cobra.MaximumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runAgentStatus(dirArg(args)) },
		},
		&cobra.Command{
			Use:   "stop [dir]",
			Short: "Stop the background watch agent",
			Args:  cobra.MaximumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runAgentStop(dirArg(args)) },
		},
		&cobra.Command{
			Use:   "logs [dir]",
			Short: "Print the background watch agent's log",
			Args:  cobra.MaximumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runAgentLogs(dirArg(args)) },
		},
	)
	return cmd
}

func runAgentStatus(dir string) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	pid, ok := readLockPID(controlPath(root, agentPIDFile))
	if ok && processAlive(pid) && looksLikeAqtProcess(pid) {
		fmt.Printf("running (pid %d)\nlogs: aqt agent logs\n", pid)
		return nil
	}
	fmt.Println("not running")
	return nil
}

func runAgentStop(dir string) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	path := controlPath(root, agentPIDFile)
	pid, ok := readLockPID(path)
	if !ok || !processAlive(pid) {
		_ = os.Remove(path) // clear a stale pid file if one was left behind
		fmt.Println("no watch agent running")
		return nil
	}
	// Guard against PID recycling: never SIGTERM a process that merely inherited a
	// dead watcher's PID.
	if !looksLikeAqtProcess(pid) {
		return fmt.Errorf("pid %d is not an aqt watcher (likely a recycled PID); refusing to signal it. "+
			"Delete %s if you are sure no agent is running", pid, path)
	}
	if err := terminateAgent(pid); err != nil {
		return fmt.Errorf("signal agent (pid %d): %w", pid, err)
	}
	fmt.Printf("stopped watch agent (pid %d)\n", pid)
	return nil
}

func runAgentLogs(dir string) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	f, err := os.Open(controlPath(root, agentLogFile))
	if os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "no agent log yet")
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(os.Stdout, f)
	return err
}

// looksLikeAqtProcess best-effort verifies that pid is one of our own watchers,
// so `agent stop` never signals an unrelated process that recycled a dead
// watcher's PID. On a system without /proc it can't tell and trusts the pid file.
func looksLikeAqtProcess(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return true // no /proc (e.g. non-Linux), or a benign read race
	}
	comm := strings.TrimSpace(string(b))
	self := filepath.Base(selfExe())
	// /proc/<pid>/comm is truncated to 15 bytes, so also accept a bounded prefix.
	return comm == self || strings.Contains(comm, "aqt") || (len(self) > 15 && strings.HasPrefix(self, comm))
}

func selfExe() string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "aqt"
}
