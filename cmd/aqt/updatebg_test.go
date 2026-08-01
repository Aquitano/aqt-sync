package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/update"
)

// withUpdateStore points the policy and agent registry at a temporary directory,
// so no test reads or writes the real user config.
func withUpdateStore(t *testing.T) update.Store {
	t.Helper()
	store := update.Store{Dir: t.TempDir()}
	orig := updateStore
	updateStore = func() (update.Store, error) { return store, nil }
	t.Cleanup(func() { updateStore = orig })
	return store
}

// withTerminal pretends the invocation is a person at a terminal, which is the
// precondition every background check is gated on.
func withTerminal(t *testing.T, yes bool) {
	t.Helper()
	orig := onATerminal
	onATerminal = func() bool { return yes }
	t.Cleanup(func() { onATerminal = orig })
}

func withFlags(t *testing.T, asJSON, quiet bool) {
	t.Helper()
	origJSON, origQuiet := flagJSON, flagQuiet
	flagJSON, flagQuiet = asJSON, quiet
	t.Cleanup(func() { flagJSON, flagQuiet = origJSON, origQuiet })
}

// A background check must only ever run for an interactive person. Everything
// else is a script, a pipe, or a daemon consuming output that never asked for an
// update notice.
func TestBackgroundUpdateSuppression(t *testing.T) {
	root := rootCmd()
	cases := []struct {
		name     string
		command  string
		terminal bool
		asJSON   bool
		quiet    bool
		want     bool
	}{
		{name: "an ordinary command on a terminal", command: "status", terminal: true, want: true},
		{name: "machine-readable output", command: "status", terminal: true, asJSON: true},
		{name: "quiet output", command: "status", terminal: true, quiet: true},
		{name: "a pipe or script", command: "status"},
		// watch and agent are long-lived or detached; a notice would land in a log.
		{name: "the watch command", command: "watch", terminal: true},
		{name: "the agent command", command: "agent", terminal: true},
		// update is already doing this deliberately, and tui owns the screen.
		{name: "the update command", command: "update", terminal: true},
		{name: "the tui command", command: "tui", terminal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTerminal(t, tc.terminal)
			withFlags(t, tc.asJSON, tc.quiet)

			cmd := subcommand(t, root, tc.command)
			if got := backgroundUpdateAllowed(cmd); got != tc.want {
				t.Fatalf("backgroundUpdateAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// Subcommands inherit their parent's suppression: `aqt agent start` is as much a
// daemon invocation as `aqt agent` is.
func TestBackgroundUpdateSuppressionCoversSubcommands(t *testing.T) {
	withTerminal(t, true)
	withFlags(t, false, false)

	agent := subcommand(t, rootCmd(), "agent")
	for _, name := range []string{"start", "status", "stop", "logs"} {
		if sub := subcommand(t, agent, name); backgroundUpdateAllowed(sub) {
			t.Errorf("`aqt agent %s` allows a background check", name)
		}
	}
}

// The default is off, so installing aqt adds no network traffic to commands that
// never asked for it.
func TestBackgroundUpdateDoesNothingUnderTheDefaultPolicy(t *testing.T) {
	withUpdateStore(t)
	withTerminal(t, true)
	withFlags(t, false, false)
	// A base URL that cannot be reached: if the policy were consulted wrongly and a
	// check ran, it would have to touch this and take the full timeout.
	t.Setenv(updateBaseURLEnv, "https://127.0.0.1:1/never-reached")
	withBuild(t, "v0.3.0", update.KindRelease)

	done := make(chan struct{})
	go func() {
		defer close(done)
		maybeBackgroundUpdate(subcommand(t, rootCmd(), "status"))
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the default policy performed a network check")
	}
}

// artifactSourceFunc adapts a function to update.ArtifactSource.
type artifactSourceFunc func(ctx context.Context, version string, a update.Artifact, w io.Writer) error

func (f artifactSourceFunc) FetchArtifact(ctx context.Context, version string, a update.Artifact, w io.Writer) error {
	return f(ctx, version, a, w)
}

// withArtifactSource serves the release archive from the test instead of GitHub.
func withArtifactSource(t *testing.T, fn artifactSourceFunc) {
	t.Helper()
	orig := updateArtifactSource
	updateArtifactSource = func() update.ArtifactSource { return fn }
	t.Cleanup(func() { updateArtifactSource = orig })
}

// captureStderr redirects os.Stderr for the duration of fn, which is where every
// background update notice is written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// The check is budgeted for a few kilobytes of metadata. An automatic install
// downloads tens of megabytes, so deriving its context from the check's would
// leave it whatever remains of five seconds — on an ordinary connection, never
// enough, and the update would fail the same way every day forever.
func TestBackgroundAutoInstallDoesNotInheritTheCheckBudget(t *testing.T) {
	requirePublishedPlatform(t)
	store := withUpdateStore(t)
	withTerminal(t, true)
	withFlags(t, false, false)
	serveUpdateFixture(t, "v9.9.9")
	withBuild(t, "v0.3.0", update.KindRelease)
	if err := store.SetPolicy(update.PolicyAuto); err != nil {
		t.Fatal(err)
	}

	var budget time.Duration
	withArtifactSource(t, func(ctx context.Context, _ string, _ update.Artifact, _ io.Writer) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("the automatic install runs unbounded")
		}
		budget = time.Until(deadline)
		return errors.New("no archive in this test")
	})

	out := captureStderr(t, func() {
		maybeBackgroundUpdate(subcommand(t, rootCmd(), "status"))
	})

	if budget == 0 {
		t.Fatal("the install never reached the artifact source")
	}
	if budget <= update.BackgroundTimeout {
		t.Fatalf("the install had %v, the check budget is %v", budget, update.BackgroundTimeout)
	}
	// The install failed for the test's own reason, which is the path being asserted
	// on: it must name the release and the command that finishes the job.
	if !strings.Contains(out, "automatic update to v9.9.9 failed") || !strings.Contains(out, "aqt update") {
		t.Fatalf("the failure notice does not say what to do:\n%s", out)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	// A failure is not a deferral: keeping one would retry the whole download on
	// every subsequent command instead of at the next interval.
	if st.DeferredVersion != "" {
		t.Fatalf("a failed install left a deferral for %q", st.DeferredVersion)
	}
	if st.LastCheckAt == "" {
		t.Fatal("the check was not stamped, so the next command would check again")
	}
}

// While a deferral is pending the interval is bypassed so the install lands at the
// first idle moment. Idle is decided locally: an agent still holding the binary is
// not a reason to fetch metadata after every command.
func TestBackgroundDeferralDoesNotCheckWhileAnAgentRuns(t *testing.T) {
	store := withUpdateStore(t)
	withTerminal(t, true)
	withFlags(t, false, false)
	// Unreachable: reaching for it at all is the failure this test is about.
	t.Setenv(updateBaseURLEnv, "https://127.0.0.1:1/never-reached")
	withBuild(t, "v0.3.0", update.KindRelease)

	if err := store.SetPolicy(update.PolicyAuto); err != nil {
		t.Fatal(err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	st.MarkChecked(time.Now())
	st.DeferredVersion = "v9.9.9"
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	// A pid that is certainly running and is not this process, so the deferral holds.
	if err := store.RegisterAgent(t.TempDir(), liveOtherPID(t), time.Now()); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		maybeBackgroundUpdate(subcommand(t, rootCmd(), "status"))
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a pending deferral checked the network while an agent was running")
	}
}

// liveOtherPID starts a process that outlives the test, so a registry entry for it
// reads as a running agent.
func liveOtherPID(t *testing.T) int {
	t.Helper()
	name, args := "sleep", []string{"30"}
	if runtime.GOOS == "windows" {
		name, args = "cmd", []string{"/c", "timeout", "/t", "30", "/nobreak"}
	}
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a helper process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd.Process.Pid
}

func TestUpdatePolicyCommandRoundTrips(t *testing.T) {
	store := withUpdateStore(t)

	for _, want := range []update.Policy{update.PolicyNotify, update.PolicyAuto, update.PolicyOff} {
		out := captureStdout(t, func() {
			runCmd(t, rootCmd(), "update", "policy", string(want))
		})
		if !strings.Contains(out, string(want)) {
			t.Fatalf("output does not confirm the policy:\n%s", out)
		}
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if st.Policy != want {
			t.Fatalf("stored policy = %q, want %q", st.Policy, want)
		}
	}
}

func TestUpdatePolicyCommandRejectsAnUnknownMode(t *testing.T) {
	withUpdateStore(t)

	root := rootCmd()
	root.SetArgs([]string{"update", "policy", "aggressive"})
	if err := root.Execute(); err == nil {
		t.Fatal("an unknown policy was accepted")
	}
}

func TestUpdatePolicyCommandShowsTheCurrentMode(t *testing.T) {
	store := withUpdateStore(t)
	if err := store.SetPolicy(update.PolicyNotify); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		runCmd(t, rootCmd(), "update", "policy")
	})
	if strings.TrimSpace(out) != string(update.PolicyNotify) {
		t.Fatalf("output = %q, want %q", strings.TrimSpace(out), update.PolicyNotify)
	}
}

// An agent that was killed rather than stopped cleanly never unregisters. It must
// not defer automatic updates forever, which matters most on Windows, where
// stopping an agent terminates it outright.
func TestLiveWatchAgentsReapsADeadAgent(t *testing.T) {
	store := withUpdateStore(t)
	if err := store.RegisterAgent(t.TempDir(), 0x7FFFFFF0, time.Now()); err != nil {
		t.Fatal(err)
	}

	if agents := liveWatchAgents(store); len(agents) != 0 {
		t.Fatalf("a dead agent still defers updates: %+v", agents)
	}
	recorded, err := store.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(recorded) != 0 {
		t.Fatalf("the dead entry survived on disk: %+v", recorded)
	}
}

// A stale entry whose pid was recycled into this very process must not make the
// update defer on itself: the process running the check is by definition not a
// watch agent, since agents never reach this path.
func TestLiveWatchAgentsIgnoresTheCurrentProcess(t *testing.T) {
	store := withUpdateStore(t)
	if err := store.RegisterAgent(t.TempDir(), os.Getpid(), time.Now()); err != nil {
		t.Fatal(err)
	}

	if agents := liveWatchAgents(store); len(agents) != 0 {
		t.Fatalf("the checking process counted itself as an agent: %+v", agents)
	}
}

func TestWatchAgentRegistrationRoundTrips(t *testing.T) {
	store := withUpdateStore(t)
	root := t.TempDir()

	registerWatchAgent(root)
	agents, err := store.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("agents after registering = %+v", agents)
	}

	unregisterWatchAgent(root)
	agents, err = store.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 0 {
		t.Fatalf("agents after unregistering = %+v", agents)
	}
}
