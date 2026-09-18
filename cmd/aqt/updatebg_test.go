// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/update"
)

// withUpdateStore points the update policy at a temporary directory,
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

func (app *application) withFlags(t *testing.T, asJSON, quiet bool) {
	t.Helper()
	origJSON, origQuiet := app.json, app.quiet
	app.json, app.quiet = asJSON, quiet
	t.Cleanup(func() { app.json, app.quiet = origJSON, origQuiet })
}

// A background check must only ever run for an interactive person. Everything
// else is a script, a pipe, or a daemon consuming output that never asked for an
// update notice.
func TestBackgroundUpdateSuppression(t *testing.T) {
	app := &application{ctx: context.Background()}
	root := app.rootCmd()
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
			app.withFlags(t, tc.asJSON, tc.quiet)

			cmd := subcommand(t, root, tc.command)
			if got := app.backgroundUpdateAllowed(cmd); got != tc.want {
				t.Fatalf("backgroundUpdateAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// Subcommands inherit their parent's suppression: `aqt agent start` is as much a
// daemon invocation as `aqt agent` is.
func TestBackgroundUpdateSuppressionCoversSubcommands(t *testing.T) {
	app := &application{ctx: context.Background()}
	withTerminal(t, true)
	app.withFlags(t, false, false)

	agent := subcommand(t, app.rootCmd(), "agent")
	for _, name := range []string{"start", "status", "stop", "logs"} {
		if sub := subcommand(t, agent, name); app.backgroundUpdateAllowed(sub) {
			t.Errorf("`aqt agent %s` allows a background check", name)
		}
	}
}

// The default is off, so installing aqt adds no network traffic to commands that
// never asked for it.
func TestBackgroundUpdateDoesNothingUnderTheDefaultPolicy(t *testing.T) {
	app := &application{ctx: context.Background()}
	withUpdateStore(t)
	withTerminal(t, true)
	app.withFlags(t, false, false)
	// A base URL that cannot be reached: if the policy were consulted wrongly and a
	// check ran, it would have to touch this and take the full timeout.
	t.Setenv(updateBaseURLEnv, "https://127.0.0.1:1/never-reached")
	withBuild(t, "v0.3.0", update.KindRelease)

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.maybeBackgroundUpdate(subcommand(t, app.rootCmd(), "status"))
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the default policy performed a network check")
	}
}

func TestUpdatePolicyCommandRoundTrips(t *testing.T) {
	app := &application{ctx: context.Background()}
	store := withUpdateStore(t)

	for _, want := range []update.Policy{update.PolicyNotify, update.PolicyOff} {
		out := captureStdout(t, func() {
			runCmd(t, app.rootCmd(), "update", "policy", string(want))
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
	app := &application{ctx: context.Background()}
	withUpdateStore(t)

	root := app.rootCmd()
	root.SetArgs([]string{"update", "policy", "aggressive"})
	if err := root.Execute(); err == nil {
		t.Fatal("an unknown policy was accepted")
	}
}

func TestUpdatePolicyCommandShowsTheCurrentMode(t *testing.T) {
	app := &application{ctx: context.Background()}
	store := withUpdateStore(t)
	if err := store.SetPolicy(update.PolicyNotify); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		runCmd(t, app.rootCmd(), "update", "policy")
	})
	if strings.TrimSpace(out) != string(update.PolicyNotify) {
		t.Fatalf("output = %q, want %q", strings.TrimSpace(out), update.PolicyNotify)
	}
}

func TestBackgroundNotificationsRespectIntervalAndVersion(t *testing.T) {
	requirePublishedPlatform(t)
	app := &application{ctx: context.Background()}
	store := serveUpdateFixture(t, "v9.9.9")
	withTerminal(t, true)
	withBuild(t, "v0.3.0", update.KindRelease)
	if err := store.SetPolicy(update.PolicyNotify); err != nil {
		t.Fatal(err)
	}
	command := subcommand(t, app.rootCmd(), "status")
	out := captureStderr(t, func() { app.maybeBackgroundUpdate(command) })
	if !strings.Contains(out, "v9.9.9 is available") || !strings.Contains(out, "aqt update") {
		t.Fatalf("notification: %q", out)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.NotifiedVersion != "v9.9.9" || st.LastCheckAt == "" || st.Ceiling(update.ChannelStable) != "v9.9.9" {
		t.Fatalf("state after notification: %+v", st)
	}
	// A recent check must stay untouched, even though this command runs later.
	st.MarkChecked(time.Now().Add(-time.Hour))
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	if out := captureStderr(t, func() { app.maybeBackgroundUpdate(command) }); out != "" {
		t.Fatalf("repeated notice: %q", out)
	}
	recent, err := store.Load()
	if err != nil || recent.LastCheckAt != st.LastCheckAt {
		t.Fatalf("checked before interval elapsed: %+v, %v", recent, err)
	}
	// A due check records fresh metadata without repeating the same version notice.
	st.MarkChecked(time.Now().Add(-2 * update.CheckInterval))
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}
	if out := captureStderr(t, func() { app.maybeBackgroundUpdate(command) }); out != "" {
		t.Fatalf("same release notified twice: %q", out)
	}
	checked, err := store.Load()
	if err != nil || checked.LastCheckAt == st.LastCheckAt {
		t.Fatalf("due check did not run: %+v, %v", checked, err)
	}
}
