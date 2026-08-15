// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/update"
)

// backgroundApplyTimeout bounds an automatic install. It is a separate budget from
// the check, and not derived from it: the check moves a few kilobytes of metadata
// after every eligible command, while this moves tens of megabytes once per
// release for a user who asked for it. Bounded all the same, because the command
// that triggered it is holding the prompt until this returns.
const backgroundApplyTimeout = 2 * time.Minute

// backgroundSilent commands never trigger a background check. `watch` and `agent`
// are long-lived or detached, `update` is already doing this on purpose, and `tui`
// owns the screen, so a stray line would corrupt what it drew.
var backgroundSilent = map[string]bool{
	"watch":  true,
	"agent":  true,
	"update": true,
	"tui":    true,
}

// maybeBackgroundUpdate runs after a command that succeeded. It is entirely
// advisory: every failure path returns without a word, because a user who ran
// `aqt sync` asked about their files and not about this.
func maybeBackgroundUpdate(cmd *cobra.Command) {
	if !backgroundUpdateAllowed(cmd) {
		return
	}
	store, err := updateStore()
	if err != nil {
		return
	}
	st, err := store.Load()
	if err != nil || st.Policy == update.PolicyOff {
		return
	}
	if !st.DueForCheck(time.Now()) {
		// A deferred install is work already decided on; it should finish at the first
		// idle moment rather than wait out another full interval. Until that moment
		// arrives the answer needs no network: the agents that deferred it are still
		// running, and asking again on every command is what the interval prevents.
		if st.DeferredVersion == "" || len(liveWatchAgents(store)) > 0 {
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), update.BackgroundTimeout)
	defer cancel()

	res, checkErr := update.Check(ctx, update.Options{
		Build: update.Build{Version: version, Kind: buildKind},
		// Background work is stable-only. A prerelease is something a user opts into
		// per invocation, never something a policy decides on their behalf.
		Channel: update.ChannelStable,
		Source:  updateSource(),
		Roots:   updateTrustRoots(),
	})
	// A failed check still counts as a check. Otherwise an unreachable network
	// turns "once a day" into "on every command".
	st.MarkChecked(time.Now())
	if checkErr != nil || res.Status != update.StatusUpdateAvailable {
		if checkErr == nil && res.Status == update.StatusUpToDate {
			st.DeferredVersion = ""
		}
		_ = store.Save(st)
		return
	}

	if st.Policy == update.PolicyAuto {
		if applyInBackground(store, &st, res) {
			return
		}
	}
	notify(&st, res)
	_ = store.Save(st)
}

// applyInBackground installs a release under the auto policy. It reports whether
// it handled the situation, so the caller falls back to a plain notice when this
// declines.
func applyInBackground(store update.Store, st *update.State, res update.Result) bool {
	in, err := update.DetectInstall(update.Build{Version: version, Kind: buildKind})
	if err != nil || !in.Replaceable() || res.Artifact == nil {
		return false // notify instead: nothing here is ours to replace
	}
	// Replacing the binary out from under a running watch agent is safe on the
	// filesystems this runs on, but the agent would keep running the old code with
	// no way to know it. Defer instead, and say what finishes the job.
	if agents := liveWatchAgents(store); len(agents) > 0 {
		if st.DeferredVersion != res.AvailableVersion {
			fmt.Fprintf(os.Stderr, "aqt %s is available; %d watch agent(s) are running, so it was not installed.\n",
				res.AvailableVersion, len(agents))
			fmt.Fprintln(os.Stderr, "Stop them with `aqt agent stop` in each folder, then run `aqt update`.")
		}
		st.DeferredVersion = res.AvailableVersion
		st.NotifiedVersion = res.AvailableVersion
		_ = store.Save(*st)
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), backgroundApplyTimeout)
	defer cancel()

	applied, err := applyUpdate(ctx, in, res)
	if err != nil {
		// An automatic install that failed must not be silent — the user would
		// otherwise never learn why they are still on the old version — but it also
		// must not fail their command. The deferral is dropped rather than kept: a
		// failure that repeats would otherwise retry on every single command.
		fmt.Fprintf(os.Stderr, "aqt: automatic update to %s failed: %v\n", res.AvailableVersion, err)
		fmt.Fprintln(os.Stderr, "Run `aqt update` to install it.")
		st.DeferredVersion = ""
		_ = store.Save(*st)
		return true
	}
	fmt.Fprintf(os.Stderr, "aqt updated %s -> %s\n", applied.FromVersion, applied.ToVersion)
	st.DeferredVersion = ""
	st.NotifiedVersion = applied.ToVersion
	_ = store.Save(*st)
	return true
}

// notify prints one line about an available release, once per version. Repeating
// it on every check for a release the user has already declined to install is how
// a helpful notice turns into noise people learn to ignore.
func notify(st *update.State, res update.Result) {
	if st.NotifiedVersion == res.AvailableVersion {
		return
	}
	fmt.Fprintf(os.Stderr, "aqt %s is available (you have %s). Run `aqt update` to install it.\n",
		res.AvailableVersion, res.CurrentVersion)
	st.NotifiedVersion = res.AvailableVersion
}

// registerWatchAgent records this process in the global agent registry. Failures
// are ignored: the registry only decides whether an automatic update defers, and
// a watcher that cannot be recorded must still watch.
func registerWatchAgent(root string) {
	store, err := updateStore()
	if err != nil {
		return
	}
	_ = store.RegisterAgent(root, os.Getpid(), time.Now())
}

func unregisterWatchAgent(root string) {
	store, err := updateStore()
	if err != nil {
		return
	}
	_ = store.UnregisterAgent(root)
}

// liveWatchAgents returns the registered agents still running, reaping the rest.
func liveWatchAgents(store update.Store) []update.Agent {
	agents, err := store.LiveAgents(func(pid int) bool {
		return pid != os.Getpid() && processAlive(pid)
	})
	if err != nil {
		return nil
	}
	return agents
}

// onATerminal reports whether both ends of this invocation are a terminal. A
// variable so the suppression rules can be tested without one.
var onATerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && interactiveStdin()
}

// backgroundUpdateAllowed gates every background check on the invocation looking
// like a person at a terminal. Machine-readable output, quiet mode, a pipe, and a
// detached agent all mean something is consuming this output that did not ask for
// an update notice.
func backgroundUpdateAllowed(cmd *cobra.Command) bool {
	if flagJSON || flagQuiet {
		return false
	}
	if !onATerminal() {
		return false
	}
	if cmd == nil {
		return false
	}
	for c := cmd; c != nil; c = c.Parent() {
		if backgroundSilent[c.Name()] {
			return false
		}
	}
	return true
}
