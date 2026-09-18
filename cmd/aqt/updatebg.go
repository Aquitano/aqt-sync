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
func (app *application) maybeBackgroundUpdate(cmd *cobra.Command) {
	if !app.backgroundUpdateAllowed(cmd) {
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
		return
	}

	ctx, cancel := context.WithTimeout(app.ctx, update.BackgroundTimeout)
	defer cancel()

	res, checkErr := update.Check(ctx, update.Options{
		Build: update.Build{Version: version, Kind: buildKind},
		// Background work is stable-only. A prerelease is something a user opts into
		// per invocation, never something a policy decides on their behalf.
		Channel: update.ChannelStable,
		Source:  updateSource(),
		Roots:   updateTrustRoots(),
		Floor:   st.Ceiling(update.ChannelStable),
	})
	// A failed check still counts as a check. Otherwise an unreachable network
	// turns "once a day" into "on every command".
	st.MarkChecked(time.Now())
	// A version only reaches the result after full manifest authentication, so it
	// raises the freshness ceiling. The background path never lowers it: accepting
	// an upstream retraction is an explicit `aqt update --accept-rollback`.
	if checkErr == nil && res.AvailableVersion != "" {
		st.RaiseCeiling(update.ChannelStable, res.AvailableVersion)
	}
	if checkErr != nil || res.Status != update.StatusUpdateAvailable {
		_ = store.Save(st)
		return
	}

	notify(&st, res)
	_ = store.Save(st)
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

// onATerminal reports whether both ends of this invocation are a terminal. A
// variable so the suppression rules can be tested without one.
var onATerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && interactiveStdin()
}

// backgroundUpdateAllowed gates every background check on the invocation looking
// like a person at a terminal. Machine-readable output, quiet mode, a pipe, and a
// detached agent all mean something is consuming this output that did not ask for
// an update notice.
func (app *application) backgroundUpdateAllowed(cmd *cobra.Command) bool {
	if app.json || app.quiet {
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
