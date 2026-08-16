// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/update"
)

// Exhausted rate limiting is temporary, so cron and `watch --once` must see the
// retryable network code rather than a generic failure they would treat as
// permanent.
func TestExhaustedRateLimitExitsRetryable(t *testing.T) {
	err := error(&client.RateLimitedError{
		Attempts: 4, LastDelay: 2 * time.Second, NextRetryAt: time.Now().Add(2 * time.Second),
	})
	if got := exitCode(err); got != 5 {
		t.Errorf("exitCode(rate limited) = %d, want 5", got)
	}
	if got := exitCode(fmt.Errorf("sync: %w", err)); got != 5 {
		t.Errorf("exitCode(wrapped rate limited) = %d, want 5", got)
	}
	if got := exitCode(client.ErrRateLimited); got != 5 {
		t.Errorf("exitCode(ErrRateLimited) = %d, want 5", got)
	}
}

// The 426 must keep its own exit code; rate-limit handling must not swallow it.
func TestUpgradeRequiredKeepsExitSix(t *testing.T) {
	err := error(&client.UpgradeRequiredError{MinClient: 9, Capability: api.ClientCapability})
	if got := exitCode(err); got != 6 {
		t.Errorf("exitCode(upgrade required) = %d, want 6", got)
	}
	if !errors.Is(err, client.ErrUpgradeRequired) {
		t.Error("UpgradeRequiredError no longer satisfies errors.Is(err, ErrUpgradeRequired)")
	}
}

// The rendered 426 must name the three facts a user needs to act: what they are
// running, what the resource needs, and the command that upgrades this install.
func TestUpgradeGuidanceNamesVersionCapabilityAndAction(t *testing.T) {
	got := upgradeGuidance(
		&client.UpgradeRequiredError{MinClient: 9, Capability: api.ClientCapability},
		update.Install{Owner: update.OwnerStandalone},
	)
	for _, want := range []string{version, strconv.Itoa(api.ClientCapability), "9", "aqt update"} {
		if !strings.Contains(got, want) {
			t.Errorf("guidance %q is missing %q", got, want)
		}
	}
}

// A source build has no upgrade command at all; it must still say something
// actionable rather than falling back to a command that will refuse.
func TestUpgradeGuidanceExplainsSourceBuilds(t *testing.T) {
	got := upgradeGuidance(
		&client.UpgradeRequiredError{MinClient: 9, Capability: api.ClientCapability},
		update.Install{Owner: update.OwnerSource},
	)
	if !strings.Contains(got, "make build") {
		t.Errorf("guidance %q does not tell a source build how to upgrade", got)
	}
}

// Server prose is quoted, never trusted: explainError renders it through the
// sanitized Detail, so no escape sequence reaches the terminal.
func TestUpgradeGuidanceIsControlCharacterFree(t *testing.T) {
	got := upgradeGuidance(
		&client.UpgradeRequiredError{MinClient: 9, Capability: api.ClientCapability, Detail: "upgrade aqt"},
		update.Install{Owner: update.OwnerStandalone},
	)
	if !strings.Contains(got, "upgrade aqt") {
		t.Errorf("guidance %q dropped the server detail entirely", got)
	}
	if strings.ContainsAny(got, "\x1b\n\r\x00") {
		t.Errorf("guidance carries control characters: %q", got)
	}
}

// explainError expands only what it knows how to explain; every other error must
// reach the user unchanged.
func TestExplainErrorPassesOtherErrorsThrough(t *testing.T) {
	orig := errors.New("something else went wrong")
	if got := explainError(orig); got != orig {
		t.Errorf("explainError rewrote an unrelated error: %v", got)
	}
	if got := explainError(nil); got != nil {
		t.Errorf("explainError(nil) = %v, want nil", got)
	}
}

// A 426 surfaces from deep inside a command, so the expansion must survive
// wrapping. The action itself depends on how this binary was installed; what is
// invariant is that the running version and both capabilities are named.
func TestExplainErrorExpandsWrappedUpgradeError(t *testing.T) {
	wrapped := fmt.Errorf("clone: %w", &client.UpgradeRequiredError{MinClient: 9, Capability: api.ClientCapability})
	got := explainError(wrapped).Error()
	for _, want := range []string{version, strconv.Itoa(api.ClientCapability), "9"} {
		if !strings.Contains(got, want) {
			t.Errorf("expanded error %q is missing %q", got, want)
		}
	}
}

// The TUI's one-line verdict for exit 6 must carry the same recovery action as the
// CLI, so a user who never leaves the dashboard still learns what to run.
func TestTUIUpgradeNoteNamesTheUpdateCommand(t *testing.T) {
	got := tuiExitNote(6)
	if !strings.Contains(got, upgradeAction(detectedInstall())) {
		t.Errorf("tuiExitNote(6) = %q, want the CLI's recovery action", got)
	}
	if !strings.Contains(got, strconv.Itoa(api.ClientCapability)) {
		t.Errorf("tuiExitNote(6) = %q, want this build's capability", got)
	}
}

// Both the CLI message and the TUI note read the action from one place, so a
// source install is never pointed at a command that would refuse.
func TestUpgradeActionRoutesByInstallOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		install update.Install
		want    string
	}{
		{"standalone", update.Install{Owner: update.OwnerStandalone}, "aqt update"},
		{"source", update.Install{Owner: update.OwnerSource}, "make build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := upgradeAction(tc.install)
			if !strings.Contains(got, tc.want) {
				t.Errorf("upgradeAction = %q, want it to name %q", got, tc.want)
			}
			if tc.name != "standalone" && strings.Contains(got, "run `aqt update`") {
				t.Errorf("upgradeAction = %q points a %s install at `aqt update`", got, tc.name)
			}
		})
	}
}
