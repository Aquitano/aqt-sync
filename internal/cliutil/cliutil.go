// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cliutil holds the presentation and confirmation rules the aqt and
// aqt-server binaries share, so one format or one safety gate is not two.
package cliutil

import (
	"errors"
	"fmt"
	"time"
)

// HumanBytes renders a byte count as a short human string (e.g. 1.2 KB).
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// FormatTime renders a time in the local zone at minute precision. A zero time
// renders as "-": nothing was recorded.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// FormatUnix renders a Unix-seconds timestamp like FormatTime, treating 0 (rather
// than the zero time.Time) as "nothing recorded".
func FormatUnix(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return FormatTime(time.Unix(unix, 0))
}

// ErrNotConfirmable means a destructive command needed a confirmation that the run
// could never answer (no terminal, no -y/--yes).
var ErrNotConfirmable = errors.New("confirmation required: pass -y/--yes to proceed non-interactively")

// ErrAborted means the confirmation was declined.
var ErrAborted = errors.New("aborted")

// Confirm gates a destructive action: assumeYes skips the prompt, a run that cannot
// prompt fails with ErrNotConfirmable rather than letting a prompt read EOF and be
// taken as consent, and anything but an affirmative answer aborts. ask puts the
// question to the user and is only called when a prompt is possible.
func Confirm(prompt string, assumeYes, canPrompt bool, ask func(prompt string) (bool, error)) error {
	if assumeYes {
		return nil
	}
	if !canPrompt {
		return ErrNotConfirmable
	}
	ok, err := ask(prompt)
	if err != nil {
		return err
	}
	if !ok {
		return ErrAborted
	}
	return nil
}
