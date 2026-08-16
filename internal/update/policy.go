// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aquitano/aqt-sync/internal/fsatomic"
)

// Policy decides what, if anything, ordinary commands do about updates. The
// default is Off: installing aqt must not add background network traffic to
// commands the user did not point at the network.
type Policy string

const (
	// PolicyOff never checks outside an explicit `aqt update`.
	PolicyOff Policy = "off"
	// PolicyNotify checks at most once a day and prints one line when a newer
	// release exists. It never installs anything.
	PolicyNotify Policy = "notify"
	// PolicyAuto additionally installs a stable release once it is safe to replace
	// the binary.
	PolicyAuto Policy = "auto"
)

// CheckInterval is the floor between background checks. It is deliberately long:
// the point is to notice a release eventually, not promptly.
const CheckInterval = 24 * time.Hour

// BackgroundTimeout bounds a background check end to end. A check that has not
// finished by then is abandoned, because it is running after a command the user
// already got their answer from.
const BackgroundTimeout = 5 * time.Second

// ErrBadPolicy means a policy name is not one of the three.
var ErrBadPolicy = errors.New("unknown update policy")

// ParsePolicy validates a policy name.
func ParsePolicy(s string) (Policy, error) {
	switch p := Policy(s); p {
	case PolicyOff, PolicyNotify, PolicyAuto:
		return p, nil
	default:
		return "", fmt.Errorf("%w %q: want off, notify, or auto", ErrBadPolicy, s)
	}
}

// State is the persisted update state, shared by every profile: which binary is
// installed is a machine-level fact, not a per-profile one.
type State struct {
	Policy Policy `json:"policy"`
	// LastCheckAt is when a background check last completed, successfully or not.
	// Failures count, so an unreachable network cannot turn into a check on every
	// single command.
	LastCheckAt string `json:"lastCheckAt,omitempty"`
	// NotifiedVersion is the version the user was last shown a notice for, so a
	// release the user has already been told about stays quiet.
	NotifiedVersion string `json:"notifiedVersion,omitempty"`
	// DeferredVersion is an auto-mode install that was postponed because a watch
	// agent was using the binary. It is what lets the next idle invocation finish
	// the job instead of waiting another full interval.
	DeferredVersion string `json:"deferredVersion,omitempty"`
}

// Store is the directory the update state lives in. It is a value rather than a
// package global so tests get their own and never touch the real config.
type Store struct{ Dir string }

const stateFileName = "update.json"

// DefaultStore is <user config dir>/aqt, the same directory profiles live in.
func DefaultStore() (Store, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return Store{}, err
	}
	return Store{Dir: filepath.Join(base, "aqt")}, nil
}

func (s Store) path() string { return filepath.Join(s.Dir, stateFileName) }

// Load reads the state. A missing file is the default policy, not an error: the
// common case is a fresh install that has never written one.
func (s Store) Load() (State, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return State{Policy: PolicyOff}, nil
	}
	if err != nil {
		return State{Policy: PolicyOff}, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		// A corrupt state file must not wedge every command that consults it. The
		// safe reading is the default one, and the next Save rewrites it.
		return State{Policy: PolicyOff}, nil
	}
	if _, err := ParsePolicy(string(st.Policy)); err != nil {
		st.Policy = PolicyOff
	}
	return st, nil
}

// Save writes the state atomically, so a crash mid-write cannot leave a torn file
// that the next command reads as a different policy than the user set.
func (s Store) Save(st State) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(s.path(), append(b, '\n'), 0o600)
}

// SetPolicy persists a new policy, leaving the rest of the state alone.
func (s Store) SetPolicy(p Policy) error {
	st, err := s.Load()
	if err != nil {
		return err
	}
	st.Policy = p
	// A policy change is an explicit statement about what should happen next, so
	// drop a deferral decided under the old one.
	if p != PolicyAuto {
		st.DeferredVersion = ""
	}
	return s.Save(st)
}

// DueForCheck reports whether enough time has passed since the last background
// check. An unparseable or future timestamp counts as due, so a clock that moved
// cannot suppress checks indefinitely.
func (st State) DueForCheck(now time.Time) bool {
	if st.LastCheckAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, st.LastCheckAt)
	if err != nil {
		return true
	}
	// A stamp in the future is a clock that moved or a state file copied from
	// another machine. Waiting it out would suppress checks for as long as the skew
	// lasts, so treat it as due and let the next check rewrite it.
	if last.After(now) {
		return true
	}
	return !now.Before(last.Add(CheckInterval))
}

// MarkChecked stamps the time a background check ran.
func (st *State) MarkChecked(now time.Time) {
	st.LastCheckAt = now.UTC().Truncate(time.Second).Format(time.RFC3339)
}
