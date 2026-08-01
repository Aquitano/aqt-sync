package update

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) Store {
	t.Helper()
	return Store{Dir: t.TempDir()}
}

// Installing aqt must not add background network traffic to commands that never
// asked for it, so anything other than an explicit opt-in reads as off.
func TestPolicyDefaultsToOff(t *testing.T) {
	st, err := testStore(t).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Policy != PolicyOff {
		t.Fatalf("policy = %q, want off", st.Policy)
	}
}

func TestPolicyRoundTrips(t *testing.T) {
	s := testStore(t)
	for _, p := range []Policy{PolicyNotify, PolicyAuto, PolicyOff} {
		if err := s.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy(%s): %v", p, err)
		}
		st, err := s.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if st.Policy != p {
			t.Fatalf("policy = %q, want %q", st.Policy, p)
		}
	}
}

func TestParsePolicyRejectsAnythingElse(t *testing.T) {
	for _, s := range []string{"", "on", "yes", "Auto", "always"} {
		if _, err := ParsePolicy(s); !errors.Is(err, ErrBadPolicy) {
			t.Fatalf("ParsePolicy(%q) = %v, want ErrBadPolicy", s, err)
		}
	}
}

// A state file that cannot be read must not wedge every command that consults it.
// The safe reading is the default one.
func TestPolicyFallsBackWhenTheStateFileIsUnusable(t *testing.T) {
	cases := map[string]string{
		"corrupt json":   "{not json",
		"unknown policy": `{"policy":"aggressive"}`,
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			if err := os.WriteFile(filepath.Join(s.Dir, stateFileName), []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			st, err := s.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if st.Policy != PolicyOff {
				t.Fatalf("policy = %q, want off", st.Policy)
			}
		})
	}
}

func TestPolicyChangeClearsADeferredInstall(t *testing.T) {
	s := testStore(t)
	if err := s.Save(State{Policy: PolicyAuto, DeferredVersion: "v9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy(PolicyNotify); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.DeferredVersion != "" {
		t.Fatalf("a deferral decided under auto survived the switch to notify: %q", st.DeferredVersion)
	}
}

func TestDueForCheckRateLimits(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		last string
		want bool
	}{
		{name: "never checked", last: "", want: true},
		{name: "just checked", last: now.Add(-time.Minute).Format(time.RFC3339), want: false},
		{name: "checked an hour ago", last: now.Add(-time.Hour).Format(time.RFC3339), want: false},
		{name: "checked just under the interval", last: now.Add(-CheckInterval + time.Minute).Format(time.RFC3339), want: false},
		{name: "checked a day ago", last: now.Add(-CheckInterval).Format(time.RFC3339), want: true},
		// A clock that jumped must not be able to suppress checks indefinitely.
		{name: "stamped in the future", last: now.Add(72 * time.Hour).Format(time.RFC3339), want: true},
		{name: "unparseable", last: "not a time", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := State{LastCheckAt: tc.last}
			if got := st.DueForCheck(now); got != tc.want {
				t.Fatalf("DueForCheck = %v, want %v", got, tc.want)
			}
		})
	}
}

// A failed check still counts, so an unreachable network cannot turn "once a day"
// into "on every command".
func TestMarkCheckedStampsRegardlessOfOutcome(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	var st State
	st.MarkChecked(now)

	if st.DueForCheck(now) {
		t.Fatal("a stamped check is still due immediately")
	}
	if !st.DueForCheck(now.Add(CheckInterval)) {
		t.Fatal("a check is not due again after the interval")
	}
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	s := testStore(t)
	if err := s.Save(State{Policy: PolicyNotify}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if runtimeIsPOSIX() && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", fi.Mode().Perm())
	}
	// A rename-based write leaves no temporaries next to the file it replaced.
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("state directory holds %d files, want just the state file", len(entries))
	}
}
