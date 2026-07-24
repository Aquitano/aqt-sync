package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/identity"
)

// `aqt lock` advertises that the device stays attached, so it must not cost the
// tracked folders anything. Sealing base.json under the session key meant a routine
// lock made every base unreadable, and `aqt sync` then refused with errSyncNoBase —
// pushing the user into a --reconcile that resurrects deletions.
func TestLockLeavesTrackedFoldersSyncable(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.init(dir)
	if err := runSync(dir, syncOptions{}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	// This is exactly what `aqt lock` does.
	if err := identity.ClearSession(identity.DefaultProfile); err != nil {
		t.Fatalf("lock: %v", err)
	}

	base, ok, err := loadBaseForSync(dir)
	if err != nil {
		t.Fatalf("loadBaseForSync: %v", err)
	}
	if !ok {
		t.Fatal("the sealed base is unreadable after `aqt lock`; sync would refuse with errSyncNoBase")
	}
	if len(base.Entries) == 0 {
		t.Fatal("the base opened but is empty")
	}
	// Unlocking again (what `aqt login` does) and syncing must work against that base.
	h.unlockSession()
	if err := runSync(dir, syncOptions{}); err != nil {
		t.Fatalf("sync after lock: %v", err)
	}
}

// An id that begins with a dash is parsed by cobra as a flag cluster. Servers no
// longer mint them, but ids handed out before that stay valid forever and no
// server-side change can reach them.
func TestLeadingDashIDsAreAddressable(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "a legacy id is rewritten to its aqt:// form",
			in:   []string{"unshare", "-aCPpqvuOEo", "-y"},
			want: []string{"unshare", "aqt://-aCPpqvuOEo", "-y"},
		},
		{
			name: "real flags are untouched",
			in:   []string{"sync", "--force", "-y", "-q"},
			want: []string{"sync", "--force", "-y", "-q"},
		},
		{
			name: "a long flag value is untouched",
			in:   []string{"whoami", "--profile", "-aCPpqvuOEo"},
			want: []string{"whoami", "--profile", "-aCPpqvuOEo"},
		},
		{
			name: "another command flag value is untouched",
			in:   []string{"snapshot", "create", "release", "--label", "-aCPpqvuOEo"},
			want: []string{"snapshot", "create", "release", "--label", "-aCPpqvuOEo"},
		},
		{
			name: "a short flag value is untouched",
			in:   []string{"pull", "some-id", "-o", "-aCPpqvuOEo"},
			want: []string{"pull", "some-id", "-o", "-aCPpqvuOEo"},
		},
		{
			name: "an attached short flag value is untouched",
			in:   []string{"pull", "some-id", "-oaCPpqvuOE"},
			want: []string{"pull", "some-id", "-oaCPpqvuOE"},
		},
		{
			name: "a combined short flag value is untouched",
			in:   []string{"pull", "some-id", "-qoCPpqvuOE"},
			want: []string{"pull", "some-id", "-qoCPpqvuOE"},
		},
		{
			name: "an already-prefixed ref is untouched",
			in:   []string{"rm", "aqt://-aCPpqvuOEo"},
			want: []string{"rm", "aqt://-aCPpqvuOEo"},
		},
		{
			name: "nothing past -- is rewritten",
			in:   []string{"rm", "--", "-aCPpqvuOEo"},
			want: []string{"rm", "--", "-aCPpqvuOEo"},
		},
		{
			name: "a plain id is untouched",
			in:   []string{"rm", "aCPpqvuOEoX"},
			want: []string{"rm", "aCPpqvuOEoX"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeLeadingDashIDs(rootCmd(), tc.in)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("escapeLeadingDashIDs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The rewritten form has to survive the ref parser, or the fix just moves the error.
func TestRewrittenDashIDParsesBackToTheID(t *testing.T) {
	rewritten := escapeLeadingDashIDs(rootCmd(), []string{"-aCPpqvuOEo"})[0]
	if id, _, _ := parseRef(rewritten); id != "-aCPpqvuOEo" {
		t.Fatalf("parseRef(%q) = %q, want the original id", rewritten, id)
	}
}

// Logging a different account into an occupied profile used to overwrite its token
// and device id, orphaning that device's server-side session with nothing left to
// revoke it by. `aqt signup` already refuses this; the asymmetry was the bug.
func TestLoginRefusesToOverwriteAnotherAccountsProfile(t *testing.T) {
	newE2E(t)

	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	original := prof.Token

	err = runLogin("someone-else@example.com", 0)
	if err == nil {
		t.Fatal("login as a different account over an existing profile succeeded")
	}
	if !strings.Contains(err.Error(), "already logged in") {
		t.Fatalf("login error = %v, want it to name the occupied profile", err)
	}
	after, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	if after.Token != original {
		t.Fatal("the existing profile's token was overwritten anyway")
	}
}
