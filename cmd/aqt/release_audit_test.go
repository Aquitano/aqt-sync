// SPDX-License-Identifier: AGPL-3.0-or-later

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
