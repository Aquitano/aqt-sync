// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func tempTrackedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, syncengine.ControlDir), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestSyncLockExcludesConcurrent(t *testing.T) {
	root := tempTrackedRoot(t)
	lockPath := filepath.Join(root, syncengine.ControlDir, "lock")

	release, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := acquirePIDFile(lockPath, func(int) error { return errLockBusy }); err == nil {
		t.Fatal("expected a second process to be excluded while the lock is held")
	}
	release()
	// After release the lock is free again.
	release2, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
}

var errLockBusy = errors.New("busy")

// In-place restore takes the sync lock before swapping the tree and then calls
// runSync underneath it, so the lock must be re-entrant within one process — and
// the OS lock must be held until the outermost release.
func TestSyncLockIsReentrantInProcess(t *testing.T) {
	root := tempTrackedRoot(t)
	lockPath := filepath.Join(root, syncengine.ControlDir, "lock")

	outer, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("outer acquire: %v", err)
	}
	inner, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("nested acquire: %v", err)
	}
	inner()
	// Still held after the inner release: an outside acquirer stays excluded.
	if _, err := acquirePIDFile(lockPath, func(int) error { return errLockBusy }); err == nil {
		t.Fatal("lock free after the inner release")
	}
	outer()
	rel, err := acquirePIDFile(lockPath, func(int) error { return errLockBusy })
	if err != nil {
		t.Fatalf("lock still held after the outer release: %v", err)
	}
	rel()
}

func TestSyncLockReclaimsStale(t *testing.T) {
	root := tempTrackedRoot(t)
	lockPath := filepath.Join(root, syncengine.ControlDir, "lock")
	// A lock owned by a PID that is not running must be reclaimed, not honored.
	if err := os.WriteFile(lockPath, []byte("999999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("expected a stale lock to be reclaimed: %v", err)
	}
	release()
}

// `aqt lock` advertises that the device stays attached, so it must not cost the
// tracked folders anything. Sealing base.json under the session key meant a routine
// lock made every base unreadable, and `aqt sync` then refused with errSyncNoBase —
// pushing the user into a --reconcile that resurrects deletions.
func TestLockLeavesTrackedFoldersSyncable(t *testing.T) {
	app := &application{ctx: context.Background()}
	h := app.newE2E(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.init(dir)
	if err := app.runSync(dir, syncOptions{}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	// This is exactly what `aqt lock` does.
	if err := identity.ClearSession(identity.DefaultProfile); err != nil {
		t.Fatalf("lock: %v", err)
	}

	base, ok, err := folderstate.LoadBaseForSync(dir, app.profile)
	if err != nil {
		t.Fatalf("LoadBaseForSync: %v", err)
	}
	if !ok {
		t.Fatal("the sealed base is unreadable after `aqt lock`; sync would refuse with errSyncNoBase")
	}
	if len(base.Entries) == 0 {
		t.Fatal("the base opened but is empty")
	}
	// Unlocking again (what `aqt login` does) and syncing must work against that base.
	h.unlockSession()
	if err := app.runSync(dir, syncOptions{}); err != nil {
		t.Fatalf("sync after lock: %v", err)
	}
}
