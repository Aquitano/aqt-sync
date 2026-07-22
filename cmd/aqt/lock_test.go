package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

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
	// Another live process must still be excluded; the pid file is what enforces it.
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
// runSync underneath it, so the lock must be re-entrant within one process — and the
// pid file must survive until the outermost release.
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
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("pid file gone after the inner release: %v", err)
	}
	outer()
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("pid file still present after the outer release: %v", err)
	}
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
