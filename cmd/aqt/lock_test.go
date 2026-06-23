package main

import (
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

	release, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// A second acquire while this (live) process holds it must fail.
	if _, err := acquireSyncLock(root); err == nil {
		t.Fatal("expected the second acquire to fail while the lock is held")
	}
	release()
	// After release the lock is free again.
	release2, err := acquireSyncLock(root)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()
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
