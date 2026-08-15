// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// heldSyncLocks counts the sync locks this process holds, by folder. The lock is
// an OS file lock taken per open, so a process that re-acquired one it already
// held would collide with itself. Counting makes it re-entrant, which lets a
// command that must mutate the tree before syncing (in-place restore) hold the
// lock across both instead of leaving the mutation unprotected.
var heldSyncLocks = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// acquireSyncLock takes an exclusive per-folder lock so two `aqt sync` runs in
// the same directory cannot race on the manifest. The lock is an OS file lock on
// .aqt/lock, which the kernel drops when the holding process exits, so a crash
// never wedges the folder and there is no reclaim step to race. Re-entrant within
// one process: each acquire must be released.
func acquireSyncLock(root string) (release func(), err error) {
	heldSyncLocks.Lock()
	if heldSyncLocks.n[root] > 0 {
		heldSyncLocks.n[root]++
		heldSyncLocks.Unlock()
		return func() { releaseHeldSyncLock(root, nil) }, nil
	}
	heldSyncLocks.Unlock()

	path := filepath.Join(root, syncengine.ControlDir, "lock")
	drop, err := acquirePIDFile(path, func(pid int) error {
		return fmt.Errorf("another aqt sync is running here (pid %d); wait for it to finish", pid)
	})
	if err != nil {
		return nil, err
	}
	heldSyncLocks.Lock()
	heldSyncLocks.n[root]++
	heldSyncLocks.Unlock()
	return func() { releaseHeldSyncLock(root, drop) }, nil
}

func releaseHeldSyncLock(root string, drop func()) {
	heldSyncLocks.Lock()
	heldSyncLocks.n[root]--
	last := heldSyncLocks.n[root] == 0
	if last {
		delete(heldSyncLocks.n, root)
	}
	heldSyncLocks.Unlock()
	if last && drop != nil {
		drop()
	}
}

// acquirePIDFile takes an exclusive OS lock (flock/LockFileEx) on the file at
// path, creating it if needed, and returns a release. The kernel drops the lock
// when the holding process exits, so a crashed holder frees it with no reclaim
// step — the old pid-file dance (check the recorded pid, remove, recreate) was a
// check-then-act that let two racing reclaimers both hold the lock. The recorded
// pid is now informational only, for busyMsg; the lock itself is the OS lock.
func acquirePIDFile(path string, busyMsg func(pid int) error) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	held, err := tryLockFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if !held {
		pid, _ := readLockPID(path)
		f.Close()
		return nil, busyMsg(pid)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	// Close drops the lock. The file itself stays: removing it would reopen the
	// unlink race (a waiter holding the old inode and a fresh creator would each
	// hold "the" lock at once).
	return func() { f.Close() }, nil
}

func readLockPID(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return pid, true
}
