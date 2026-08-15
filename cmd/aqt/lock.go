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

// heldSyncLocks counts the sync locks this process holds, by folder. The lock is a
// pid file, so a process that re-acquired one it already held would read its own
// live pid and refuse. Counting makes it re-entrant, which lets a command that must
// mutate the tree before syncing (in-place restore) hold the lock across both
// instead of leaving the mutation unprotected.
var heldSyncLocks = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

// acquireSyncLock takes an exclusive per-folder lock so two `aqt sync` runs in
// the same directory cannot race on the manifest. The lock is an advisory file
// in .aqt/ holding the holder's PID; a lock left behind by a process that is no
// longer running is reclaimed, so a crash does not wedge the folder. Re-entrant
// within one process: each acquire must be released, and the pid file goes away
// with the last one.
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
		return fmt.Errorf("another aqt sync is running here (pid %d); if not, delete %s", pid, path)
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

// acquirePIDFile creates an exclusive pid file at path and returns a release that
// removes it. A file left behind by a process that is no longer running is
// reclaimed (so a crash never wedges the folder); a file still held by a live
// process yields busyMsg(pid).
func acquirePIDFile(path string, busyMsg func(pid int) error) (release func(), err error) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if pid, ok := readLockPID(path); ok && processAlive(pid) {
			return nil, busyMsg(pid)
		}
		os.Remove(path) // holder is gone: clear the stale file and retry once
	}
	return nil, fmt.Errorf("could not acquire lock at %s", path)
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
