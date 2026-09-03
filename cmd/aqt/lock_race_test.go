// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// deadPID returns a pid no live process holds, so a lock file naming it is stale.
func deadPID(t *testing.T) int {
	t.Helper()
	for pid := 1 << 22; pid > 1<<20; pid -= 7919 {
		if !processAlive(pid) {
			return pid
		}
	}
	t.Skip("could not find a dead pid to fake a stale lock")
	return 0
}

// Reclaiming a stale pid file was a remove-then-create: two racers could both
// clear it and both end up holding the lock (reproduced 2 holders in the audit).
// The lock is now an OS file lock the kernel drops on process death, so a stale
// pid file is just stationery — exactly one racer may hold the lock at a time
// (issue #183).
func TestStaleLockReclaimAdmitsOneHolder(t *testing.T) {
	stalePID := deadPID(t)
	for iter := range 200 {
		path := filepath.Join(t.TempDir(), "lock")
		if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", stalePID)), 0o600); err != nil {
			t.Fatal(err)
		}
		var wins int32
		var releases sync.Map
		var wg sync.WaitGroup
		for g := range 8 {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				release, err := acquirePIDFile(path, func(pid int) error {
					return fmt.Errorf("busy: %d", pid)
				})
				if err == nil {
					atomic.AddInt32(&wins, 1)
					releases.Store(g, release)
				}
			}(g)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("iteration %d: %d goroutines hold the lock, want exactly 1", iter, wins)
		}
		releases.Range(func(_, v any) bool {
			v.(func())()
			return true
		})
	}
}
