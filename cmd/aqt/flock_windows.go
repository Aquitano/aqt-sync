// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockFile takes a non-blocking exclusive LockFileEx region lock on f. Held
// reports whether the lock was obtained; a lock someone else holds is
// (false, nil). Windows releases the lock when the handle closes — including on
// process death — so a crashed holder never wedges the lock.
func tryLockFile(f *os.File) (held bool, err error) {
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{})
	if err == nil {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return false, nil
	}
	return false, err
}
