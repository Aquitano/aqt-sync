// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile takes a non-blocking exclusive flock on f. Held reports whether the
// lock was obtained; a lock someone else holds is (false, nil). The kernel
// releases the lock when the last descriptor for this open closes — including on
// process death — so a crashed holder never wedges the lock.
func tryLockFile(f *os.File) (held bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return false, nil
	}
	return false, err
}
