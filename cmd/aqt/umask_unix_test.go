//go:build !windows

package main

import (
	"syscall"
	"testing"
)

// setUmask installs a umask for the duration of a test and returns its restore.
func setUmask(t *testing.T, mask int) func() {
	t.Helper()
	prev := syscall.Umask(mask)
	return func() { syscall.Umask(prev) }
}
