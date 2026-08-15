//go:build windows

package syncengine

import (
	"errors"
	"io/fs"
	"syscall"
)

// Windows has no POSIX permission bits: Go synthesizes Perm() from the read-only
// attribute — 0666 or 0444 for files, 0777 for directories. Recording that would
// read as a genuine local change on the first scan after a clone, and pushing it
// would strip +x from every executable and make the whole tree world-writable on
// every POSIX device. Mode is therefore a POSIX-only attribute: a Windows scan
// carries the last-synced mode forward untouched — which also keeps the stat
// fast-path honest, since base and scan can never disagree on mode here — and
// gives a path created on this device the conventional default.

func scanFileMode(info fs.FileInfo, prev uint32, inBase bool) uint32 {
	if inBase && prev != 0 {
		return prev
	}
	return 0o644
}

func scanDirMode(info fs.FileInfo, prev uint32, inBase bool) uint32 {
	if inBase && prev != 0 {
		return prev
	}
	return 0o755
}

// lockedByAnotherProcess reports a sharing or lock violation: another process
// holds the file open in an exclusive mode (Outlook's .pst, a running .exe).
// Neither maps to fs.ErrPermission in Go, but for a scan they mean the same
// thing — this file cannot be read right now and that is not the tree's fault.
func lockedByAnotherProcess(err error) bool {
	const (
		errorSharingViolation = syscall.Errno(32)
		errorLockViolation    = syscall.Errno(33)
	)
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation)
}
