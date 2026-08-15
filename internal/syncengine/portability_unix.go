// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package syncengine

import "io/fs"

// On POSIX the scanned permission bits are authoritative: record what stat reports.

func scanFileMode(info fs.FileInfo, prev uint32, inBase bool) uint32 {
	return uint32(info.Mode().Perm())
}

func scanDirMode(info fs.FileInfo, prev uint32, inBase bool) uint32 {
	return uint32(info.Mode().Perm())
}

// lockedByAnotherProcess is a Windows-only failure class; POSIX reads are not
// gated by other processes' open handles.
func lockedByAnotherProcess(error) bool { return false }
