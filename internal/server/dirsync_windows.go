// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package server

// fsyncDir is a no-op on Windows: a directory handle cannot be flushed with
// FlushFileBuffers, and NTFS does not require an explicit directory sync for a
// freshly created or renamed file's entry to be durable. The unix build does the
// real fsync.
func fsyncDir(string) error { return nil }
