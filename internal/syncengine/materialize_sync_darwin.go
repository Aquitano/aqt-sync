// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"

	"golang.org/x/sys/unix"
)

// syncForRename orders a temp file's data ahead of the rename that publishes it, so
// a crash leaves the old file or the new one, never a torn mix. File.Sync here is
// F_FULLFSYNC, a drive cache flush that costs milliseconds per file; a barrier sync
// keeps the ordering without the flush, and FlushWrites pays for one flush per batch.
// A filesystem without barrier support gets the full sync.
func syncForRename(f *os.File) error {
	if _, err := unix.FcntlInt(f.Fd(), unix.F_BARRIERFSYNC, 0); err != nil {
		return f.Sync()
	}
	return nil
}

// FlushWrites makes the files materialized under dir durable. F_FULLFSYNC flushes
// the drive's whole cache rather than one file's blocks, so a single call covers
// every file a batch barrier-synced.
func FlushWrites(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
