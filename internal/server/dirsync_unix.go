//go:build !windows

package server

import "os"

// fsyncDir flushes a directory's entries to disk so a freshly created or renamed file
// in it survives a power loss. Without it the file's data can be durable while the
// directory entry naming it is not (ext4 writeback, XFS, btrfs), leaving a committed
// DB row pointing at a pack or blob the kernel later loses.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
