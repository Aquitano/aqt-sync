// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package fsatomic

import "os"

// syncDir fsyncs a directory so the rename that just landed in it survives power
// loss. Fsyncing the file alone persists its contents but not the directory entry.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
