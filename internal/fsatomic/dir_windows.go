// SPDX-License-Identifier: AGPL-3.0-or-later

package fsatomic

// syncDir is a no-op on Windows: directory handles cannot be fsynced, and rename
// durability is left to the filesystem.
func syncDir(string) error { return nil }
