// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin

package syncengine

import "os"

// syncForRename makes a temp file's data durable before the rename that publishes
// it, so a crash leaves the old file or the new one, never a torn mix.
func syncForRename(f *os.File) error { return f.Sync() }

// FlushWrites is a no-op here: syncForRename already made each file's data durable.
func FlushWrites(string) error { return nil }
