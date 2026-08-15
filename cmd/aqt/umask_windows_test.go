// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import "testing"

const supportsPOSIXPermissions = false

// setUmask is a no-op on Windows, which has no umask; the mode assertions that use
// it reduce to the unfiltered default there.
func setUmask(t *testing.T, mask int) func() {
	t.Helper()
	return func() {}
}
