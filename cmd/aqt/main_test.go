package main

import (
	"os"
	"testing"
)

// TestMain forces the keychain off for the e2e suite so it exercises the
// machine-bound file fallback and never reaches the real OS keychain — which on a
// locked CI keychain (notably headless macOS) would block the `security` call.
func TestMain(m *testing.M) {
	os.Setenv("AQT_NO_KEYCHAIN", "1")
	os.Exit(m.Run())
}
