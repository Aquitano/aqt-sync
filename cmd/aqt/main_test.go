package main

import (
	"os"
	"testing"
	"time"
)

// TestMain forces the keychain off for the e2e suite so it exercises the
// machine-bound file fallback and never reaches the real OS keychain — which on a
// locked CI keychain (notably headless macOS) would block the `security` call.
// The node cache is pointed at a throwaway directory so tests never read or write
// the developer's real cache (t.Setenv in individual tests still overrides it).
func TestMain(m *testing.M) {
	os.Setenv("AQT_NO_KEYCHAIN", "1")
	cacheDir, err := os.MkdirTemp("", "aqt-test-nodecache-*")
	if err == nil {
		os.Setenv("AQT_NODE_CACHE_DIR", cacheDir)
	}
	code := m.Run()
	if err == nil {
		os.RemoveAll(cacheDir)
	}
	os.Exit(code)
}

func TestAccountLifecycleCommandsAreExplicit(t *testing.T) {
	root := rootCmd()
	for _, name := range []string{"signup", "login", "lock", "logout"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil || cmd == root || cmd.Name() != name {
			t.Fatalf("command %q missing: %v", name, err)
		}
	}
	if err := validateSessionTTL(-time.Second); err == nil {
		t.Fatal("negative login TTL was accepted")
	}
}
