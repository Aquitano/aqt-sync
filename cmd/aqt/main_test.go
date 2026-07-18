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
	// A sub-second TTL truncates to 0 seconds on disk, which means "no expiry" --
	// the opposite of the caller's intent, so it must be rejected.
	if err := validateSessionTTL(500 * time.Millisecond); err == nil {
		t.Fatal("sub-second login TTL was accepted")
	}
	if err := validateSessionTTL(0); err != nil {
		t.Fatalf("zero TTL (no expiry) must be valid: %v", err)
	}
	if err := validateSessionTTL(time.Second); err != nil {
		t.Fatalf("1s TTL must be valid: %v", err)
	}
}
