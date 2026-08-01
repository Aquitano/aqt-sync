package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain forces the keychain off for the e2e suite so it exercises the
// machine-bound file fallback and never reaches the real OS keychain — which on a
// locked CI keychain (notably headless macOS) would block the `security` call.
// Config and node-cache paths are pointed at a throwaway directory so tests never
// read or write the developer's real profiles, sessions, contacts, or cache. Keep
// all three UserConfigDir inputs set: Windows reads AppData, Linux reads
// XDG_CONFIG_HOME, and macOS derives its path from HOME.
func TestMain(m *testing.M) {
	os.Setenv("AQT_NO_KEYCHAIN", "1")
	testRoot, err := os.MkdirTemp("", "aqt-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create isolated test root: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("AppData", testRoot)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(testRoot, ".config"))
	os.Setenv("HOME", testRoot)
	os.Setenv("AQT_NODE_CACHE_DIR", filepath.Join(testRoot, "nodecache"))
	code := m.Run()
	os.RemoveAll(testRoot)
	os.Exit(code)
}

// isolateConfigEnv points os.UserConfigDir at base on every supported platform.
// Tests that need to switch identities mid-test must also switch AppData on Windows.
func isolateConfigEnv(t *testing.T, base string) {
	t.Helper()
	t.Setenv("AppData", base)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, ".config"))
	t.Setenv("HOME", base)
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
