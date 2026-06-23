package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// isolateConfigDir points os.UserConfigDir at a throwaway directory on every
// platform, so the test never touches (or deletes) the developer's real cached
// session. UserConfigDir reads AppData on Windows, XDG_CONFIG_HOME on Linux, and
// $HOME/Library/Application Support on macOS.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
}

func TestSessionCacheRoundTrip(t *testing.T) {
	isolateConfigDir(t)

	var mk crypto.MasterKey
	for i := range mk {
		mk[i] = byte(i)
	}

	if _, ok := LoadSession("default"); ok {
		t.Fatal("expected no cached session initially")
	}
	if err := SaveSession("default", mk, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadSession("default")
	if !ok || got != mk {
		t.Fatalf("roundtrip mismatch: ok=%v", ok)
	}
	if err := ClearSession("default"); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSession("default"); ok {
		t.Fatal("expected a miss after ClearSession")
	}
}

func TestSessionCacheRejectsMalformed(t *testing.T) {
	isolateConfigDir(t)

	p, err := sessionPath("default")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	// A key of the wrong length must be treated as a miss and removed.
	if err := os.WriteFile(p, []byte(`{"masterKey":"YWJj","expiresAt":0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadSession("default"); ok {
		t.Fatal("malformed session must be a miss")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("malformed session should be removed")
	}
}
