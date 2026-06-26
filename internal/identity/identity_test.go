package identity

import (
	"os"
	"path/filepath"
	"strings"
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

func TestProfileSaveRoundTripAtomic(t *testing.T) {
	isolateConfigDir(t)

	if err := Save(&Profile{Name: "default", Server: "https://one.example", Token: "tok-1"}); err != nil {
		t.Fatal(err)
	}
	// Overwrite with new content; the file must end up holding the new profile.
	if err := Save(&Profile{Name: "default", Server: "https://two.example", Token: "tok-2"}); err != nil {
		t.Fatal(err)
	}

	got, err := Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != "https://two.example" || got.Token != "tok-2" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "default.json")); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("profile perms = %o, want 600", perm)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".aqt-tmp-") {
			t.Fatalf("leftover temp file after Save: %s", e.Name())
		}
	}
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

func TestSessionCacheIsMachineBound(t *testing.T) {
	isolateConfigDir(t)

	orig := machineSecretFn
	t.Cleanup(func() { machineSecretFn = orig })

	var mk crypto.MasterKey
	for i := range mk {
		mk[i] = byte(i)
	}
	machineSecretFn = func() []byte { return []byte("machine-A") }
	if err := SaveSession("default", mk, time.Hour); err != nil {
		t.Fatal(err)
	}

	// The same file on a different machine (different secret) must not decrypt.
	machineSecretFn = func() []byte { return []byte("machine-B") }
	if _, ok := LoadSession("default"); ok {
		t.Fatal("a session sealed on another machine must not open here")
	}

	// And once it fails to open, the unusable file is removed.
	p, _ := sessionPath("default")
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("an undecryptable session should be removed")
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
