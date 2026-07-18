package identity

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// TestMain installs the in-memory keychain mock so no test ever reads from or
// writes to the developer's real OS secret store.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

// isolateConfigDir points os.UserConfigDir at a throwaway directory on every
// platform and resets the mock keychain, so the test never touches (or deletes)
// the developer's real cached session and starts from an empty secret store.
// UserConfigDir reads AppData on Windows, XDG_CONFIG_HOME on Linux, and
// $HOME/Library/Application Support on macOS.
func isolateConfigDir(t *testing.T) {
	t.Helper()
	keyring.MockInit() // fresh in-memory store per test
	dir := t.TempDir()
	t.Setenv("AppData", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
}

// forceNoKeychain simulates a host with no keychain backend, so the code under
// test falls back to the machine-bound file path.
func forceNoKeychain(t *testing.T) {
	t.Helper()
	unavailable := errors.New("keychain unavailable")
	g, s, d := keyringGet, keyringSet, keyringDelete
	keyringGet = func(string, string) (string, error) { return "", unavailable }
	keyringSet = func(string, string, string) error { return unavailable }
	keyringDelete = func(string, string) error { return unavailable }
	t.Cleanup(func() { keyringGet, keyringSet, keyringDelete = g, s, d })
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
	// File mode bits are a Unix concept; Windows reports 0666 for a writable file.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, "default.json")); err != nil {
			t.Fatal(err)
		} else if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("profile perms = %o, want 600", perm)
		}
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

func TestProfileRoundTripPreservesFingerprint(t *testing.T) {
	isolateConfigDir(t)

	want := &Profile{Email: "a@example.com", DeviceID: "dev1", Fingerprint: "SHA256:abc123"}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != want.Fingerprint {
		t.Fatalf("fingerprint not preserved: got %q want %q", got.Fingerprint, want.Fingerprint)
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
	forceNoKeychain(t) // exercise the machine-bound fallback, not the keychain seal

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

func TestSessionSealedByKeychainKey(t *testing.T) {
	isolateConfigDir(t) // mock keychain is available

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

	// With a keychain present the seal is bound to the random keychain key, not the
	// machine secret, so changing the machine secret must NOT prevent opening it.
	machineSecretFn = func() []byte { return []byte("machine-B") }
	got, ok := LoadSession("default")
	if !ok || got != mk {
		t.Fatalf("keychain-sealed session should open regardless of machine secret: ok=%v", ok)
	}

	// Clearing the session drops the keychain key, so a stale file cannot reopen.
	if err := ClearSession("default"); err != nil {
		t.Fatal(err)
	}
	if _, ok := keychainSealingKey("default", false); ok {
		t.Fatal("ClearSession should drop the keychain sealing key")
	}
}

func TestTokenMovedToKeychain(t *testing.T) {
	isolateConfigDir(t) // mock keychain is available

	if err := Save(&Profile{Name: "default", Server: "https://x.example", Token: "tok-secret"}); err != nil {
		t.Fatal(err)
	}

	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "tok-secret") {
		t.Fatalf("token must not be written to the profile file when a keychain is present: %s", raw)
	}

	got, err := Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok-secret" {
		t.Fatalf("token not recovered from keychain: %q", got.Token)
	}
}

func TestTokenStaysInFileWithoutKeychain(t *testing.T) {
	isolateConfigDir(t)
	forceNoKeychain(t)

	if err := Save(&Profile{Name: "default", Token: "tok-file"}); err != nil {
		t.Fatal(err)
	}
	dir, err := configDir()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "tok-file") {
		t.Fatal("without a keychain the token must remain in the 0600 file")
	}
	got, err := Load("default")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok-file" {
		t.Fatalf("token round-trip without keychain failed: %q", got.Token)
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

func TestDeleteRemovesProfileTokenAndSession(t *testing.T) {
	isolateConfigDir(t)
	p := &Profile{Name: "default", Server: "https://x.example", Email: "u.com", Token: "tok-secret"}
	if err := Save(p); err != nil {
		t.Fatal(err)
	}
	var mk crypto.MasterKey
	if err := SaveSession("default", mk, 0); err != nil {
		t.Fatal(err)
	}
	if err := SaveSession("default", mk, -time.Second); err == nil {
		t.Fatal("negative TTL was accepted")
	}
	if err := Delete("default"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("default"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("profile still loads: %v", err)
	}
	if _, ok := LoadSession("default"); ok {
		t.Fatal("session survived delete")
	}
	if token, ok := keychainLoadToken("default"); ok || token != "" {
		t.Fatal("keychain token survived delete")
	}
}
