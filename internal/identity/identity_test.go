package identity

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

func TestSessionCacheRoundTrip(t *testing.T) {
	t.Setenv("AppData", t.TempDir()) // isolate the config dir (Windows UserConfigDir)

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
	t.Setenv("AppData", t.TempDir())

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
