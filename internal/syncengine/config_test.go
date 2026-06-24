package syncengine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigWatch(t *testing.T) {
	dir := t.TempDir()
	body := `{"watch": {"interval": "7s", "gitGuard": false}}`
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Watch.Interval != "7s" {
		t.Fatalf("interval = %q, want 7s", cfg.Watch.Interval)
	}
	if cfg.Watch.GitGuardEnabled() {
		t.Fatal("gitGuard:false must disable the guard")
	}
}

// A missing .aqtconfig (or an omitted gitGuard) defaults the guard on.
func TestWatchConfigGuardDefaultsOn(t *testing.T) {
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Watch.GitGuardEnabled() {
		t.Fatal("an unset gitGuard must default to enabled")
	}
}
