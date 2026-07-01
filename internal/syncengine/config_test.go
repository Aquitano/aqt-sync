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

func TestConfigChunkerProfiles(t *testing.T) {
	cases := []struct {
		name                         string
		cfg                          Config
		wantMin, wantNormal, wantMax int
	}{
		{"zero value defaults", Config{}, defaultMin, defaultNormal, defaultMax},
		{"named default", Config{ChunkProfile: "default"}, defaultMin, defaultNormal, defaultMax},
		{"named large", Config{ChunkProfile: "large"}, largeMin, largeNormal, largeMax},
		{"explicit overrides profile", Config{ChunkProfile: "large", Chunk: &ChunkSizes{Min: 1, Normal: 2, Max: 3}}, 1, 2, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := tc.cfg.Chunker()
			if err != nil {
				t.Fatalf("Chunker(): %v", err)
			}
			if ch.Min != tc.wantMin || ch.Normal != tc.wantNormal || ch.Max != tc.wantMax {
				t.Fatalf("sizes = %d/%d/%d, want %d/%d/%d", ch.Min, ch.Normal, ch.Max, tc.wantMin, tc.wantNormal, tc.wantMax)
			}
		})
	}
}

func TestConfigChunkerRejectsBadConfig(t *testing.T) {
	bad := []struct {
		name string
		cfg  Config
	}{
		{"unknown profile", Config{ChunkProfile: "huge"}},
		{"min above normal", Config{Chunk: &ChunkSizes{Min: 10, Normal: 5, Max: 20}}},
		{"normal above max", Config{Chunk: &ChunkSizes{Min: 1, Normal: 30, Max: 20}}},
		{"zero min", Config{Chunk: &ChunkSizes{Min: 0, Normal: 5, Max: 20}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.cfg.Chunker(); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// The chunkProfile field round-trips from JSON and drives Chunker.
func TestLoadConfigChunkProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"chunkProfile": "large"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := cfg.Chunker()
	if err != nil {
		t.Fatal(err)
	}
	if ch.Normal != largeNormal {
		t.Fatalf("normal = %d, want %d (large profile)", ch.Normal, largeNormal)
	}
}
