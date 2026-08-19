// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWatch(t *testing.T) {
	t.Parallel()
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

func TestLoadConfigConflicts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"conflicts": "copy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Conflicts != "copy" {
		t.Fatalf("conflicts = %q, want copy", cfg.Conflicts)
	}

	if err := os.WriteFile(filepath.Join(dir, configFile), []byte(`{"conflicts": "merge"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Conflicts != "merge" {
		t.Fatalf("conflicts = %q, want merge", cfg.Conflicts)
	}
}

// A missing .aqtconfig (or an omitted gitGuard) defaults the guard on.
func TestWatchConfigGuardDefaultsOn(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Watch.GitGuardEnabled() {
		t.Fatal("an unset gitGuard must default to enabled")
	}
}

func TestConfigChunkerProfiles(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	bad := []struct {
		name string
		cfg  Config
	}{
		{"unknown profile", Config{ChunkProfile: "gigantic"}},
		{"min above normal", Config{Chunk: &ChunkSizes{Min: 10, Normal: 5, Max: 20}}},
		{"normal above max", Config{Chunk: &ChunkSizes{Min: 1, Normal: 30, Max: 20}}},
		{"zero min", Config{Chunk: &ChunkSizes{Min: 0, Normal: 5, Max: 20}}},
		{"max above pack target", Config{Chunk: &ChunkSizes{Min: 1, Normal: 2, Max: DefaultPackTarget + 1}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.cfg.Chunker(); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// The default size-scaling selector picks a profile from file size at deterministic
// boundaries: the coarser profile takes over exactly at its threshold.
func TestDefaultChunkSelectorBySize(t *testing.T) {
	t.Parallel()
	sel := DefaultChunkSelector()
	cases := []struct {
		name string
		size int64
		want ChunkSizes
	}{
		{"empty", 0, ChunkSizes{defaultMin, defaultNormal, defaultMax}},
		{"just below large", (8 << 20) - 1, ChunkSizes{defaultMin, defaultNormal, defaultMax}},
		{"at large boundary", 8 << 20, ChunkSizes{largeMin, largeNormal, largeMax}},
		{"just below huge", (1 << 30) - 1, ChunkSizes{largeMin, largeNormal, largeMax}},
		{"at huge boundary", 1 << 30, ChunkSizes{hugeMin, hugeNormal, hugeMax}},
		{"far past huge", 64 << 30, ChunkSizes{hugeMin, hugeNormal, hugeMax}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := sel.ChunkerFor(tc.size)
			if ch.Min != tc.want.Min || ch.Normal != tc.want.Normal || ch.Max != tc.want.Max {
				t.Fatalf("size %d -> %d/%d/%d, want %d/%d/%d",
					tc.size, ch.Min, ch.Normal, ch.Max, tc.want.Min, tc.want.Normal, tc.want.Max)
			}
		})
	}
}

// A pinned profile ignores file size; the default config scales; a bad profile errors.
func TestConfigChunkSelectorPinnedVsScaled(t *testing.T) {
	t.Parallel()
	scaled, err := Config{}.ChunkSelector()
	if err != nil {
		t.Fatal(err)
	}
	if scaled.ChunkerFor(0).Normal == scaled.ChunkerFor(1<<30).Normal {
		t.Fatal("default config must scale the chunker with file size")
	}

	pinned, err := Config{ChunkProfile: "large"}.ChunkSelector()
	if err != nil {
		t.Fatal(err)
	}
	if pinned.ChunkerFor(0).Normal != largeNormal || pinned.ChunkerFor(1<<30).Normal != largeNormal {
		t.Fatal("a named profile must pin one granularity for every size")
	}

	explicit, err := Config{Chunk: &ChunkSizes{Min: 1, Normal: 2, Max: 3}}.ChunkSelector()
	if err != nil {
		t.Fatal(err)
	}
	if explicit.ChunkerFor(9<<20).Normal != 2 {
		t.Fatal("an explicit chunk block must pin its sizes regardless of file size")
	}

	if _, err := (Config{ChunkProfile: "gigantic"}).ChunkSelector(); err == nil {
		t.Fatal("an unknown profile must error")
	}
}

// A misspelled or unknown key must fail the load with the file path and the
// field name, not silently fall back to defaults.
func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, configFile)
	if err := os.WriteFile(path, []byte(`{"chunkProfiles": "large"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(dir)
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name the config path %s", err, path)
	}
	if !strings.Contains(err.Error(), "chunkProfiles") {
		t.Fatalf("error %q does not name the offending field", err)
	}
}

func TestParseConfigRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	bad := []struct {
		name string
		body string
	}{
		{"future version", `{"version": 2}`},
		{"bad conflicts", `{"conflicts": "markers"}`},
		{"bad chunk profile", `{"chunkProfile": "gigantic"}`},
		{"bad chunk ordering", `{"chunk": {"min": 10, "normal": 5, "max": 20}}`},
		{"bad watch interval", `{"watch": {"interval": "fast"}}`},
		{"negative watch interval", `{"watch": {"interval": "-2s"}}`},
		{"wrong value type", `{"chunkProfile": 3}`},
		{"trailing data", `{"conflicts": "copy"} {"conflicts": "block"}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tc.body)); err == nil {
				t.Fatalf("ParseConfig(%s): expected an error", tc.body)
			}
		})
	}

	good := []string{
		`{}`,
		`{"version": 1}`,
		`{"chunkProfile": "large", "watch": {"interval": "2s", "gitGuard": false}, "conflicts": "copy"}`,
		`{"conflicts": "merge"}`,
	}
	for _, body := range good {
		if _, err := ParseConfig([]byte(body)); err != nil {
			t.Fatalf("ParseConfig(%s): %v", body, err)
		}
	}
}

// The .aqtconfig example in the folder-sync spec must be accepted by the real
// parser, so the docs cannot drift into showing a config the CLI rejects.
func TestDesignConfigExampleParses(t *testing.T) {
	t.Parallel()
	doc := filepath.Join("..", "..", "docs", "protocol", "folder-sync.md")
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	design := strings.ReplaceAll(string(b), "\r\n", "\n")
	marker := "## `.aqtconfig`"
	i := strings.Index(design, marker)
	if i < 0 {
		t.Fatalf("%s no longer contains the marker %q", doc, marker)
	}
	rest := design[i:]
	start := strings.Index(rest, "```json\n")
	if start < 0 {
		t.Fatalf("no ```json fence after the .aqtconfig marker in %s", doc)
	}
	rest = rest[start+len("```json\n"):]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatalf("unterminated .aqtconfig example fence in %s", doc)
	}
	if _, err := ParseConfig([]byte(rest[:end])); err != nil {
		t.Fatalf("the documented .aqtconfig example is rejected by the parser: %v", err)
	}
}

// The chunkProfile field round-trips from JSON and drives Chunker.
func TestLoadConfigChunkProfile(t *testing.T) {
	t.Parallel()
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
