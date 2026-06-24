package syncengine

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds per-folder sync options read from .aqtconfig (JSON). The zero
// value — no file present — is the default: chunked sync with per-account dedup.
type Config struct {
	// Pack selects pack-and-seal: the whole tree is tarred into one sealed blob
	// rather than chunked. Simpler and leaks no structure, but loses chunk-level
	// dedup, so any change re-ships the entire folder. Default false.
	Pack bool `json:"pack"`

	// Watch configures `aqt watch` for this folder, so a tree can pin its own
	// debounce and guard behavior in-tree (like .aqtignore) rather than per-run.
	Watch WatchConfig `json:"watch"`
}

// WatchConfig holds the per-folder watch-daemon options. CLI flags override it.
type WatchConfig struct {
	// Interval is the debounce floor as a Go duration string ("2s", "1m30s").
	// Empty means the built-in default; `--interval` overrides it.
	Interval string `json:"interval"`

	// GitGuard holds a push back while any sub-repo is mid git operation. It is a
	// pointer so an omitted field reads as the default (enabled); set it to false
	// to let the daemon sync regardless of git state.
	GitGuard *bool `json:"gitGuard"`
}

// GitGuardEnabled reports whether the git-lock guard is on, defaulting to true
// when .aqtconfig does not set it.
func (w WatchConfig) GitGuardEnabled() bool {
	return w.GitGuard == nil || *w.GitGuard
}

// LoadConfig reads dir/.aqtconfig; a missing file yields the default Config.
func LoadConfig(dir string) (Config, error) {
	var c Config
	b, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}
