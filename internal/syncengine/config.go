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
