package syncengine

import (
	"encoding/json"
	"fmt"
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

	// ChunkProfile names the content-defined chunking granularity: "" or "default"
	// is the source-tree profile (2K/8K/64K, ~8K average); "large" is the big-binary
	// profile (64K/256K/1M, ~256K average), which cuts ~32x fewer chunks per MB and
	// so slashes the per-chunk metadata and server-ingest cost on media/dataset trees
	// at the price of coarser dedup. Ignored when Chunk is set. Because boundaries are
	// derived from these sizes, switching a folder's profile re-chunks it once with no
	// dedup against the old profile — it is a deliberately sticky, per-folder choice.
	ChunkProfile string `json:"chunkProfile"`

	// Chunk overrides the granularity with explicit byte sizes, taking precedence over
	// ChunkProfile. For the rare tree a named profile does not fit; must satisfy
	// 0 < min <= normal <= max.
	Chunk *ChunkSizes `json:"chunk"`

	// Watch configures `aqt watch` for this folder, so a tree can pin its own
	// debounce and guard behavior in-tree (like .aqtignore) rather than per-run.
	Watch WatchConfig `json:"watch"`
}

// ChunkSizes are explicit content-defined chunking bounds in bytes. min doubles as
// the inline cutoff (files this small skip chunking).
type ChunkSizes struct {
	Min    int `json:"min"`
	Normal int `json:"normal"`
	Max    int `json:"max"`
}

// Chunking sizes for the coarse "large" profile: ~32x fewer chunks per MB than the
// default, tuned for trees of large binaries where chunk-level dedup buys little.
const (
	largeMin    = 64 << 10  // 64 KiB
	largeNormal = 256 << 10 // 256 KiB
	largeMax    = 1 << 20   // 1 MiB
)

// namedChunkProfiles maps ChunkProfile to its sizes. "" is treated as "default".
var namedChunkProfiles = map[string]ChunkSizes{
	"":        {defaultMin, defaultNormal, defaultMax},
	"default": {defaultMin, defaultNormal, defaultMax},
	"large":   {largeMin, largeNormal, largeMax},
}

// Chunker builds the content-defined chunker this config selects: an explicit Chunk
// block if present, else the named ChunkProfile, else the default. Unlike NewChunker
// (which panics on a bad ordering — a programmer error) it returns an error, since
// these sizes come from a user-edited config file.
func (c Config) Chunker() (*Chunker, error) {
	sizes, err := c.chunkSizes()
	if err != nil {
		return nil, err
	}
	if !(0 < sizes.Min && sizes.Min <= sizes.Normal && sizes.Normal <= sizes.Max) {
		return nil, fmt.Errorf("invalid chunk sizes in %s: need 0 < min (%d) <= normal (%d) <= max (%d)",
			configFile, sizes.Min, sizes.Normal, sizes.Max)
	}
	return NewChunker(sizes.Min, sizes.Normal, sizes.Max), nil
}

func (c Config) chunkSizes() (ChunkSizes, error) {
	if c.Chunk != nil {
		return *c.Chunk, nil
	}
	sizes, ok := namedChunkProfiles[c.ChunkProfile]
	if !ok {
		return ChunkSizes{}, fmt.Errorf("unknown chunkProfile %q in %s (want \"default\" or \"large\")", c.ChunkProfile, configFile)
	}
	return sizes, nil
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
