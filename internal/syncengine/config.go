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

	// ChunkProfile pins one content-defined chunking granularity for every file in the
	// folder, overriding the default size-scaling. "large" is the big-binary profile
	// (64K/256K/1M, ~256K average) and "huge" the coarsest (256K/1M/4M, ~1M average);
	// both cut far fewer chunks per MB than the source-tree default, slashing per-chunk
	// metadata and server-ingest cost on media/dataset trees at the price of coarser
	// dedup. "" or "default" leaves the size-scaling on (see ChunkSelector). Ignored
	// when Chunk is set. Because boundaries are derived from these sizes, changing a
	// folder's profile re-chunks it once with no dedup against the old profile — it is
	// a deliberately sticky, per-folder choice.
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

// Chunking sizes for the "huge" profile: ~1 MiB average, for multi-GB files where
// even the large profile would mint hundreds of thousands of chunk records.
const (
	hugeMin    = 256 << 10 // 256 KiB
	hugeNormal = 1 << 20   // 1 MiB
	hugeMax    = 4 << 20   // 4 MiB
)

// namedChunkProfiles maps ChunkProfile to its sizes. "" is treated as "default".
var namedChunkProfiles = map[string]ChunkSizes{
	"":        {defaultMin, defaultNormal, defaultMax},
	"default": {defaultMin, defaultNormal, defaultMax},
	"large":   {largeMin, largeNormal, largeMax},
	"huge":    {hugeMin, hugeNormal, hugeMax},
}

// sizeScaledTiers is the default (unpinned) chunking ladder: a file is cut with the
// coarsest profile whose size threshold it clears. At the 8K default a 1 GiB file
// mints ~130k chunk records, each costing an AEAD tag, a manifest entry, a pack-index
// entry, and a DB row (~4-5% metadata overhead), and drives the node/FileRoot size
// ceilings; scaling large files to 256K-1M chunks cuts that by 1-2 orders of
// magnitude while small files keep byte-level dedup. Ascending by minSize.
var sizeScaledTiers = []struct {
	minSize int64
	sizes   ChunkSizes
}{
	{0, ChunkSizes{defaultMin, defaultNormal, defaultMax}}, // <= 8 MiB: ~8 KiB average
	{8 << 20, ChunkSizes{largeMin, largeNormal, largeMax}}, // > 8 MiB: ~256 KiB average
	{1 << 30, ChunkSizes{hugeMin, hugeNormal, hugeMax}},    // > 1 GiB: ~1 MiB average
}

// scaledSelector chooses a Chunker by file size from a size ladder. Each Chunker is
// built once and reused across files, since a Chunker is stateless between calls.
type scaledSelector struct {
	minSizes []int64
	chunkers []*Chunker
}

func newScaledSelector() scaledSelector {
	s := scaledSelector{
		minSizes: make([]int64, len(sizeScaledTiers)),
		chunkers: make([]*Chunker, len(sizeScaledTiers)),
	}
	for i, t := range sizeScaledTiers {
		s.minSizes[i] = t.minSize
		s.chunkers[i] = NewChunker(t.sizes.Min, t.sizes.Normal, t.sizes.Max)
	}
	return s
}

// ChunkerFor returns the coarsest tier whose threshold size does not exceed size.
func (s scaledSelector) ChunkerFor(size int64) *Chunker {
	c := s.chunkers[0]
	for i, min := range s.minSizes {
		if size < min {
			break
		}
		c = s.chunkers[i]
	}
	return c
}

// DefaultChunkSelector returns the size-scaling selector a folder uses when its
// config pins no granularity — also the right choice for a standalone streamed file.
func DefaultChunkSelector() ChunkSelector { return newScaledSelector() }

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
	// Cap max so a mistyped size is a returned error, not an OOM: the chunker reserves
	// a ~2*max window, and a chunk larger than one pack's target is meaningless anyway.
	if sizes.Max > DefaultPackTarget {
		return nil, fmt.Errorf("invalid chunk sizes in %s: max (%d) exceeds the pack target %d; a chunk must fit in one pack",
			configFile, sizes.Max, DefaultPackTarget)
	}
	return NewChunker(sizes.Min, sizes.Normal, sizes.Max), nil
}

// ChunkSelector builds the per-file chunker chooser this config selects. An explicit
// Chunk block or a named ChunkProfile pins one granularity for every file (a sticky
// per-folder choice, since boundaries derive from the sizes). The default — no chunk
// config — scales the chunker with file size (see sizeScaledTiers) so a large file is
// not shredded into millions of tiny records.
func (c Config) ChunkSelector() (ChunkSelector, error) {
	if c.Chunk != nil || (c.ChunkProfile != "" && c.ChunkProfile != "default") {
		ch, err := c.Chunker()
		if err != nil {
			return nil, err
		}
		return ch, nil
	}
	return newScaledSelector(), nil
}

func (c Config) chunkSizes() (ChunkSizes, error) {
	if c.Chunk != nil {
		return *c.Chunk, nil
	}
	sizes, ok := namedChunkProfiles[c.ChunkProfile]
	if !ok {
		return ChunkSizes{}, fmt.Errorf("unknown chunkProfile %q in %s (want \"default\", \"large\", or \"huge\")", c.ChunkProfile, configFile)
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
