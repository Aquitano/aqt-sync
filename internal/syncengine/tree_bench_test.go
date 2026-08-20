// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Benchmarks for the per-push full-tree re-seal (issue #231). Every push and every
// prune closure re-runs SealTree over the whole DAG, so these measure that fixed
// cost across the layouts that stress it differently: wide (few, huge nodes), deep
// (many tiny nodes on a long spine), and a mixed tree shaped like a real source
// checkout. The "nodes" metric is the directory-node count, so per-node cost is
// ns/op divided by nodes.

// benchRand returns entry metadata that is deterministic across runs, so every
// benchmark iteration (and every re-run) seals byte-identical trees.
func benchRand() *rand.Rand { return rand.New(rand.NewSource(231)) }

func benchHex(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	rng.Read(b)
	return hex.EncodeToString(b)
}

// benchInline builds pseudo-text: repetitive enough to compress like source code
// rather than defeating zstd with pure noise.
func benchInline(rng *rand.Rand, n int) []byte {
	const line = "func benchLine(x int) int { return x }\n"
	b := make([]byte, n)
	for i := range b {
		b[i] = line[(i+rng.Intn(4))%len(line)]
	}
	return b
}

// benchEntry fabricates a file entry the way a scan would emit it: bytes inline at
// or below the 2 KiB chunker minimum, content-addressed chunk records above it.
func benchEntry(rng *rand.Rand, path string, size int) Entry {
	e := Entry{Path: path, Mode: 0o644, Size: int64(size), Hash: benchHex(rng, 32)}
	if size <= defaultMin {
		e.Inline = benchInline(rng, size)
		return e
	}
	nchunks := (size + defaultNormal - 1) / defaultNormal
	e.Chunks = make([]crypto.Chunk, nchunks)
	for i := range e.Chunks {
		key := make([]byte, crypto.KeySize)
		rng.Read(key)
		e.Chunks[i] = crypto.Chunk{ID: benchHex(rng, 32), Key: key, Len: defaultNormal}
	}
	return e
}

// wideManifest concentrates the metadata in few nodes: dirs directories under the
// root, each holding filesPer chunked files, so node plaintexts are large.
func wideManifest(dirs, filesPer int) Manifest {
	rng := benchRand()
	var m Manifest
	m.Version = TreeManifestVersion
	for d := 0; d < dirs; d++ {
		dir := fmt.Sprintf("dir%04d", d)
		m.Dirs = append(m.Dirs, DirEntry{Path: dir, Mode: 0o755})
		for f := 0; f < filesPer; f++ {
			m.Entries = append(m.Entries, benchEntry(rng, fmt.Sprintf("%s/file%04d.bin", dir, f), 24<<10))
		}
	}
	return m
}

// deepManifest is one chain of depth nested directories with a small file at each
// level: the most nodes per entry a tree can have.
func deepManifest(depth int) Manifest {
	rng := benchRand()
	var m Manifest
	m.Version = TreeManifestVersion
	path := ""
	for d := 0; d < depth; d++ {
		path = joinChild(path, fmt.Sprintf("d%03d", d))
		m.Dirs = append(m.Dirs, DirEntry{Path: path, Mode: 0o755})
		m.Entries = append(m.Entries, benchEntry(rng, path+"/leaf.txt", 512))
	}
	return m
}

// mixedManifest approximates a source checkout: a fanout-ary directory tree of the
// given depth with ~10 files per directory in a realistic size mix — mostly small
// inline files, some chunked, an occasional large one, and a few files big enough
// to push their chunk lists through the sealed-segment indirection.
func mixedManifest(fanout, depth int) Manifest {
	rng := benchRand()
	var m Manifest
	m.Version = TreeManifestVersion
	var fill func(prefix string, level int)
	fill = func(prefix string, level int) {
		nfiles := 6 + rng.Intn(9)
		for f := 0; f < nfiles; f++ {
			size := 200 + rng.Intn(1800) // <= 2 KiB: inline
			switch rng.Intn(20) {
			case 0: // ~5%: a couple hundred KiB
				size = 256 << 10
			case 1, 2, 3, 4, 5, 6: // ~30%: chunked source/asset file
				size = defaultMin + 1 + rng.Intn(60<<10)
			}
			m.Entries = append(m.Entries, benchEntry(rng, joinChild(prefix, fmt.Sprintf("f%02d_%s", f, benchHex(rng, 4))), size))
		}
		if level >= depth {
			return
		}
		for d := 0; d < fanout; d++ {
			sub := joinChild(prefix, fmt.Sprintf("pkg%02d", d))
			m.Dirs = append(m.Dirs, DirEntry{Path: sub, Mode: 0o755})
			fill(sub, level+1)
		}
	}
	fill("", 1)
	// A few files whose chunk lists exceed chunkListInlineMax, so the sealed
	// chunk-list segments are part of the measurement.
	for i := 0; i < 3; i++ {
		m.Entries = append(m.Entries, benchEntry(rng, fmt.Sprintf("big%d.iso", i), (chunkListInlineMax+72)*defaultNormal))
	}
	return m
}

func BenchmarkSealTree(b *testing.B) {
	var conv crypto.ConvergenceKey
	copy(conv[:], []byte("bench-convergence-key-3123123123"))
	layouts := []struct {
		name string
		m    Manifest
	}{
		{"wide", wideManifest(256, 64)},
		{"deep", deepManifest(1024)},
		{"mixed", mixedManifest(4, 6)},
	}
	modes := []struct {
		name string
		memo func() crypto.NodeSealMemo
	}{
		{"cold", func() crypto.NodeSealMemo { return nil }},
		// A warmed in-memory memo: the all-hits ceiling an unchanged re-push pays.
		{"memo", func() crypto.NodeSealMemo { return newCountingMemo() }},
	}
	for _, l := range layouts {
		nodes := len(l.m.Dirs) + 1
		for _, mode := range modes {
			b.Run(fmt.Sprintf("%s/dirs=%d/files=%d/%s", l.name, len(l.m.Dirs), len(l.m.Entries), mode.name), func(b *testing.B) {
				memo := mode.memo()
				if memo != nil {
					if _, _, err := SealTree(l.m, conv, nil, memo); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportAllocs()
				for b.Loop() {
					if _, _, err := SealTree(l.m, conv, nil, memo); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(nodes), "ns/node")
				b.ReportMetric(float64(nodes), "nodes")
			})
		}
	}
}
