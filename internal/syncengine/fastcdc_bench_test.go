// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"testing"
)

// Throughput and allocation benchmarks for the streaming chunker across the
// shipped profiles. Random data cuts near Normal (many chunks per window, the
// worst case for per-chunk buffer compaction); zero data is the degenerate
// pattern where the gear hash never varies, so cuts land wherever the fixed
// fingerprint sequence dictates — typically at Max.
func BenchmarkSplitStream(b *testing.B) {
	profiles := []struct {
		name             string
		min, normal, max int
	}{
		{"default", defaultMin, defaultNormal, defaultMax},
		{"large", largeMin, largeNormal, largeMax},
		{"huge", hugeMin, hugeNormal, hugeMax},
	}
	patterns := []struct {
		name string
		data func(n int) []byte
	}{
		{"random", func(n int) []byte { return deterministicData(1, n) }},
		{"zeros", func(n int) []byte { return make([]byte, n) }},
	}
	const size = 32 << 20
	// Materialize each pattern once; the profiles chunk identical bytes.
	inputs := make(map[string][]byte, len(patterns))
	for _, pat := range patterns {
		inputs[pat.name] = pat.data(size)
	}
	for _, p := range profiles {
		c := NewChunker(p.min, p.normal, p.max)
		for _, pat := range patterns {
			data := inputs[pat.name]
			b.Run(p.name+"/"+pat.name, func(b *testing.B) {
				b.SetBytes(size)
				b.ReportAllocs()
				for b.Loop() {
					if err := c.SplitStream(bytes.NewReader(data), func([]byte) error { return nil }); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
