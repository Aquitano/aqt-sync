// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"math/rand"
	"testing"
)

// deterministicData returns reproducible pseudo-random bytes (seeded, so it does
// not depend on the forbidden global rand source).
func deterministicData(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	r.Read(b)
	return b
}

func TestSplitCoversInputInOrder(t *testing.T) {
	t.Parallel()
	c := testChunker()
	data := deterministicData(1, 200<<10)

	chunks := c.Split(data)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks for %d bytes, got %d", len(data), len(chunks))
	}
	if got := bytes.Join(chunks, nil); !bytes.Equal(got, data) {
		t.Fatal("concatenated chunks must reconstruct the input exactly")
	}
	for i, ch := range chunks {
		last := i == len(chunks)-1
		if !last && (len(ch) < c.Min || len(ch) > c.Max) {
			t.Fatalf("chunk %d size %d out of [%d,%d]", i, len(ch), c.Min, c.Max)
		}
	}
}

func TestSplitIsDeterministic(t *testing.T) {
	t.Parallel()
	c := testChunker()
	data := deterministicData(2, 128<<10)
	a := c.Split(data)
	b := c.Split(data)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic chunk count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("chunk %d differs between runs", i)
		}
	}
}

// Inserting bytes near the front must not re-cut the whole file: most boundaries
// past the edit should be preserved (the point of content-defined chunking).
func TestSplitBoundariesStableUnderInsert(t *testing.T) {
	t.Parallel()
	c := testChunker()
	data := deterministicData(3, 256<<10)
	base := c.Split(data)

	edited := append([]byte("INSERTED PREFIX BYTES"), data...)
	after := c.Split(edited)

	baseSet := map[string]bool{}
	for _, ch := range base {
		baseSet[string(ch)] = true
	}
	shared := 0
	for _, ch := range after {
		if baseSet[string(ch)] {
			shared++
		}
	}
	// A naive fixed-size splitter would share ~0 chunks after a shift; FastCDC
	// should re-sync and share most of them.
	if shared < len(base)/2 {
		t.Fatalf("expected most chunks to survive an insert, shared %d of %d", shared, len(base))
	}
}

func TestSplitSmallInputIsOneChunk(t *testing.T) {
	t.Parallel()
	c := testChunker()
	data := []byte("tiny")
	chunks := c.Split(data)
	if len(chunks) != 1 || !bytes.Equal(chunks[0], data) {
		t.Fatalf("small input should be a single chunk, got %d", len(chunks))
	}
}
