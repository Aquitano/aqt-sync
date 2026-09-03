// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syncengine turns a directory into a sealed, deduplicated manifest and
// reconciles a local tree against a remote one. It owns the on-the-wire shape of
// a tracked folder; the crypto lives in internal/crypto.
package syncengine

import (
	"io"
	"math"
	"sync"
)

// Chunker splits a byte stream at content-defined boundaries using FastCDC
// (Xia et al., 2016). Boundaries depend only on a bounded window of preceding
// bytes, so inserting or deleting data shifts only the boundaries near the edit
// rather than re-cutting the whole file — which is what makes incremental dedup
// effective.
type Chunker struct {
	Min    int // shortest chunk; also the inline cutoff (files this small skip chunking)
	Normal int // target average chunk size
	Max    int // longest chunk
	maskS  uint64
	maskL  uint64
	bufs   *sync.Pool // *[]byte window (cap 2*Max), reused across SplitStream calls to cut per-file allocation
}

// Default chunker sizes. Small files inline below Min, so these only govern the
// granularity of larger files; tuned for source trees rather than media.
const (
	defaultMin    = 2 << 10  // 2 KiB
	defaultNormal = 8 << 10  // 8 KiB
	defaultMax    = 64 << 10 // 64 KiB
)

// NewChunker builds a chunker with explicit sizes. It panics on a nonsensical
// ordering, since those are programmer errors, not runtime conditions.
func NewChunker(min, normal, max int) *Chunker {
	//nolint:staticcheck // QF1001: the negated ordering chain states the invariant; its De Morgan expansion does not.
	if !(0 < min && min <= normal && normal <= max) {
		panic("syncengine: chunker sizes must satisfy 0 < min <= normal <= max")
	}
	// Normalized chunking: a stricter mask before the target size makes a cut
	// less likely (pushing chunks toward Normal), a looser one after makes it
	// more likely. Mask width tracks log2(Normal) so the average lands near it.
	const normalization = 2
	bits := uint(math.Round(math.Log2(float64(normal))))
	c := &Chunker{
		Min:    min,
		Normal: normal,
		Max:    max,
		maskS:  lowMask(bits + normalization),
		maskL:  lowMask(bits - normalization),
	}
	c.bufs = &sync.Pool{New: func() any {
		b := make([]byte, 0, 2*max)
		return &b
	}}
	return c
}

// ChunkSelector picks the chunking granularity for a file from its size. A single
// *Chunker satisfies it (size-independent), so callers that want one fixed
// granularity pass a Chunker directly; Config builds a size-scaling selector so a
// large file is cut into coarse chunks while small files keep the fine default.
type ChunkSelector interface {
	ChunkerFor(size int64) *Chunker
}

// ChunkerFor lets a fixed Chunker stand in wherever a ChunkSelector is expected.
func (c *Chunker) ChunkerFor(int64) *Chunker { return c }

func lowMask(bits uint) uint64 { return (uint64(1) << bits) - 1 }

// Split cuts data into content-defined chunks covering it in order.
func (c *Chunker) Split(data []byte) [][]byte {
	var chunks [][]byte
	for len(data) > 0 {
		n := c.nextCut(data)
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	return chunks
}

// SplitStream chunks an io.Reader without ever buffering more than ~Max bytes,
// calling emit once per chunk in order. A FastCDC boundary depends only on the
// bytes preceding it, so a boundary found within a buffered window of at least Max
// bytes is final regardless of what follows — which is what lets the stream be cut
// with bounded memory. The cuts are identical to Split over the same bytes, so the
// two are interchangeable for dedup.
//
// The slice passed to emit is only valid for the duration of the call; the backing
// buffer is reused once emit returns, so an implementation that retains the bytes
// must copy them (crypto.SealChunk produces an independent ciphertext, so the
// common seal-then-pack caller needs no copy).
func (c *Chunker) SplitStream(r io.Reader, emit func(chunk []byte) error) error {
	wp := c.bufs.Get().(*[]byte)
	defer c.bufs.Put(wp)
	// buf is only ever re-sliced within the pooled array's capacity — never
	// appended past it — so Put returns the same array and the pool actually
	// reuses it. The loop guard guarantees the read slice below is non-empty:
	// compaction leaves len < Max with cap 2*Max, and a full buffer with
	// start == 0 means a >= Max window, which exits the refill loop instead.
	buf := (*wp)[:0]
	start := 0 // window of unconsumed bytes is buf[start:]
	eof := false
	for {
		// Top the window up to at least Max bytes (or EOF) before cutting, so the
		// boundary search sees the same window Split would and the cuts agree.
		// Reads land directly in the buffer's spare capacity; the window only
		// slides back to the front once that capacity is exhausted, which with
		// cap 2*Max amortizes to one sub-Max copy per Max bytes consumed rather
		// than one per chunk.
		for !eof && len(buf)-start < c.Max {
			if len(buf) == cap(buf) {
				buf = buf[:copy(buf, buf[start:])]
				start = 0
			}
			n, err := r.Read(buf[len(buf):cap(buf)])
			if n > 0 { // guard a contract-violating negative n from corrupting the window
				buf = buf[:len(buf)+n]
			}
			if err == io.EOF {
				eof = true
			} else if err != nil {
				return err
			}
		}
		window := buf[start:]
		if len(window) == 0 {
			return nil
		}
		n := c.nextCut(window)
		if err := emit(window[:n]); err != nil {
			return err
		}
		start += n
	}
}

// nextCut returns the length of the next chunk at the front of data.
func (c *Chunker) nextCut(data []byte) int {
	n := len(data)
	if n <= c.Min {
		return n
	}
	if n > c.Max {
		n = c.Max
	}
	var fp uint64
	for i := range n {
		fp = (fp << 1) + gear[data[i]]
		length := i + 1
		if length < c.Min {
			continue
		}
		mask := c.maskL
		if length <= c.Normal {
			mask = c.maskS
		}
		if fp&mask == 0 {
			return length
		}
	}
	return n
}

// gear is the FastCDC gear hash table: one pseudo-random 64-bit value per byte.
// It is generated deterministically (fixed seed) so chunk boundaries are
// identical on every machine — a prerequisite for cross-machine dedup.
var gear = func() [256]uint64 {
	var t [256]uint64
	x := uint64(0x9e3779b97f4a7c15)
	for i := range t {
		// splitmix64
		x += 0x9e3779b97f4a7c15
		z := x
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		t[i] = z ^ (z >> 31)
	}
	return t
}()
