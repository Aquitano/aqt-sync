// Package syncengine turns a directory into a sealed, deduplicated manifest and
// reconciles a local tree against a remote one. It owns the on-the-wire shape of
// a tracked folder; the crypto lives in internal/crypto.
package syncengine

import "math"

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
	if !(0 < min && min <= normal && normal <= max) {
		panic("syncengine: chunker sizes must satisfy 0 < min <= normal <= max")
	}
	// Normalized chunking: a stricter mask before the target size makes a cut
	// less likely (pushing chunks toward Normal), a looser one after makes it
	// more likely. Mask width tracks log2(Normal) so the average lands near it.
	const normalization = 2
	bits := uint(math.Round(math.Log2(float64(normal))))
	return &Chunker{
		Min:    min,
		Normal: normal,
		Max:    max,
		maskS:  lowMask(bits + normalization),
		maskL:  lowMask(bits - normalization),
	}
}

// DefaultChunker returns a chunker with the package default sizes.
func DefaultChunker() *Chunker { return NewChunker(defaultMin, defaultNormal, defaultMax) }

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
	for i := 0; i < n; i++ {
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
