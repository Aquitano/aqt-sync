// Package merge provides the line-oriented diff and three-way merge used by
// folder conflict resolution and the aqt diff command.
package merge

import "bytes"

const (
	// MaxTextSize bounds content materialized in memory for a diff or merge.
	MaxTextSize     = 8 << 20
	binarySniff     = 8 << 10
	maxEditDistance = 2048
)

// Hunk replaces the half-open base line range [Start, End) with Lines.
type Hunk struct {
	Start int
	End   int
	Lines [][]byte
}

// IsText reports whether data is small enough for an in-memory line diff and has
// no NUL byte in its first 8 KiB.
func IsText(data []byte) bool {
	if len(data) > MaxTextSize {
		return false
	}
	n := len(data)
	if n > binarySniff {
		n = binarySniff
	}
	return !bytes.Contains(data[:n], []byte{0})
}

// Eligible reports whether every supplied version can participate in a text merge.
func Eligible(versions ...[]byte) bool {
	for _, version := range versions {
		if !IsText(version) {
			return false
		}
	}
	return true
}

// ThreeWay combines local and remote edits made from base. It returns clean=false
// when edits overlap; callers can then preserve both versions without ever writing
// conflict markers into the primary file.
func ThreeWay(base, local, remote []byte) (result []byte, clean bool) {
	if bytes.Equal(local, remote) {
		return append([]byte(nil), local...), true
	}
	if bytes.Equal(local, base) {
		return append([]byte(nil), remote...), true
	}
	if bytes.Equal(remote, base) {
		return append([]byte(nil), local...), true
	}

	baseLines := splitLines(base)
	localChanges, ok := Changes(base, local)
	if !ok {
		return nil, false
	}
	remoteChanges, ok := Changes(base, remote)
	if !ok {
		return nil, false
	}
	merged := make([]Hunk, 0, len(localChanges)+len(remoteChanges))

	for li, ri := 0, 0; li < len(localChanges) || ri < len(remoteChanges); {
		switch {
		case li == len(localChanges):
			merged = append(merged, remoteChanges[ri])
			ri++
		case ri == len(remoteChanges):
			merged = append(merged, localChanges[li])
			li++
		case strictlyBefore(localChanges[li], remoteChanges[ri]):
			merged = append(merged, localChanges[li])
			li++
		case strictlyBefore(remoteChanges[ri], localChanges[li]):
			merged = append(merged, remoteChanges[ri])
			ri++
		case sameHunk(localChanges[li], remoteChanges[ri]):
			merged = append(merged, localChanges[li])
			li++
			ri++
		default:
			return nil, false
		}
	}

	var out bytes.Buffer
	pos := 0
	for _, h := range merged {
		for _, line := range baseLines[pos:h.Start] {
			out.Write(line)
		}
		for _, line := range h.Lines {
			out.Write(line)
		}
		pos = h.End
	}
	for _, line := range baseLines[pos:] {
		out.Write(line)
	}
	result = out.Bytes()
	if !outputLinesComeFromInputs(result, base, local, remote) {
		return nil, false
	}
	return result, true
}

func outputLinesComeFromInputs(output []byte, inputs ...[]byte) bool {
	known := make(map[string]struct{})
	for _, input := range inputs {
		for _, line := range splitLines(input) {
			known[string(line)] = struct{}{}
		}
	}
	for _, line := range splitLines(output) {
		if _, ok := known[string(line)]; !ok {
			return false
		}
	}
	return true
}

// Changes computes a shortest line edit script with Myers' algorithm and collapses
// it into replacement hunks against base. ok is false when the edit distance is
// too large to compute safely in memory; callers should use their binary/copy fallback.
func Changes(base, other []byte) (hunks []Hunk, ok bool) {
	a, b := splitLines(base), splitLines(other)
	ops, ok := myers(a, b)
	if !ok {
		return nil, false
	}
	var (
		current *Hunk
		basePos int
	)
	flush := func() {
		if current != nil {
			hunks = append(hunks, *current)
			current = nil
		}
	}
	for _, op := range ops {
		switch op.kind {
		case equal:
			flush()
			basePos++
		case deletion:
			if current == nil {
				current = &Hunk{Start: basePos, End: basePos}
			}
			basePos++
			current.End = basePos
		case insertion:
			if current == nil {
				current = &Hunk{Start: basePos, End: basePos}
			}
			current.Lines = append(current.Lines, op.line)
		}
	}
	flush()
	return hunks, true
}

func strictlyBefore(a, b Hunk) bool {
	if a.End < b.Start {
		return true
	}
	if a.End > b.Start {
		return false
	}
	// Adjacent replacements and an insertion at a replacement boundary are clean.
	// Two insertions at the same point compete for ordering and therefore overlap.
	return !(a.Start == a.End && b.Start == b.End)
}

func sameHunk(a, b Hunk) bool {
	if a.Start != b.Start || a.End != b.End || len(a.Lines) != len(b.Lines) {
		return false
	}
	for i := range a.Lines {
		if !bytes.Equal(a.Lines[i], b.Lines[i]) {
			return false
		}
	}
	return true
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n')
		if n < 0 {
			n = len(data) - 1
		}
		n++
		lines = append(lines, data[:n])
		data = data[n:]
	}
	return lines
}

type opKind uint8

const (
	equal opKind = iota
	deletion
	insertion
)

type operation struct {
	kind opKind
	line []byte
}

// myers returns one shortest edit script. It caps edit distance because trace
// storage is quadratic in D even though file byte size is bounded elsewhere.
func myers(a, b [][]byte) ([]operation, bool) {
	max := len(a) + len(b)
	limit := min(max, maxEditDistance)
	offset := limit + 1
	v := make([]int, 2*limit+3)
	v[offset+1] = 0
	trace := make([]frontier, 0, limit+1)
	for d := 0; d <= limit; d++ {
		trace = append(trace, snapshotFrontier(v, offset, d))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1]
			} else {
				x = v[offset+k-1] + 1
			}
			y := x - k
			for x < len(a) && y < len(b) && bytes.Equal(a[x], b[y]) {
				x++
				y++
			}
			v[offset+k] = x
			if x == len(a) && y == len(b) {
				return backtrack(trace, a, b, d), true
			}
		}
	}
	return nil, false
}

type frontier struct {
	minK int
	x    []int
}

func (f frontier) at(k int) int { return f.x[k-f.minK] }

func snapshotFrontier(v []int, offset, distance int) frontier {
	minK, maxK := -distance-1, distance+1
	x := append([]int(nil), v[offset+minK:offset+maxK+1]...)
	return frontier{minK: minK, x: x}
}

func backtrack(trace []frontier, a, b [][]byte, distance int) []operation {
	x, y := len(a), len(b)
	reversed := make([]operation, 0, x+y)
	for d := distance; d > 0; d-- {
		v := trace[d]
		k := x - y
		var prevK int
		if k == -d || (k != d && v.at(k-1) < v.at(k+1)) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := v.at(prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			reversed = append(reversed, operation{kind: equal, line: a[x]})
		}
		if x == prevX {
			y--
			reversed = append(reversed, operation{kind: insertion, line: b[y]})
		} else {
			x--
			reversed = append(reversed, operation{kind: deletion, line: a[x]})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		reversed = append(reversed, operation{kind: equal, line: a[x]})
	}
	for x > 0 {
		x--
		reversed = append(reversed, operation{kind: deletion, line: a[x]})
	}
	for y > 0 {
		y--
		reversed = append(reversed, operation{kind: insertion, line: b[y]})
	}
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return reversed
}
