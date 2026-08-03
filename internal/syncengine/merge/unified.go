package merge

import (
	"bytes"
	"fmt"
)

const unifiedContext = 3

// Unified renders a standard unified diff with three context lines. Equal input
// returns nil so callers can concatenate file diffs directly.
func Unified(oldName, newName string, oldData, newData []byte) []byte {
	if bytes.Equal(oldData, newData) {
		return nil
	}
	ops, ok := myers(splitLines(oldData), splitLines(newData))
	if !ok {
		return fmt.Appendf(nil, "Binary files %s and %s differ\n", oldName, newName)
	}
	ranges := unifiedRanges(ops, unifiedContext)
	var out bytes.Buffer
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", oldName, newName)
	oldBefore, newBefore := prefixPositions(ops)
	for _, r := range ranges {
		oldCount, newCount := 0, 0
		for _, op := range ops[r.start:r.end] {
			if op.kind != insertion {
				oldCount++
			}
			if op.kind != deletion {
				newCount++
			}
		}
		oldStart := rangeStart(oldBefore[r.start], oldCount)
		newStart := rangeStart(newBefore[r.start], newCount)
		fmt.Fprintf(&out, "@@ -%s +%s @@\n", rangeLabel(oldStart, oldCount), rangeLabel(newStart, newCount))
		for _, op := range ops[r.start:r.end] {
			prefix := byte(' ')
			switch op.kind {
			case deletion:
				prefix = '-'
			case insertion:
				prefix = '+'
			}
			writeUnifiedLine(&out, prefix, op.line)
		}
	}
	return out.Bytes()
}

type opRange struct{ start, end int }

func unifiedRanges(ops []operation, context int) []opRange {
	var ranges []opRange
	for i, op := range ops {
		if op.kind == equal {
			continue
		}
		start := i
		for n, j := 0, i-1; j >= 0 && n < context; j-- {
			start = j
			if ops[j].kind == equal {
				n++
			}
		}
		end := i + 1
		for n := 0; end < len(ops) && n < context; end++ {
			if ops[end].kind == equal {
				n++
			}
		}
		if len(ranges) > 0 && start <= ranges[len(ranges)-1].end {
			if end > ranges[len(ranges)-1].end {
				ranges[len(ranges)-1].end = end
			}
		} else {
			ranges = append(ranges, opRange{start: start, end: end})
		}
	}
	return ranges
}

func prefixPositions(ops []operation) (oldPos, newPos []int) {
	oldPos = make([]int, len(ops)+1)
	newPos = make([]int, len(ops)+1)
	for i, op := range ops {
		oldPos[i+1], newPos[i+1] = oldPos[i], newPos[i]
		if op.kind != insertion {
			oldPos[i+1]++
		}
		if op.kind != deletion {
			newPos[i+1]++
		}
	}
	return oldPos, newPos
}

func rangeStart(before, count int) int {
	if count == 0 {
		return before
	}
	return before + 1
}

func rangeLabel(start, count int) string {
	if count == 1 {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}

func writeUnifiedLine(out *bytes.Buffer, prefix byte, line []byte) {
	out.WriteByte(prefix)
	out.Write(line)
	if len(line) == 0 || line[len(line)-1] != '\n' {
		out.WriteByte('\n')
		out.WriteString("\\ No newline at end of file\n")
	}
}
