// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// SplitStream must produce byte-identical chunks to Split over the same input, so
// the two are interchangeable for cross-machine dedup.
func TestSplitStreamMatchesSplit(t *testing.T) {
	t.Parallel()
	c := testChunker()
	for _, n := range []int{0, 1, c.Min, c.Min + 1, c.Max, c.Max + 7, 200 << 10, 333333} {
		data := deterministicData(int64(n+1), n)
		want := c.Split(data)

		var got [][]byte
		if err := c.SplitStream(bytes.NewReader(data), func(ch []byte) error {
			got = append(got, append([]byte(nil), ch...))
			return nil
		}); err != nil {
			t.Fatalf("n=%d SplitStream: %v", n, err)
		}
		if len(got) != len(want) {
			t.Fatalf("n=%d chunk count: stream=%d split=%d", n, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("n=%d chunk %d differs between Split and SplitStream", n, i)
			}
		}
		if joined := concat(got); !bytes.Equal(joined, data) {
			t.Fatalf("n=%d stream chunks do not reconstruct input", n)
		}
	}
}

// shortReader hands out at most step bytes per Read, forcing many partial reads
// per refill. bytes.Reader tops the window up in a single call, so only this
// reader exercises the incremental-fill path (compaction fires either way).
type shortReader struct {
	data []byte
	step int
}

func (s *shortReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		// A zero-length read slice would loop forever; fail loudly instead so a
		// regression surfaces as a named error, not a test timeout.
		return 0, errors.New("zero-length read slice")
	}
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := s.step
	if n > len(s.data) {
		n = len(s.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, s.data[:n])
	s.data = s.data[n:]
	return n, nil
}

func TestSplitStreamShortReadsMatchSplit(t *testing.T) {
	t.Parallel()
	c := testChunker()
	data := deterministicData(7, 333333)
	want := c.Split(data)
	for _, step := range []int{1, 977, c.Min, c.Max} {
		var got [][]byte
		if err := c.SplitStream(&shortReader{data: data, step: step}, func(ch []byte) error {
			got = append(got, append([]byte(nil), ch...))
			return nil
		}); err != nil {
			t.Fatalf("step=%d SplitStream: %v", step, err)
		}
		if len(got) != len(want) {
			t.Fatalf("step=%d chunk count: stream=%d split=%d", step, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("step=%d chunk %d differs between Split and SplitStream", step, i)
			}
		}
	}
}

func concat(chunks [][]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
