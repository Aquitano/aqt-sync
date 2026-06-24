package syncengine

import (
	"bytes"
	"testing"
)

// SplitStream must produce byte-identical chunks to Split over the same input, so
// the two are interchangeable for cross-machine dedup.
func TestSplitStreamMatchesSplit(t *testing.T) {
	c := DefaultChunker()
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

func concat(chunks [][]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}
