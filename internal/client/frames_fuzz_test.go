// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzParsePublicFrames feeds arbitrary bodies to the share-link object framing,
// which a hostile server controls. Accepted output must be exactly want frames, each
// non-empty and within maxPublicFrame, laid out back to back in the body.
func FuzzParsePublicFrames(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 'h', 'i'}, uint8(1))
	f.Add([]byte{0, 0, 0, 1, 'a', 0, 0, 0, 1, 'b'}, uint8(2))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}, uint8(1))
	f.Add([]byte{0, 0, 0, 0}, uint8(1))
	f.Fuzz(func(t *testing.T, data []byte, want uint8) {
		frames, err := parsePublicFrames(data, int(want))
		if err != nil {
			return
		}
		if len(frames) != int(want) {
			t.Fatalf("got %d frames, want %d", len(frames), want)
		}
		off := 0
		for i, fr := range frames {
			n := int(binary.BigEndian.Uint32(data[off:]))
			if n == 0 || n > maxPublicFrame || n != len(fr) || !bytes.Equal(fr, data[off+4:off+4+n]) {
				t.Fatalf("frame %d (%d bytes) does not match its length prefix %d at offset %d", i, len(fr), n, off)
			}
			off += 4 + n
		}
	})
}
