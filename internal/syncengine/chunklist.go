// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Indirect chunk lists. A chunk record serializes to ~150 B, so a file's inline
// list grows linearly with its size and a directory node embedding many such lists
// (or a FileRoot naming one huge file) hits the one-object pack cap long before any
// per-file limit does. Above chunkListInlineMax records the list is serialized,
// split into fixed-size segments, and sealed through the convergent pipeline like
// any other object; the node/root then carries the small segment records instead.
// Serialization and splitting are deterministic, so a node's content address stays
// a pure function of the subtree it describes.

const (
	// chunkListInlineMax is the record count above which a chunk list is stored as
	// sealed segments rather than inline. 128 records is ~19 KiB serialized — small
	// enough that a directory of many mid-size files stays well under MaxNodeBytes.
	chunkListInlineMax = 128

	// chunkListSegmentBytes bounds one sealed segment of a serialized list, keeping
	// each segment comfortably below the pack target.
	chunkListSegmentBytes = 4 << 20
)

// sealChunkList serializes chunks, seals it in segments under conv into sink, and
// returns the segment records that recover it.
func sealChunkList(chunks []crypto.Chunk, conv crypto.ConvergenceKey, sink ChunkSink) ([]crypto.Chunk, error) {
	b, err := json.Marshal(chunks)
	if err != nil {
		return nil, err
	}
	var segs []crypto.Chunk
	for off := 0; off < len(b); off += chunkListSegmentBytes {
		end := min(off+chunkListSegmentBytes, len(b))
		ct, ch, err := crypto.SealChunkList(b[off:end], conv)
		if err != nil {
			return nil, err
		}
		if err := sink.Add(ch, ct); err != nil {
			return nil, err
		}
		segs = append(segs, ch)
	}
	return segs, nil
}

// openChunkList fetches and opens each segment by its record, reassembling the
// serialized list and decoding the chunk records.
func openChunkList(segs []crypto.Chunk, fetch func(id string) ([]byte, error)) ([]crypto.Chunk, error) {
	var buf bytes.Buffer
	for _, seg := range segs {
		ct, err := fetch(seg.ID)
		if err != nil {
			return nil, fmt.Errorf("fetch chunk-list segment %s: %w", seg.ID, err)
		}
		plain, err := crypto.OpenChunkList(ct, seg)
		if err != nil {
			return nil, err
		}
		buf.Write(plain)
	}
	var chunks []crypto.Chunk
	if err := json.Unmarshal(buf.Bytes(), &chunks); err != nil {
		return nil, fmt.Errorf("decode chunk list: %w", err)
	}
	return chunks, nil
}
