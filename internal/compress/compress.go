// SPDX-License-Identifier: AGPL-3.0-or-later

// Package compress is aqt's single compression codec. Convergent chunk ids
// depend on the compressor's exact output, so the codec is pinned: klauspost's
// pure-Go zstd at SpeedDefault, CRC off (the AEAD tag already authenticates).
// Changing the library, version, or level only degrades dedup for re-sealed
// data — old ids stop matching new output — never correctness, because every
// payload records the algorithm it was sealed with.
package compress

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// Zstd marks a zstd-compressed payload; an empty marker means raw.
const Zstd = "zstd"

// maxDecoded caps decoder output when the caller cannot pin the exact raw
// length. Sealed payloads are AEAD-authenticated before they reach the
// decoder, so this is a sanity bound, not a security boundary.
const maxDecoded = 1 << 30

// Shared coders for the one-shot EncodeAll/DecodeAll calls, which are safe for
// concurrent use; each call runs on a single goroutine, so the concurrency
// setting sizes the state pool without affecting output.
var (
	encoder *zstd.Encoder
	decoder *zstd.Decoder
)

func init() {
	var err error
	encoder, err = zstd.NewWriter(nil, encoderOpts(runtime.GOMAXPROCS(0))...)
	if err == nil {
		decoder, err = zstd.NewReader(nil, decoderOpts()...)
	}
	if err != nil {
		panic("compress init: " + err.Error()) // static options; unreachable
	}
}

func encoderOpts(concurrency int) []zstd.EOption {
	return []zstd.EOption{
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(concurrency),
		zstd.WithEncoderCRC(false),
	}
}

func decoderOpts() []zstd.DOption {
	return []zstd.DOption{
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxDecoded),
	}
}

// Encode compresses raw when that saves space, returning the payload to seal
// and its algorithm marker: (zstd output, Zstd) when strictly smaller, else
// (raw, "") so incompressible data pays no overhead. Deterministic: the same
// raw bytes always yield the same payload, which convergent dedup relies on.
func Encode(raw []byte) ([]byte, string) {
	if len(raw) == 0 {
		return raw, ""
	}
	c := encoder.EncodeAll(raw, make([]byte, 0, len(raw)))
	if len(c) >= len(raw) {
		return raw, ""
	}
	return c, Zstd
}

// Decode reverses Encode for a payload sealed under alg. rawLen >= 0 pins the exact
// expected output length, which is the caller's tamper check; rawLen < 0 leaves only
// the global cap.
func Decode(payload []byte, alg string, rawLen int) ([]byte, error) {
	switch alg {
	case "":
		if rawLen >= 0 && len(payload) != rawLen {
			return nil, errors.New("payload length mismatch")
		}
		return payload, nil
	case Zstd:
		capacity := rawLen
		if capacity < 0 {
			capacity = len(payload)
		}
		raw, err := decoder.DecodeAll(payload, make([]byte, 0, capacity))
		if err != nil {
			return nil, fmt.Errorf("zstd decode: %w", err)
		}
		if rawLen >= 0 && len(raw) != rawLen {
			return nil, errors.New("payload length mismatch")
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unknown compression algorithm %q", alg)
	}
}
