// SPDX-License-Identifier: AGPL-3.0-or-later

// Package compress is aqt's single compression codec. Convergent chunk ids
// depend on the compressor's exact output, so the codec is pinned: klauspost's
// pure-Go zstd at SpeedDefault, CRC off (the AEAD tag already authenticates).
// Changing the library, version, or level only degrades dedup for re-sealed
// data — old ids stop matching new output — never correctness, because every
// payload records the algorithm it was sealed with.
package compress

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Zstd marks a zstd-compressed payload; an empty marker means raw.
const Zstd = "zstd"

// maxDecoded caps decoder output when the caller cannot pin the exact raw
// length. Sealed payloads are AEAD-authenticated before they reach the
// decoder, so this is a sanity bound, not a security boundary, and it has to
// sit above anything Encode can produce: Encode has no cap, so a bound the
// decoder enforces but the encoder does not is a payload this package writes
// and then refuses to read back. The largest such payload is a folder's base
// manifest, which scales with the tracked tree.
const maxDecoded = 16 << 30

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
		// Without this each encoder state allocates 2x the 8 MiB window of history
		// headroom — 16 MiB x GOMAXPROCS once warmed, held for the process lifetime —
		// which one-shot EncodeAll calls on bounded payloads cannot use. Output is
		// byte-identical either way (the option changes buffer sizing, not matching;
		// pinned by TestLowerEncoderMemOutputUnchanged), so no optionsEpoch bump.
		zstd.WithLowerEncoderMem(true),
	}
}

func decoderOpts() []zstd.DOption {
	return []zstd.DOption{
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxDecoded),
	}
}

// optionsEpoch versions this package's encoder options as an input to CodecID.
// Bump it whenever encoderOpts changes, for the same reason a zstd upgrade
// matters: different options mean different bytes for the same input.
const optionsEpoch = "o1"

// CodecID names the exact compressor this build seals with: the zstd module
// version plus the encoder-options epoch. Convergent object ids depend on the
// compressor's exact output, so caches of sealed output namespace entries by
// CodecID — an upgrade that changes compressed bytes then retires them (a
// re-seal, mirroring the dedup degradation described above) instead of
// prolonging the old codec's no-longer-canonical bytes.
var CodecID = sync.OnceValue(func() string {
	version := "unversioned"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/klauspost/compress" {
				continue
			}
			version = dep.Version
			if dep.Replace != nil {
				// A replacement's identity is its path plus version; the version
				// alone can be empty (a directory replacement) or collide across
				// forks. Hash the pair, since a path is not filesystem-safe. Edits
				// inside an unversioned directory replacement stay invisible —
				// build info carries nothing to tell them apart.
				sum := sha256.Sum256([]byte(dep.Replace.Path + "@" + dep.Replace.Version))
				version = "replaced-" + hex.EncodeToString(sum[:8])
			}
		}
	}
	return "zstd-" + version + "-" + optionsEpoch
})

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
