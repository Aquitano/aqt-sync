// SPDX-License-Identifier: AGPL-3.0-or-later

package compress

import (
	"bytes"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte("compressible text payload\n"), 200)

	payload, alg := Encode(raw)
	if alg != Zstd {
		t.Fatalf("alg = %q, want %q", alg, Zstd)
	}
	if len(payload) >= len(raw) {
		t.Fatalf("compressed (%d) not smaller than raw (%d)", len(payload), len(raw))
	}
	got, err := Decode(payload, alg, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("round trip mismatch")
	}
}

func TestEncodeDeterministic(t *testing.T) {
	raw := bytes.Repeat([]byte("dedup depends on identical output\n"), 100)
	a, _ := Encode(raw)
	b, _ := Encode(raw)
	if !bytes.Equal(a, b) {
		t.Fatal("Encode is not deterministic; convergent dedup would break")
	}
}

func TestEncodeSkipsIncompressible(t *testing.T) {
	raw := make([]byte, 4096)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	payload, alg := Encode(raw)
	if alg != "" {
		t.Fatalf("alg = %q, want raw passthrough", alg)
	}
	if !bytes.Equal(payload, raw) {
		t.Fatal("raw passthrough altered the payload")
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 100)
	payload, alg := Encode(raw)

	if _, err := Decode(payload, alg, len(raw)+1); err == nil {
		t.Fatal("wrong rawLen must be rejected")
	}
	if _, err := Decode(raw, "lz4", len(raw)); err == nil {
		t.Fatal("unknown algorithm must be rejected")
	}
	if _, err := Decode(raw, "", len(raw)-1); err == nil {
		t.Fatal("raw length mismatch must be rejected")
	}
}

// WithLowerEncoderMem must not change output bytes: convergent object ids depend
// on the exact compressed form, and encoderOpts carries no epoch bump for this
// option on the strength of this test. Payload shapes cover the single-block path
// (<= 128 KiB), multi-block, high and low compressibility, and sizes past the
// point where history buffers come into play.
func TestLowerEncoderMemOutputUnchanged(t *testing.T) {
	reference, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(runtime.GOMAXPROCS(0)),
		zstd.WithEncoderCRC(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reference.Close() }()

	rng := mrand.New(mrand.NewSource(1))
	shapes := map[string]func(n int) []byte{
		"zeros": func(n int) []byte { return make([]byte, n) },
		"text": func(n int) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = "the quick brown fox jumps over the lazy dog "[i%44]
			}
			return b
		},
		"random": func(n int) []byte {
			b := make([]byte, n)
			rng.Read(b)
			return b
		},
		"mixed": func(n int) []byte {
			b := make([]byte, n)
			rng.Read(b[:n/2])
			return b
		},
	}
	sizes := []int{1, 1 << 10, 100 << 10, 128 << 10, 128<<10 + 1, 1 << 20, 4 << 20, 9 << 20}
	for name, gen := range shapes {
		for _, n := range sizes {
			raw := gen(n)
			want := reference.EncodeAll(raw, nil)
			got := encoder.EncodeAll(raw, nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s/%d: lowMem output differs (%d vs %d bytes)", name, n, len(got), len(want))
			}
		}
	}
}

// Decode and DecodeSelfSealed differ only in the bound they hand decodeWith, so a
// bound that does not reach the decoder would silently give wire input the base
// manifest's headroom.
func TestDecodeBoundIsWiredThrough(t *testing.T) {
	raw := bytes.Repeat([]byte("bounded output\n"), 500)
	payload, alg := Encode(raw)
	if alg != Zstd {
		t.Fatalf("alg = %q, want %q", alg, Zstd)
	}

	tight, err := zstd.NewReader(nil, decoderOpts(uint64(len(raw)-1))...)
	if err != nil {
		t.Fatal(err)
	}
	defer tight.Close()
	if _, err := decodeWith(tight, payload, alg, -1); !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
		t.Fatalf("one byte under the raw length: err = %v, want %v", err, zstd.ErrDecoderSizeExceeded)
	}

	loose, err := zstd.NewReader(nil, decoderOpts(uint64(len(raw)))...)
	if err != nil {
		t.Fatal(err)
	}
	defer loose.Close()
	got, err := decodeWith(loose, payload, alg, -1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("round trip mismatch at the exact bound")
	}
}
