package compress

import (
	"bytes"
	"crypto/rand"
	"testing"
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
