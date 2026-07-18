package gitremote

import (
	"bytes"
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

type memorySink map[string][]byte

func (s memorySink) Add(id string, object []byte) error {
	s[id] = append([]byte(nil), object...)
	return nil
}

func TestBundleRoundTripAcrossSegments(t *testing.T) {
	key, err := crypto.GenerateContentKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Wipe()
	want := bytes.Repeat([]byte("git bundle payload\n"), BundleSegmentSize/10)
	sink := memorySink{}
	bundle, err := SealBundle(bytes.NewReader(want), key, sink)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Segments) < 2 {
		t.Fatalf("segments = %d, want at least 2", len(bundle.Segments))
	}
	var got bytes.Buffer
	if err := OpenBundle(bundle, key, func(id string) ([]byte, error) { return sink[id], nil }, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("round trip produced %d bytes, want %d", got.Len(), len(want))
	}
}

func TestBundleRejectsTamperedObject(t *testing.T) {
	key, _ := crypto.GenerateContentKey()
	defer key.Wipe()
	sink := memorySink{}
	bundle, err := SealBundle(bytes.NewReader([]byte("bundle")), key, sink)
	if err != nil {
		t.Fatal(err)
	}
	sink[bundle.Segments[0].ID][0] ^= 1
	if err := OpenBundle(bundle, key, func(id string) ([]byte, error) { return sink[id], nil }, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered segment opened")
	}
}
