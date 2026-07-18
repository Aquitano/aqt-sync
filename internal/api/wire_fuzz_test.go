package api

import (
	"bytes"
	"testing"
	"unicode/utf8"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// seedEnvelopes returns a few well-formed bodies so the fuzzer starts from valid
// framing and mutates outward, rather than spending its budget rediscovering the
// 4-byte length prefix.
func seedEnvelopes(f *testing.F) {
	up, err := EncodeResourceUpload(PutResourceRequest{
		ID:            "abc",
		Visibility:    Private,
		Blob:          crypto.SealedBlob{Nonce: []byte("nonce"), Ciphertext: []byte("ciphertext")},
		EncryptedMeta: crypto.SealedBlob{Nonce: []byte("mn"), Ciphertext: []byte("mc")},
		ChunkRefs:     []string{"aa", "bb"},
		MinClient:     2,
		CompactAt:     64,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(up)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})             // zero-length header, rejected
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // header length over the cap, rejected without allocating it
}

// FuzzDecodeResourceUpload feeds arbitrary bytes to the upload decoder. It parses a
// body an untrusted server (or a client hitting the server) supplies, so the only
// invariant is that no input panics or hangs; a hostile length prefix must be
// rejected by the maxWireHeader cap, never used to size a giant allocation.
func FuzzDecodeResourceUpload(f *testing.F) {
	seedEnvelopes(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeResourceUpload(bytes.NewReader(body))
	})
}

// FuzzDecodeResourceDownload mirrors FuzzDecodeResourceUpload for the download body.
func FuzzDecodeResourceDownload(f *testing.F) {
	seedEnvelopes(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = DecodeResourceDownload(bytes.NewReader(body))
	})
}

// FuzzResourceUploadRoundTrip asserts encode->decode preserves every field, so the
// envelope framing (length-prefixed JSON header, then the ciphertext read whole) can
// never silently truncate or reorder a body's contents.
func FuzzResourceUploadRoundTrip(f *testing.F) {
	f.Add("id", "private", []byte("n"), []byte("c"), 3, 2)
	f.Add("", "public", []byte{}, []byte{}, 0, 0)
	f.Fuzz(func(t *testing.T, id, vis string, nonce, ct []byte, expectedVersion, minClient int) {
		// The header is JSON; a JSON string cannot carry invalid UTF-8 losslessly
		// (encoding replaces it with U+FFFD). Production ids and the visibility enum
		// are always valid UTF-8, so restricting the domain tests the real inputs.
		if !utf8.ValidString(id) || !utf8.ValidString(vis) {
			return
		}
		req := PutResourceRequest{
			ID:              id,
			Visibility:      Visibility(vis),
			Blob:            crypto.SealedBlob{Nonce: nonce, Ciphertext: ct},
			ExpectedVersion: expectedVersion,
			MinClient:       minClient,
			CompactAt:       64,
		}
		encoded, err := EncodeResourceUpload(req)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := DecodeResourceUpload(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != req.ID || got.Visibility != req.Visibility ||
			got.ExpectedVersion != req.ExpectedVersion || got.MinClient != req.MinClient || got.CompactAt != req.CompactAt {
			t.Fatalf("scalar mismatch: got %+v want %+v", got, req)
		}
		if !bytes.Equal(got.Blob.Nonce, req.Blob.Nonce) || !bytes.Equal(got.Blob.Ciphertext, req.Blob.Ciphertext) {
			t.Fatalf("blob mismatch: got %+v want %+v", got.Blob, req.Blob)
		}
	})
}

// FuzzResourceDownloadRoundTrip mirrors the upload round-trip for the download body.
func FuzzResourceDownloadRoundTrip(f *testing.F) {
	f.Add("id", "private", []byte("n"), []byte("c"), 7, 2)
	f.Add("", "public", []byte{}, []byte{}, 0, 0)
	f.Fuzz(func(t *testing.T, id, vis string, nonce, ct []byte, version, minClient int) {
		if !utf8.ValidString(id) || !utf8.ValidString(vis) {
			return
		}
		res := GetResourceResponse{
			ID:         id,
			Visibility: Visibility(vis),
			Blob:       crypto.SealedBlob{Nonce: nonce, Ciphertext: ct},
			Version:    version,
			MinClient:  minClient,
			CompactAt:  64,
			ExpiresAt:  123, MaxReads: 9, Reads: 4, CreatedAt: 100, UpdatedAt: 120,
		}
		encoded, err := EncodeResourceDownload(res)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, err := DecodeResourceDownload(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != res.ID || got.Visibility != res.Visibility ||
			got.Version != res.Version || got.MinClient != res.MinClient || got.CompactAt != res.CompactAt ||
			got.ExpiresAt != res.ExpiresAt || got.MaxReads != res.MaxReads || got.Reads != res.Reads ||
			got.CreatedAt != res.CreatedAt || got.UpdatedAt != res.UpdatedAt {
			t.Fatalf("scalar mismatch: got %+v want %+v", got, res)
		}
		if !bytes.Equal(got.Blob.Nonce, res.Blob.Nonce) || !bytes.Equal(got.Blob.Ciphertext, res.Blob.Ciphertext) {
			t.Fatalf("blob mismatch: got %+v want %+v", got.Blob, res.Blob)
		}
	})
}
