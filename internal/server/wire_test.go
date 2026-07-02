package server

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// TestRawResourceRoundTrip drives the octet-stream wire path end to end: the blob
// ciphertext travels verbatim (no base64), and both the bytes and the sealed
// metadata survive the round trip.
func TestRawResourceRoundTrip(t *testing.T) {
	h := newHarness(t)
	token, mk := h.signup("raw@example.com", "correct horse battery staple")

	plaintext := []byte("DATABASE_URL=postgres://localhost/app\nAPI_KEY=sk-live-123\n")
	ck, _ := crypto.GenerateContentKey()
	blob, err := crypto.Seal(plaintext, ck, crypto.AADBlob)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, _ := json.Marshal(api.Metadata{Name: ".env", Size: int64(len(plaintext))})
	metaBlob, _ := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))

	body, err := api.EncodeResourceUpload(api.PutResourceRequest{
		Visibility:    api.Private,
		Blob:          blob,
		EncryptedMeta: metaBlob,
		WrappedKey:    &wrapped,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := h.raw(http.MethodPut, "/v1/resources", token,
		map[string]string{"Content-Type": "application/octet-stream"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("raw put: %d (%s)", rec.Code, rec.Body.String())
	}
	var put api.PutResourceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &put); err != nil {
		t.Fatalf("decode put response: %v", err)
	}

	rec = h.raw(http.MethodGet, "/v1/resources/"+put.ID, token,
		map[string]string{"Accept": "application/octet-stream"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw get: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("raw get content-type = %q, want octet-stream", ct)
	}
	got, err := api.DecodeResourceDownload(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("decode raw download: %v", err)
	}
	if !bytes.Equal(got.Blob.Ciphertext, blob.Ciphertext) || !bytes.Equal(got.Blob.Nonce, blob.Nonce) {
		t.Fatal("blob ciphertext did not round-trip byte-identical")
	}
	if got.WrappedKey == nil {
		t.Fatal("expected wrapped key on a private resource")
	}
	unwrapped, err := crypto.UnwrapKey(*got.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	decrypted, err := crypto.Open(got.Blob, unwrapped, crypto.AADBlob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: %q", decrypted)
	}
	openedMeta, err := crypto.Open(got.EncryptedMeta, unwrapped, crypto.AADMeta)
	if err != nil {
		t.Fatalf("open meta: %v", err)
	}
	if !bytes.Equal(openedMeta, metaJSON) {
		t.Fatal("metadata did not round-trip")
	}
}

// TestRawResourceLegacyInterop confirms the two wire shapes are interchangeable: a
// blob uploaded raw is readable by a legacy JSON client, and vice versa, so an
// upgrade needs no coordinated flag day.
func TestRawResourceLegacyInterop(t *testing.T) {
	h := newHarness(t)
	token, _ := h.signup("interop@example.com", "another passphrase here now")

	ck, _ := crypto.GenerateContentKey()
	blob, _ := crypto.Seal([]byte("public snippet"), ck, crypto.AADBlob)
	metaBlob, _ := crypto.Seal([]byte(`{"name":"n.txt","size":14}`), ck, crypto.AADMeta)

	// Raw upload, legacy JSON read.
	body, _ := api.EncodeResourceUpload(api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: metaBlob,
	})
	rec := h.raw(http.MethodPut, "/v1/resources", token,
		map[string]string{"Content-Type": "application/octet-stream"}, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("raw put: %d (%s)", rec.Code, rec.Body.String())
	}
	var put api.PutResourceResponse
	json.Unmarshal(rec.Body.Bytes(), &put)

	var jsonGot api.GetResourceResponse
	if code := h.do(http.MethodGet, "/v1/resources/"+put.ID, token, nil, &jsonGot); code != http.StatusOK {
		t.Fatalf("legacy json get: %d", code)
	}
	if !bytes.Equal(jsonGot.Blob.Ciphertext, blob.Ciphertext) {
		t.Fatal("legacy JSON read of a raw upload lost the blob")
	}

	// Legacy JSON upload, raw read.
	var put2 api.PutResourceResponse
	if code := h.do(http.MethodPut, "/v1/resources", token, api.PutResourceRequest{
		Visibility: api.Public, Blob: blob, EncryptedMeta: metaBlob,
	}, &put2); code != http.StatusCreated {
		t.Fatalf("legacy json put: %d", code)
	}
	rec = h.raw(http.MethodGet, "/v1/resources/"+put2.ID, token,
		map[string]string{"Accept": "application/octet-stream"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("raw get: %d", rec.Code)
	}
	rawGot, err := api.DecodeResourceDownload(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("decode raw download: %v", err)
	}
	if !bytes.Equal(rawGot.Blob.Ciphertext, blob.Ciphertext) {
		t.Fatal("raw read of a legacy JSON upload lost the blob")
	}
}

// TestRawResourceBodyCapEnforced confirms the raw path honors the same
// maxResourceBody cap as the JSON path: an over-cap body is refused before it is
// buffered, not read whole into memory.
func TestRawResourceBodyCapEnforced(t *testing.T) {
	h := newHarness(t)
	token, _ := h.signup("cap@example.com", "passphrase for the cap test")

	header := []byte(`{"visibility":"public","blobNonce":null}`)
	over := make([]byte, 4+len(header)+maxResourceBody+1)
	binary.BigEndian.PutUint32(over, uint32(len(header)))
	copy(over[4:], header)

	rec := h.raw(http.MethodPut, "/v1/resources", token,
		map[string]string{"Content-Type": "application/octet-stream"}, over)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap raw put: got %d, want 413", rec.Code)
	}
}

// TestGzipNegotiatesJSON checks that a compressible JSON reply is gzip-encoded only
// when the client offers it, and decodes cleanly either way.
func TestGzipNegotiatesJSON(t *testing.T) {
	h := newHarness(t)
	token, _ := h.signup("gz@example.com", "passphrase for gzip negotiation")

	// A check of many unknown ids echoes them all back — kilobytes of hex JSON,
	// well over the compression threshold.
	ids := make([]string, 400)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
	}
	reqBody, _ := json.Marshal(api.ChunkCheckRequest{IDs: ids})

	gzRec := h.raw(http.MethodPost, "/v1/chunks/check", token, map[string]string{
		"Content-Type":    "application/json",
		"Accept-Encoding": "gzip",
	}, reqBody)
	if gzRec.Code != http.StatusOK {
		t.Fatalf("gzip check: %d", gzRec.Code)
	}
	if enc := gzRec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if gzRec.Body.Len() >= len(reqBody) {
		t.Fatalf("gzip body (%d) not smaller than the id list (%d)", gzRec.Body.Len(), len(reqBody))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzRec.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	var decoded api.ChunkCheckResponse
	if err := json.Unmarshal(plain, &decoded); err != nil {
		t.Fatalf("decode gunzipped body: %v", err)
	}
	if len(decoded.Missing) != len(ids) {
		t.Fatalf("missing = %d, want %d", len(decoded.Missing), len(ids))
	}

	// No Accept-Encoding: identity, decodes directly.
	idRec := h.raw(http.MethodPost, "/v1/chunks/check", token,
		map[string]string{"Content-Type": "application/json"}, reqBody)
	if enc := idRec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("identity request got Content-Encoding %q", enc)
	}
	var identity api.ChunkCheckResponse
	if err := json.Unmarshal(idRec.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decode identity body: %v", err)
	}
	if len(identity.Missing) != len(ids) {
		t.Fatalf("identity missing = %d, want %d", len(identity.Missing), len(ids))
	}
}

// TestGzipSkipsOctetStream confirms the middleware never compresses an
// already-encrypted pack body, even when the client offers gzip.
func TestGzipSkipsOctetStream(t *testing.T) {
	h := newHarness(t)
	token, _ := h.signup("gzpack@example.com", "passphrase for the pack gzip test")
	packID, pack, _ := packOf("hello pack world for gzip", "second object here padded out")

	if rec := h.raw(http.MethodPut, "/v1/packs/"+packID, token,
		map[string]string{"Content-Type": "application/octet-stream"}, pack); rec.Code != http.StatusOK {
		t.Fatalf("put pack: %d (%s)", rec.Code, rec.Body.String())
	}

	rec := h.raw(http.MethodGet, "/v1/packs/"+packID, token,
		map[string]string{"Accept-Encoding": "gzip"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get pack: %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("pack body was compressed (Content-Encoding %q); ciphertext must ship raw", enc)
	}
	if !bytes.Equal(rec.Body.Bytes(), pack) {
		t.Fatal("pack GET under Accept-Encoding: gzip did not round-trip the bytes")
	}
}
