package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Resource bodies travel as a raw envelope instead of base64 inside JSON: a
// 4-byte big-endian header length, a JSON header, then the blob ciphertext
// verbatim. Base64 added a third to the wire size of every multi-MiB blob and
// forced both ends to JSON-process the whole body; the envelope keeps the
// ciphertext a single opaque buffer, like the pack transport.

// maxWireHeader bounds the envelope's JSON header before it is allocated or
// parsed. ChunkRefs dominates a large upload's header (one 64-hex id per chunk
// root), so the bound matches the server's chunk-batch body cap; everything
// else in the header is a few hundred bytes.
const maxWireHeader = 32 << 20

// resourceUploadHeader is the JSON header of PUT /v1/resources. The blob
// ciphertext follows as the rest of the body, sealed with BlobNonce.
type resourceUploadHeader struct {
	ID              string             `json:"id,omitempty"`
	Visibility      Visibility         `json:"visibility"`
	BlobNonce       []byte             `json:"blobNonce"`
	EncryptedMeta   crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey      *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	ChunkRefs       []string           `json:"chunkRefs,omitempty"`
	ExpectedVersion int                `json:"expectedVersion,omitempty"`
}

// resourceDownloadHeader is the JSON header of a GET /v1/resources/:id
// response; the blob ciphertext follows as the rest of the body.
type resourceDownloadHeader struct {
	ID            string             `json:"id"`
	Visibility    Visibility         `json:"visibility"`
	BlobNonce     []byte             `json:"blobNonce"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	Version       int                `json:"version"`
}

// EncodeResourceUpload encodes req as a raw upload body: length-prefixed JSON
// header, then the blob ciphertext.
func EncodeResourceUpload(req PutResourceRequest) ([]byte, error) {
	return encodeEnvelope(resourceUploadHeader{
		ID:              req.ID,
		Visibility:      req.Visibility,
		BlobNonce:       req.Blob.Nonce,
		EncryptedMeta:   req.EncryptedMeta,
		WrappedKey:      req.WrappedKey,
		ChunkRefs:       req.ChunkRefs,
		ExpectedVersion: req.ExpectedVersion,
	}, req.Blob.Ciphertext)
}

// DecodeResourceUpload reads a raw upload body. The ciphertext is read whole as
// one buffer, bounded by the caller's body cap, and never JSON-processed.
func DecodeResourceUpload(r io.Reader) (PutResourceRequest, error) {
	var h resourceUploadHeader
	ct, err := decodeEnvelope(r, &h)
	if err != nil {
		return PutResourceRequest{}, err
	}
	return PutResourceRequest{
		ID:              h.ID,
		Visibility:      h.Visibility,
		Blob:            crypto.SealedBlob{Nonce: h.BlobNonce, Ciphertext: ct},
		EncryptedMeta:   h.EncryptedMeta,
		WrappedKey:      h.WrappedKey,
		ChunkRefs:       h.ChunkRefs,
		ExpectedVersion: h.ExpectedVersion,
	}, nil
}

// EncodeResourceDownload encodes res as a raw download body: length-prefixed
// JSON header, then the blob ciphertext.
func EncodeResourceDownload(res GetResourceResponse) ([]byte, error) {
	return encodeEnvelope(resourceDownloadHeader{
		ID:            res.ID,
		Visibility:    res.Visibility,
		BlobNonce:     res.Blob.Nonce,
		EncryptedMeta: res.EncryptedMeta,
		WrappedKey:    res.WrappedKey,
		Version:       res.Version,
	}, res.Blob.Ciphertext)
}

// DecodeResourceDownload reads a raw download body.
func DecodeResourceDownload(r io.Reader) (GetResourceResponse, error) {
	var h resourceDownloadHeader
	ct, err := decodeEnvelope(r, &h)
	if err != nil {
		return GetResourceResponse{}, err
	}
	return GetResourceResponse{
		ID:            h.ID,
		Visibility:    h.Visibility,
		Blob:          crypto.SealedBlob{Nonce: h.BlobNonce, Ciphertext: ct},
		EncryptedMeta: h.EncryptedMeta,
		WrappedKey:    h.WrappedKey,
		Version:       h.Version,
	}, nil
}

func encodeEnvelope(header any, ciphertext []byte) ([]byte, error) {
	hj, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4+len(hj)+len(ciphertext))
	binary.BigEndian.PutUint32(out, uint32(len(hj)))
	copy(out[4:], hj)
	copy(out[4+len(hj):], ciphertext)
	return out, nil
}

func decodeEnvelope(r io.Reader, header any) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("resource envelope: read header length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > maxWireHeader {
		return nil, fmt.Errorf("resource envelope: header length %d out of range", n)
	}
	hj := make([]byte, n)
	if _, err := io.ReadFull(r, hj); err != nil {
		return nil, fmt.Errorf("resource envelope: read header: %w", err)
	}
	if err := json.Unmarshal(hj, header); err != nil {
		return nil, fmt.Errorf("resource envelope: decode header: %w", err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("resource envelope: read ciphertext: %w", err)
	}
	if len(ct) == 0 {
		ct = nil
	}
	return ct, nil
}
