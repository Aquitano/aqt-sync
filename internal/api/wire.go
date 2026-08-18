// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/binary"
	"encoding/json"
	"errors"
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

// ErrHeaderTooLarge means an envelope's declared header length exceeds
// maxWireHeader. It is its own sentinel rather than one more malformed-body error
// because ChunkRefs is what crosses the bound in practice: a folder whose chunk
// count outgrows the cap fails here, and both ends need to name that cause instead
// of reporting a corrupt envelope.
var ErrHeaderTooLarge = errors.New("resource envelope: header exceeds the 32 MiB wire cap")

// MaxPackBytes is the wire contract for one serialized pack — object region plus
// index trailer. The server rejects a larger body outright (a non-retryable 413),
// so every client-side pack builder must dispatch before an append would cross
// it; both sides derive their bound from this one constant so they cannot drift.
const MaxPackBytes = 32 << 20

const (
	ResourceJSONMediaType     = "application/vnd.aqt.resource+json; version=1"
	ResourceEnvelopeMediaType = "application/vnd.aqt.resource+octet-stream; version=1"
	ObjectFramesMediaType     = "application/vnd.aqt.object-frames; version=1"
)

// resourceUploadHeader is the JSON header of PUT /v1/resources. The blob
// ciphertext follows as the rest of the body, sealed with BlobNonce.
type resourceUploadHeader struct {
	ID              string             `json:"id,omitempty"`
	Visibility      Visibility         `json:"visibility"`
	BlobNonce       []byte             `json:"blobNonce"`
	EncryptedMeta   crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey      *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	ChunkRefs       []string           `json:"chunkRefs,omitempty"`
	ClientGC        bool               `json:"clientGc,omitempty"`
	ExpectedVersion int                `json:"expectedVersion,omitempty"`
	MinClient       int                `json:"minClient,omitempty"`
	CompactAt       int                `json:"compactAt,omitempty"`
	ExpireSeconds   int64              `json:"expireSeconds,omitempty"`
	MaxReads        int64              `json:"maxReads,omitempty"`
	OnExpiry        OnExpiry           `json:"onExpiry,omitempty"`
	RevokeGrantee   string             `json:"revokeGrantee,omitempty"`
}

// resourceDownloadHeader is the JSON header of a GET /v1/resources/:id
// response; the blob ciphertext follows as the rest of the body.
type resourceDownloadHeader struct {
	ID            string             `json:"id"`
	Visibility    Visibility         `json:"visibility"`
	BlobNonce     []byte             `json:"blobNonce"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	GrantKey      []byte             `json:"grantKey,omitempty"`
	Owner         string             `json:"owner,omitempty"`
	Version       int                `json:"version"`
	MinClient     int                `json:"minClient,omitempty"`
	CompactAt     int                `json:"compactAt,omitempty"`
	ExpiresAt     int64              `json:"expiresAt,omitempty"`
	MaxReads      int64              `json:"maxReads,omitempty"`
	Reads         int64              `json:"reads,omitempty"`
	CreatedAt     int64              `json:"createdAt,omitempty"`
	UpdatedAt     int64              `json:"updatedAt,omitempty"`
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
		ClientGC:        req.ClientGC,
		ExpectedVersion: req.ExpectedVersion,
		MinClient:       req.MinClient,
		CompactAt:       req.CompactAt,
		ExpireSeconds:   req.ExpireSeconds,
		MaxReads:        req.MaxReads,
		OnExpiry:        req.OnExpiry,
		RevokeGrantee:   req.RevokeGrantee,
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
		ClientGC:        h.ClientGC,
		ExpectedVersion: h.ExpectedVersion,
		MinClient:       h.MinClient,
		CompactAt:       h.CompactAt,
		ExpireSeconds:   h.ExpireSeconds,
		MaxReads:        h.MaxReads,
		OnExpiry:        h.OnExpiry,
		RevokeGrantee:   h.RevokeGrantee,
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
		GrantKey:      res.GrantKey,
		Owner:         res.Owner,
		Version:       res.Version,
		MinClient:     res.MinClient,
		CompactAt:     res.CompactAt,
		ExpiresAt:     res.ExpiresAt,
		MaxReads:      res.MaxReads,
		Reads:         res.Reads,
		CreatedAt:     res.CreatedAt,
		UpdatedAt:     res.UpdatedAt,
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
		GrantKey:      h.GrantKey,
		Owner:         h.Owner,
		Version:       h.Version,
		MinClient:     h.MinClient,
		CompactAt:     h.CompactAt,
		ExpiresAt:     h.ExpiresAt,
		MaxReads:      h.MaxReads,
		Reads:         h.Reads,
		CreatedAt:     h.CreatedAt,
		UpdatedAt:     h.UpdatedAt,
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
	if n > maxWireHeader {
		return nil, fmt.Errorf("%w: declared %d bytes", ErrHeaderTooLarge, n)
	}
	if n == 0 {
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
