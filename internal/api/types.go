// Package api defines the wire types shared by the aqt server and client.
//
// Everything the server receives is opaque: sealed blobs, encrypted metadata,
// and key material it can store but never read. The plaintext schema the client
// seals (Metadata) lives here too so client and server agree on its shape, even
// though the server only ever sees its ciphertext.
package api

import "github.com/aquitano/aqt-sync/internal/crypto"

type Visibility string

const (
	Private Visibility = "private"
	Public  Visibility = "public"
)

// Metadata is the plaintext resource description. The client seals it under the
// content key before upload; the server stores only the ciphertext.
type Metadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// CreateAccountRequest registers a new account and attaches the first device.
// PublicKey is the Ed25519 public half of the account's signing key (derived
// client-side from the master key); the server stores it and never sees the
// passphrase, master key, or private key.
type CreateAccountRequest struct {
	Email      string           `json:"email"`
	Kdf        crypto.KdfParams `json:"kdf"`
	PublicKey  []byte           `json:"publicKey"`
	DeviceName string           `json:"deviceName"`
}

// ChallengeRequest asks the server for a fresh nonce to sign when attaching a
// device to an existing account.
type ChallengeRequest struct {
	Email string `json:"email"`
}

// ChallengeResponse carries a one-time, short-lived nonce and its id.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       []byte `json:"nonce"`
}

// AttachDeviceRequest logs in an additional device by returning a signature over
// the challenge nonce, proving possession of the account's signing key.
type AttachDeviceRequest struct {
	Email       string `json:"email"`
	ChallengeID string `json:"challengeId"`
	Signature   []byte `json:"signature"`
	DeviceName  string `json:"deviceName"`
}

// AuthResponse is returned by account creation and device attach.
type AuthResponse struct {
	OwnerHandle string `json:"ownerHandle"`
	DeviceID    string `json:"deviceId"`
	Token       string `json:"token"`
}

// SaltResponse carries the KDF parameters a new machine needs to re-derive the
// master key from the passphrase.
type SaltResponse struct {
	Kdf crypto.KdfParams `json:"kdf"`
}

// PutResourceRequest creates a resource (ID empty) or replaces an existing one
// in place (ID set, must be owned by the caller). WrappedKey is present only for
// private resources (the content key wrapped under the owner's master key); for
// public resources the content key lives in the share-link fragment instead.
//
// ChunkRefs lists the chunk ids the blob (a folder's sealed manifest) references.
// The server stores them as the resource's GC roots; it never inspects them.
//
// ExpectedVersion, when > 0, is the version the client based this update on. The
// server rejects the write (409) if the stored version differs, so a concurrent
// write is never silently lost — the client re-fetches and retries. Omit it (0)
// for a create or an unconditional replace.
type PutResourceRequest struct {
	ID              string             `json:"id,omitempty"`
	Visibility      Visibility         `json:"visibility"`
	Blob            crypto.SealedBlob  `json:"blob"`
	EncryptedMeta   crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey      *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	ChunkRefs       []string           `json:"chunkRefs,omitempty"`
	ExpectedVersion int                `json:"expectedVersion,omitempty"`
}

// ChunkData is one opaque, content-addressed chunk on the wire. ID is the hex
// sha256 of Data; the server verifies the binding on upload.
type ChunkData struct {
	ID   string `json:"id"`
	Data []byte `json:"data"`
}

// ChunkCheckRequest asks which of the given chunk ids the owner does not yet have
// (the have/want negotiation before an upload).
type ChunkCheckRequest struct {
	IDs []string `json:"ids"`
}

type ChunkCheckResponse struct {
	Missing []string `json:"missing"`
}

type ChunkUploadRequest struct {
	Chunks []ChunkData `json:"chunks"`
}

type ChunkUploadResponse struct {
	Stored int `json:"stored"`
}

type ChunkFetchRequest struct {
	IDs []string `json:"ids"`
}

type ChunkFetchResponse struct {
	Chunks []ChunkData `json:"chunks"`
}

// GCResponse reports how many unreferenced chunks a sweep deleted.
type GCResponse struct {
	Deleted int `json:"deleted"`
}

type PutResourceResponse struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// SetVisibilityRequest flips a resource public/private without re-uploading its
// blob. Used by `share` (private → public); making private again instead rotates
// the content key via a full PutResource.
type SetVisibilityRequest struct {
	Visibility Visibility `json:"visibility"`
}

type GetResourceResponse struct {
	ID            string             `json:"id"`
	Visibility    Visibility         `json:"visibility"`
	Blob          crypto.SealedBlob  `json:"blob"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	Version       int                `json:"version"`
}

type ResourceListItem struct {
	ID            string            `json:"id"`
	Visibility    Visibility        `json:"visibility"`
	EncryptedMeta crypto.SealedBlob `json:"encryptedMeta"`
	Version       int               `json:"version"`
}

type ListResourcesResponse struct {
	Resources []ResourceListItem `json:"resources"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
