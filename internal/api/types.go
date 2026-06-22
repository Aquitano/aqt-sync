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
type PutResourceRequest struct {
	ID            string             `json:"id,omitempty"`
	Visibility    Visibility         `json:"visibility"`
	Blob          crypto.SealedBlob  `json:"blob"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
}

type PutResourceResponse struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
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
