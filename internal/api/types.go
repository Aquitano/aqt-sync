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
// AuthKey is the server-facing key (crypto.DeriveAuthKey); the server persists
// only a hash of it and never sees the passphrase or master key.
type CreateAccountRequest struct {
	Email      string           `json:"email"`
	Kdf        crypto.KdfParams `json:"kdf"`
	AuthKey    []byte           `json:"authKey"`
	DeviceName string           `json:"deviceName"`
}

// AttachDeviceRequest logs in an additional device for an existing account.
type AttachDeviceRequest struct {
	Email      string `json:"email"`
	AuthKey    []byte `json:"authKey"`
	DeviceName string `json:"deviceName"`
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

// PutResourceRequest creates a resource. WrappedKey is present only for private
// resources (the content key wrapped under the owner's master key); for public
// resources the content key lives in the share-link fragment instead.
type PutResourceRequest struct {
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
