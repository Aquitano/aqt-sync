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

// Resource kinds carried in Metadata.Kind so the client can tell a single-file
// push from a tracked-folder manifest without decrypting the blob. An absent kind
// (older resources) is treated as a file.
const (
	KindFile   = "file"
	KindFolder = "folder"
)

// Metadata is the plaintext resource description. The client seals it under the
// content key before upload; the server stores only the ciphertext.
type Metadata struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Kind string `json:"kind,omitempty"`
	// Streamed marks a file whose blob is a sealed FileRoot over chunk objects rather
	// than the inline ciphertext, so pull reconstructs it from the objects.
	Streamed bool `json:"streamed,omitempty"`
	// Packed marks a pack-and-seal folder whose blob is a sealed PackRoot over a
	// tarball of the whole tree (no chunk-level dedup), so sync/clone reconstruct it
	// by untarring rather than per-file. A folder resource without this is chunked.
	Packed bool `json:"packed,omitempty"`
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

// PackIndexEntry locates one object inside a pack: its content-address id and the
// byte slice [Off, Off+Len) of its ciphertext, relative to the start of the pack.
// A pack's trailing index is a JSON array of these (see syncengine.PackBuilder for
// the on-the-wire pack layout); the server verifies every slice against its id.
type PackIndexEntry struct {
	ID  string `json:"id"`
	Off int    `json:"off"`
	Len int    `json:"len"`
}

// ObjectLocation tells a client where to download an object: which pack holds it
// and the byte range [Off, Off+Len) within that pack. Returned by /v1/chunks/locate
// so a pull can range-fetch only the packs (and byte spans) it needs.
type ObjectLocation struct {
	ID     string `json:"id"`
	PackID string `json:"packId"`
	Off    int64  `json:"off"`
	Len    int64  `json:"len"`
}

// LocateRequest asks where a set of object ids live; the response carries one
// ObjectLocation per id the owner stores (unknown ids are simply absent).
type LocateRequest struct {
	IDs []string `json:"ids"`
}

type LocateResponse struct {
	Locations []ObjectLocation `json:"locations"`
}

// ChunkCheckRequest asks which of the given chunk ids the owner does not yet have
// (the have/want negotiation before an upload).
type ChunkCheckRequest struct {
	IDs []string `json:"ids"`
}

type ChunkCheckResponse struct {
	Missing []string `json:"missing"`
}

// PutPackResponse acknowledges a pack upload, reporting how many of its objects
// were newly stored (zero means every object already existed: a fully-deduped pack).
type PutPackResponse struct {
	StoredObjects int `json:"storedObjects"`
}

// GCResponse reports a pack maintenance run: how many fully-dead packs were swept
// (DeletedPacks/FreedBytes) and how many partially-dead packs were compacted by
// copying their live objects into fresh packs (RepackedPacks/ReclaimedBytes).
type GCResponse struct {
	DeletedPacks   int   `json:"deletedPacks"`
	FreedBytes     int64 `json:"freedBytes"`
	RepackedPacks  int   `json:"repackedPacks,omitempty"`
	ReclaimedBytes int64 `json:"reclaimedBytes,omitempty"`
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

// ResourceListItem describes one of the owner's resources. WrappedKey (the
// content key under the owner's master key) is included so `aqt ls`/`aqt find`
// can decrypt the sealed metadata locally; the list endpoint is owner-only, so it
// reveals nothing a GET of each resource would not.
type ResourceListItem struct {
	ID            string             `json:"id"`
	Visibility    Visibility         `json:"visibility"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	Version       int                `json:"version"`
}

type ListResourcesResponse struct {
	Resources []ResourceListItem `json:"resources"`
}

// Device is one attached device on an account. The server never returns the token
// (only its hash is stored); Current is set client-side to mark the local device.
type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Current bool   `json:"current,omitempty"`
}

type ListDevicesResponse struct {
	Devices []Device `json:"devices"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
