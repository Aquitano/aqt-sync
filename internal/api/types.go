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
	// Tree marks a chunked folder whose blob is a sealed TreeRoot over a Merkle DAG of
	// directory nodes (Phase 4), so a moved/copied subtree dedups and a diff can skip
	// unchanged subtrees. A chunked folder created by a current client always sets it.
	Tree bool `json:"tree,omitempty"`
}

// CreateAccountRequest registers a new account and attaches the first device.
// PublicKey is the Ed25519 public half of the account's signing key (derived
// client-side from the random master key). WrappedRoot is that master key sealed
// under the passphrase-derived unlock key, and AuthVerifier proves possession of
// the passphrase. The server stores all three but never sees the passphrase, the
// master key, or the private key.
type CreateAccountRequest struct {
	Email        string            `json:"email"`
	Kdf          crypto.KdfParams  `json:"kdf"`
	PublicKey    []byte            `json:"publicKey"`
	WrappedRoot  crypto.SealedBlob `json:"wrappedRoot"`
	AuthVerifier []byte            `json:"authVerifier"`
	DeviceName   string            `json:"deviceName"`
	// InviteToken is required only when the server runs in invite-registration mode;
	// open servers ignore it. It is a server-issued shared secret, not key material.
	InviteToken string `json:"inviteToken,omitempty"`
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

// AttachDeviceRequest logs in an additional device. The signature over the
// challenge nonce proves possession of the account's signing key (so the master
// key); AuthVerifier proves possession of the current passphrase. The server
// requires both, so after a passphrase change a device cannot re-attach without
// the new passphrase.
type AttachDeviceRequest struct {
	Email        string `json:"email"`
	ChallengeID  string `json:"challengeId"`
	Signature    []byte `json:"signature"`
	AuthVerifier []byte `json:"authVerifier"`
	DeviceName   string `json:"deviceName"`
}

// AuthResponse is returned by account creation, device attach, and passphrase
// change. Epoch is the device token's auth epoch; a passphrase change bumps the
// account epoch, invalidating every token issued under an older one.
type AuthResponse struct {
	OwnerHandle string `json:"ownerHandle"`
	DeviceID    string `json:"deviceId"`
	Token       string `json:"token"`
	Epoch       int    `json:"epoch,omitempty"`
}

// SaltResponse is the new-device bootstrap: the KDF params and the wrapped master
// key a fresh machine needs to turn the passphrase into the master key. The server
// returns an indistinguishable decoy for an unknown email, so this endpoint does
// not reveal which emails have accounts.
type SaltResponse struct {
	Kdf         crypto.KdfParams  `json:"kdf"`
	WrappedRoot crypto.SealedBlob `json:"wrappedRoot"`
}

// PassphraseChangeRequest re-wraps the account's master key under a new passphrase.
// The master key itself does not change, so no resource is re-encrypted. OldAuthVerifier
// proves the caller knows the current passphrase (not just holds a token);
// ExpectedEpoch pins the change to the epoch the caller last saw (optimistic
// concurrency). On success the server stores the new Kdf/WrappedRoot/verifier and
// bumps the account epoch, invalidating every other device's token.
type PassphraseChangeRequest struct {
	Kdf             crypto.KdfParams  `json:"kdf"`
	WrappedRoot     crypto.SealedBlob `json:"wrappedRoot"`
	OldAuthVerifier []byte            `json:"oldAuthVerifier"`
	NewAuthVerifier []byte            `json:"newAuthVerifier"`
	ExpectedEpoch   int               `json:"expectedEpoch"`
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
//
// This is an in-process type: on the wire it travels as the raw envelope in
// wire.go (JSON header + ciphertext), never as JSON, so the blob pays no base64
// tax.
// MinClient declares the lowest client capability that can read the sealed formats
// this write stores (Capability* constants). A create/update leaves it 0 for a
// baseline (v1) write; a server treats 0 as CapabilityBaseline and never lets a
// client declare above its own capability.
type PutResourceRequest struct {
	ID              string
	Visibility      Visibility
	Blob            crypto.SealedBlob
	EncryptedMeta   crypto.SealedBlob
	WrappedKey      *crypto.WrappedKey
	ChunkRefs       []string
	ExpectedVersion int
	MinClient       int
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

// GetResourceResponse is an in-process type: on the wire it travels as the raw
// envelope in wire.go (JSON header + ciphertext), never as JSON.
type GetResourceResponse struct {
	ID            string
	Visibility    Visibility
	Blob          crypto.SealedBlob
	EncryptedMeta crypto.SealedBlob
	WrappedKey    *crypto.WrappedKey
	Version       int
	// MinClient is the lowest client capability that can read this resource's sealed
	// formats, so a current client can explain an incompatible remote instead of
	// failing to decrypt. 0 from an older server means "unknown" (treat as baseline).
	MinClient int
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
	// AutoSnapshot reports whether the server's scheduled snapshot job covers this
	// resource, so `snapshot auto` can show coverage without a per-resource fetch.
	AutoSnapshot bool `json:"autoSnapshot"`
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

// --- snapshots ---

// SnapshotInfo describes one retained snapshot: a frozen, GC-pinned copy of a
// resource version. EncryptedMeta and WrappedKey are copied from the resource at
// snapshot time, so a browse can decrypt the resource's name without touching the
// live resource (which may since have changed or been deleted). The server holds
// all of it opaquely; it never reads the meta or the key.
type SnapshotInfo struct {
	ID         string `json:"id"`
	ResourceID string `json:"resourceId"`
	Version    int    `json:"version"`
	CreatedAt  int64  `json:"createdAt"`
	// EncryptedLabel is the optional user label, sealed by the client under the
	// resource content key (AADSnapshotLabel). Absent on scheduled snapshots, which
	// the keyless server creates without a key to seal one. The server never reads it.
	EncryptedLabel *crypto.SealedBlob `json:"encryptedLabel,omitempty"`
	EncryptedMeta  crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey     *crypto.WrappedKey `json:"wrappedKey,omitempty"`
}

// CreateSnapshotRequest pins the current version of a resource the caller owns.
// The server reads the resource's live blob and chunk roots and copies both into
// an immutable snapshot; no plaintext or key is sent (the snapshot reuses the
// already-stored ciphertext). EncryptedLabel, when set, is the client-sealed label
// stored opaquely alongside.
type CreateSnapshotRequest struct {
	ResourceID     string             `json:"resourceId"`
	EncryptedLabel *crypto.SealedBlob `json:"encryptedLabel,omitempty"`
}

type ListSnapshotsResponse struct {
	Snapshots []SnapshotInfo `json:"snapshots"`
}

// GetSnapshotResponse carries everything the client needs to reconstruct a
// snapshot: the sealed root blob plus the copied meta and wrapped key. The chunk
// objects are fetched from the owner's object store by id, exactly as a normal
// pull does, so restore reuses the existing materialize path. All decryption
// happens on the client; the server returns only ciphertext.
type GetSnapshotResponse struct {
	Snapshot SnapshotInfo      `json:"snapshot"`
	Blob     crypto.SealedBlob `json:"blob"`
	// MinClient is the capability the snapshot's sealed formats need, copied from the
	// resource at snapshot time so restore can be gated the same way a resource read is.
	MinClient int `json:"minClient,omitempty"`
}

// SetAutoSnapshotRequest toggles whether the server's scheduled snapshot job
// covers a resource. Tracked roots are covered by default; this is the per-root
// opt-out.
type SetAutoSnapshotRequest struct {
	Enabled bool `json:"enabled"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	// Code is a stable machine-readable tag for errors a client acts on
	// programmatically (e.g. ErrCodeUpgradeRequired on a 426). Absent on plain errors.
	Code string `json:"code,omitempty"`
	// MinClient accompanies an upgrade-required (426) error: the capability the
	// resource needs, so the client can report exactly how far it is behind.
	MinClient int `json:"min_client,omitempty"`
}
