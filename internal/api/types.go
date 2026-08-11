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
	KindFile      = "file"
	KindFolder    = "folder"
	KindGitRemote = "gitremote"
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
	// EncPublicKey is the X25519 half of the account's published identity (derived
	// from the master key like the signing key), the target other accounts wrap
	// grant keys to. EncKeySig is its Ed25519 self-signature (crypto.SignEncKey),
	// so a client can verify the two halves belong together. Optional: an older
	// client omits both and backfills via PUT /v1/account/enc-key on next login.
	EncPublicKey []byte `json:"encPublicKey,omitempty"`
	EncKeySig    []byte `json:"encKeySig,omitempty"`
}

// PublishEncKeyRequest backfills the account's X25519 encryption key (and its
// identity self-signature) for accounts created before grants existed. The
// server verifies the signature against the stored Ed25519 key before storing.
type PublishEncKeyRequest struct {
	EncPublicKey []byte `json:"encPublicKey"`
	EncKeySig    []byte `json:"encKeySig"`
}

// AccountKeysResponse is the grant-target lookup: the opaque owner handle plus
// both published public keys and the binding signature. Like the bootstrap
// endpoint, an unknown email (or one whose account predates enc keys) yields an
// indistinguishable decoy, so the lookup is not an account-existence oracle;
// a grant wrapped to a decoy key simply never decrypts for anyone.
type AccountKeysResponse struct {
	Handle       string `json:"handle"`
	PublicKey    []byte `json:"publicKey"`
	EncPublicKey []byte `json:"encPublicKey"`
	EncKeySig    []byte `json:"encKeySig"`
}

// CreateGrantRequest grants one account read access to a resource the caller
// owns: the resource's content key HPKE-wrapped to the grantee's enc key
// (crypto.WrapGrant, bound to resource id + owner handle + grantee handle).
// The server stores the wrap opaquely; re-granting an existing grantee
// replaces the wrap (the rotation path re-wraps for remaining grantees).
type CreateGrantRequest struct {
	GranteeHandle   string `json:"granteeHandle"`
	WrappedKey      []byte `json:"wrappedKey"`
	ExpectedVersion int    `json:"expectedVersion,omitempty"`
}

// GrantEntry is one grant on a resource, as listed for its owner.
type GrantEntry struct {
	GranteeHandle string `json:"granteeHandle"`
	CreatedAt     int64  `json:"createdAt"`
}

type ListGrantsResponse struct {
	Grants []GrantEntry `json:"grants"`
	// NextCursor is the opaque cursor to pass as ?cursor= for the following page;
	// empty on the last page. See ListResourcesResponse for the paging contract.
	NextCursor string `json:"nextCursor,omitempty"`
}

// ShareItem is one incoming grant, as listed for its grantee: enough to show
// the share (the meta decrypts under the unwrapped grant key) and to pull it.
type ShareItem struct {
	ResourceID    string            `json:"resourceId"`
	OwnerHandle   string            `json:"ownerHandle"`
	WrappedKey    []byte            `json:"wrappedKey"`
	EncryptedMeta crypto.SealedBlob `json:"encryptedMeta"`
	CreatedAt     int64             `json:"createdAt"`
}

type ListSharesResponse struct {
	Shares []ShareItem `json:"shares"`
	// NextCursor is the opaque cursor to pass as ?cursor= for the following page;
	// empty on the last page. See ListResourcesResponse for the paging contract.
	NextCursor string `json:"nextCursor,omitempty"`
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

// KeyWrapMigration replaces an owner-wrapped content key during an account root
// key rotation. ExpectedVersion prevents a stale client from silently replacing a
// resource that changed while it prepared the migration.
type KeyWrapMigration struct {
	ID              string            `json:"id"`
	WrappedKey      crypto.WrappedKey `json:"wrappedKey"`
	ExpectedVersion int               `json:"expectedVersion,omitempty"`
}

// GrantKeyMigration replaces an incoming grant's HPKE wrap after the grantee's
// derived X25519 identity changes with its root key.
type GrantKeyMigration struct {
	ResourceID  string `json:"resourceId"`
	OwnerHandle string `json:"ownerHandle"`
	WrappedKey  []byte `json:"wrappedKey"`
}

// RootKeyRotationRequest atomically changes the account root key. Every owner
// resource and snapshot that has a recoverable wrapped key, plus every incoming
// grant, must be included so the old root is not needed after the account identity
// switches. The server stores these values opaquely and verifies only membership,
// versions, the current-passphrase proof, and the new public-key binding.
type RootKeyRotationRequest struct {
	Kdf             crypto.KdfParams    `json:"kdf"`
	WrappedRoot     crypto.SealedBlob   `json:"wrappedRoot"`
	OldAuthVerifier []byte              `json:"oldAuthVerifier"`
	NewAuthVerifier []byte              `json:"newAuthVerifier"`
	ExpectedEpoch   int                 `json:"expectedEpoch"`
	PublicKey       []byte              `json:"publicKey"`
	EncPublicKey    []byte              `json:"encPublicKey"`
	EncKeySig       []byte              `json:"encKeySig"`
	Resources       []KeyWrapMigration  `json:"resources"`
	Snapshots       []KeyWrapMigration  `json:"snapshots"`
	IncomingGrants  []GrantKeyMigration `json:"incomingGrants"`
}

// DeleteAccountRequest erases the calling account and everything stored under it.
// AuthVerifier proves the caller knows the current passphrase, so a stolen device
// token alone cannot destroy an account — the same proof the passphrase change and
// root-key rotation require. There is no epoch field: a passphrase changed
// elsewhere already invalidates the verifier.
type DeleteAccountRequest struct {
	AuthVerifier []byte `json:"authVerifier"`
}

// DeleteAccountResponse is the receipt for an erasure: what the server actually
// removed. Counts are of rows deleted.
//
// Bytes is the storage total the account held, on the same basis UsageResponse and
// the quota report it, so the receipt and the usage the caller saw before
// confirming are the same number. It is a pointer because the only honest
// alternative to that number is no number: the server's other byte total counts
// unlinked files alone, a fraction of this one, and substituting it would read as
// though most of the account had survived.
//
// FileErrors counts stored files the server could not remove. The rows are gone, so
// the account is deleted either way, but the ciphertext may still be on the
// operator's disk — which is the account holder's business, not just the operator's.
// The paths themselves stay server-side.
type DeleteAccountResponse struct {
	OwnerHandle string `json:"ownerHandle"`
	Resources   int64  `json:"resources"`
	Snapshots   int64  `json:"snapshots"`
	Devices     int64  `json:"devices"`
	Packs       int64  `json:"packs"`
	Objects     int64  `json:"objects"`
	Grants      int64  `json:"grants"`
	Bytes       *int64 `json:"bytes,omitempty"`
	FileErrors  int    `json:"fileErrors,omitempty"`
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
//
// ExpireSeconds and MaxReads carry an optional server-enforced lifecycle policy for a
// public link. ExpireSeconds is a TTL in seconds (not an absolute time, so server
// clock skew is irrelevant); the server computes expires_at = now + ExpireSeconds.
// MaxReads caps the number of non-owner reads. Both are meaningful only on a public
// resource; a policy on a private put is rejected. Zero means "no limit". OnExpiry
// selects what happens when the policy fires.
type PutResourceRequest struct {
	ID              string             `json:"id,omitempty"`
	Visibility      Visibility         `json:"visibility"`
	Blob            crypto.SealedBlob  `json:"blob"`
	EncryptedMeta   crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey      *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	ChunkRefs       []string           `json:"chunkRefs,omitempty"`
	ExpectedVersion int                `json:"expectedVersion,omitempty"`
	MinClient       int                `json:"minClient,omitempty"`
	// CompactAt is non-zero only for a git-remote resource. It is deliberately
	// server-visible so the server can refuse grants/public links for this resource
	// class and retain the per-repository compaction threshold without learning the
	// sealed repository name, refs, or bundle structure.
	CompactAt     int      `json:"compactAt,omitempty"`
	ExpireSeconds int64    `json:"expireSeconds,omitempty"`
	MaxReads      int64    `json:"maxReads,omitempty"`
	OnExpiry      OnExpiry `json:"onExpiry,omitempty"`
	// IdempotencyKey is carried in the HTTP Idempotency-Key header, not the body.
	IdempotencyKey string `json:"-"`
	// RevokeGrantee drops that grantee's grant in the same transaction as the write.
	// Revocation is a key rotation plus a row delete, and the two must not be separable:
	// if the rotation lands and the delete is lost, the stale row is still listed as a
	// grant, so the next rotation re-wraps the new key to the account that was revoked.
	// Ignored on a create (a new resource has no grants). Empty means revoke nobody.
	RevokeGrantee string `json:"revokeGrantee,omitempty"`
}

// OnExpiry selects what a server does with a resource once its link's lifecycle
// policy fires (the expiry passes, or the read limit is reached). The server cannot
// choose for itself: the metadata is sealed, so it cannot tell an ephemeral upload
// from a link over content the owner still depends on.
type OnExpiry string

const (
	// ExpiryReclaim destroys the content: blobs deleted, objects unrooted, the owner's
	// wrapped key cleared, and the row left as a tombstone that returns 410 forever.
	// This is what `push --public --burn` asks for, and what every server that predates
	// the field does unconditionally — so it is also the zero value.
	ExpiryReclaim OnExpiry = "reclaim"
	// ExpiryRetire only takes the link down: visibility flips back to private and the
	// policy clears, leaving the blobs, objects and wrapped key untouched. Sharing a
	// resource that already exists — above all a synced folder, whose server-side copy
	// every other device pulls from — must not let a link's expiry destroy the data
	// behind it.
	ExpiryRetire OnExpiry = "retire"
)

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

// PublicObjectsRequest asks the unauthenticated public-read endpoint for a set of a
// public resource's referenced object slices. The response is not JSON but a binary
// framing (one length-prefixed frame per requested id, in request order), so there
// is no matching response type here.
type PublicObjectsRequest struct {
	IDs []string `json:"ids"`
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

// PutResourceResponse acknowledges a resource write. ExpiresAt (absolute unix
// seconds, 0 = none), MaxReads (0 = none) and OnExpiry echo the lifecycle policy the
// server accepted. The echo is the enforcement handshake: an old server that ignores
// the policy request fields echoes nothing, so a new client can fail closed rather
// than mint a link the server will not actually expire — or, for OnExpiry, one whose
// expiry would destroy content the client meant to keep.
type PutResourceResponse struct {
	ID        string   `json:"id"`
	Version   int      `json:"version"`
	ExpiresAt int64    `json:"expiresAt,omitempty"`
	MaxReads  int64    `json:"maxReads,omitempty"`
	OnExpiry  OnExpiry `json:"onExpiry,omitempty"`
}

// SetVisibilityRequest flips a resource public/private without re-uploading its
// blob. Used by `share` (private → public); making private again instead rotates
// the content key via a full PutResource.
type SetVisibilityRequest struct {
	Visibility      Visibility `json:"visibility"`
	ExpectedVersion int        `json:"expectedVersion,omitempty"`
	// ExpireSeconds and MaxReads apply (or replace) a lifecycle policy on the public
	// link, so a policy can be attached after the fact by `aqt share`. Applying a
	// policy resets the read counter; flipping to Private clears the policy entirely.
	// Zero means "no limit". See PutResourceRequest for the TTL rationale. OnExpiry
	// selects what firing the policy does; `aqt share` asks for ExpiryRetire, since the
	// resource it is sharing existed before the link and must outlive it.
	ExpireSeconds int64    `json:"expireSeconds,omitempty"`
	MaxReads      int64    `json:"maxReads,omitempty"`
	OnExpiry      OnExpiry `json:"onExpiry,omitempty"`
}

// UpdateResourceMetadataRequest replaces only the client-sealed metadata blob.
// The server cannot inspect it; ExpectedVersion prevents a rename based on stale
// metadata from racing a sync or another rename.
type UpdateResourceMetadataRequest struct {
	EncryptedMeta   crypto.SealedBlob `json:"encryptedMeta"`
	ExpectedVersion int               `json:"expectedVersion"`
}

// GetResourceResponse is an in-process type: on the wire it travels as the raw
// envelope in wire.go (JSON header + ciphertext), never as JSON.
type GetResourceResponse struct {
	ID            string             `json:"id"`
	Visibility    Visibility         `json:"visibility"`
	Blob          crypto.SealedBlob  `json:"blob"`
	EncryptedMeta crypto.SealedBlob  `json:"encryptedMeta"`
	WrappedKey    *crypto.WrappedKey `json:"wrappedKey,omitempty"`
	// GrantKey is set instead of WrappedKey when the read was served through an
	// account grant: the content key HPKE-wrapped to the caller (crypto.UnwrapGrant
	// opens it). Owner carries the resource owner's opaque handle on those reads,
	// which the grantee needs for the wrap's info binding; a wrong value from a
	// hostile server just fails the unwrap.
	GrantKey []byte `json:"grantKey,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Version  int    `json:"version"`
	// MinClient is the lowest client capability that can read this resource's sealed
	// formats, so a current client can explain an incompatible remote instead of
	// failing to decrypt. 0 from an older server means "unknown" (treat as baseline).
	MinClient int   `json:"minClient,omitempty"`
	CompactAt int   `json:"compactAt,omitempty"`
	ExpiresAt int64 `json:"expiresAt,omitempty"`
	MaxReads  int64 `json:"maxReads,omitempty"`
	Reads     int64 `json:"reads,omitempty"`
	CreatedAt int64 `json:"createdAt,omitempty"`
	UpdatedAt int64 `json:"updatedAt,omitempty"`
}

// PublicResourcePreflight is the uncounted browser-share inspection response. It
// deliberately omits resource ciphertext and owner key material: recipients get
// only the encrypted metadata and lifecycle facts needed to decide whether a
// counted browser fetch is supported and worth consuming.
type PublicResourcePreflight struct {
	ID            string            `json:"id"`
	EncryptedMeta crypto.SealedBlob `json:"encryptedMeta"`
	MinClient     int               `json:"minClient"`
	ExpiresAt     int64             `json:"expiresAt,omitempty"`
	MaxReads      int64             `json:"maxReads,omitempty"`
	Reads         int64             `json:"reads,omitempty"`
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
	CompactAt     int                `json:"compactAt,omitempty"`
	// AutoSnapshot reports whether the server's scheduled snapshot job covers this
	// resource, so `snapshot auto` can show coverage without a per-resource fetch.
	AutoSnapshot bool `json:"autoSnapshot"`
	// Link lifecycle policy, echoed so `aqt share ls` can answer "who has access,
	// for how long?" without a per-resource fetch. Owner-only endpoint, so this
	// reveals nothing beyond what the owner set. All zero when the link has no
	// policy (or the server predates these fields).
	ExpiresAt int64 `json:"expiresAt,omitempty"`
	MaxReads  int64 `json:"maxReads,omitempty"`
	Reads     int64 `json:"reads,omitempty"`
	CreatedAt int64 `json:"createdAt,omitempty"`
	UpdatedAt int64 `json:"updatedAt,omitempty"`
}

type ListResourcesResponse struct {
	Resources []ResourceListItem `json:"resources"`
	// NextCursor is the opaque cursor to fetch the following page: pass it as
	// ?cursor= on the next request. Empty when this is the last page. A caller that
	// wants the whole set follows it until empty; the Go client does this
	// transparently so its list methods still return the full slice.
	NextCursor string `json:"nextCursor,omitempty"`
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
	// NextCursor is the opaque cursor to pass as ?cursor= for the following page;
	// empty on the last page. See ListResourcesResponse for the paging contract.
	NextCursor string `json:"nextCursor,omitempty"`
}

// UsageResponse summarizes the calling account's storage: pack bytes stored
// against the server's per-owner quota (0 = unlimited) plus row counts.
// Resources counts live entries only, not reclaimed link tombstones.
type UsageResponse struct {
	StorageBytes int64 `json:"storageBytes"`
	QuotaBytes   int64 `json:"quotaBytes,omitempty"`
	Packs        int64 `json:"packs"`
	Objects      int64 `json:"objects"`
	Resources    int64 `json:"resources"`
	Snapshots    int64 `json:"snapshots"`
	Devices      int64 `json:"devices"`
	MaxResources int64 `json:"maxResources,omitempty"`
	MaxSnapshots int64 `json:"maxSnapshots,omitempty"`
	MaxObjects   int64 `json:"maxObjects,omitempty"`
	MaxDevices   int64 `json:"maxDevices,omitempty"`
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
	// Anchored marks a snapshot retention must never prune. It is a plaintext
	// server-side flag (like the scheduled marker): retention acts on it without a
	// key, and it leaks only "this snapshot is protected" — the same shape of leak as
	// scheduled — while the name stays sealed in EncryptedLabel.
	Anchored bool `json:"anchored,omitempty"`
	// Automatic marks snapshots created by scheduled retention or a client-side
	// maintenance operation such as git-remote compaction. Auto-retention may prune
	// these; manual and anchored snapshots remain untouched.
	Automatic bool `json:"automatic,omitempty"`
}

// CreateSnapshotRequest pins the current version of a resource the caller owns.
// The server reads the resource's live blob and chunk roots and copies both into
// an immutable snapshot; no plaintext or key is sent (the snapshot reuses the
// already-stored ciphertext). EncryptedLabel, when set, is the client-sealed label
// stored opaquely alongside.
type CreateSnapshotRequest struct {
	ResourceID     string             `json:"resourceId"`
	EncryptedLabel *crypto.SealedBlob `json:"encryptedLabel,omitempty"`
	// Anchor pins the new snapshot against retention (see SnapshotInfo.Anchored). Set
	// by `aqt checkpoint`; a plain `snapshot create` leaves it false.
	Anchor         bool   `json:"anchor,omitempty"`
	Automatic      bool   `json:"automatic,omitempty"`
	IdempotencyKey string `json:"-"`
}

// SetSnapshotAnchorRequest toggles a snapshot's anchor: an anchored snapshot is
// exempt from every retention path and cannot be pruned until unanchored.
type SetSnapshotAnchorRequest struct {
	Anchored bool `json:"anchored"`
}

type ListSnapshotsResponse struct {
	Snapshots []SnapshotInfo `json:"snapshots"`
	// NextCursor is the opaque cursor to pass as ?cursor= for the following page;
	// empty on the last page. See ListResourcesResponse for the paging contract.
	NextCursor string `json:"nextCursor,omitempty"`
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
	MinClient int `json:"minClient,omitempty"`
	// RetryAfterSeconds accompanies a rate-limited (429) error, mirroring the
	// Retry-After header for clients behind an intermediary that strips it. The
	// header stays authoritative whenever it survives and parses.
	RetryAfterSeconds int    `json:"retryAfterSeconds,omitempty"`
	LimitKind         string `json:"limitKind,omitempty"`
	Current           int64  `json:"current,omitempty"`
	Limit             int64  `json:"limit,omitempty"`
}
