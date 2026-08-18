// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// Capability is a small, monotonically increasing integer describing which
// encrypted-resource formats a client can read. Bump it whenever a write format
// becomes unreadable by an older release, so the server can turn an under-capable
// client's read into an actionable HTTP 426 "upgrade required" instead of letting
// it surface as an opaque AEAD failure.
const (
	// CapabilityBaseline is v0.1.0: unbound (v1 AAD) resource roots and metadata.
	CapabilityBaseline = 1
	// CapabilityIDBinding is v0.2.0: resource-id-bound (v2 AAD) roots and metadata.
	CapabilityIDBinding = 2
	// CapabilityRootKeyRotation is the first release that can rotate an account
	// root key and migrate the identities derived from it.
	CapabilityRootKeyRotation = 3
	// CapabilityGitRemote is the first release that understands sealed Git remote
	// roots and the server-side policy attached to them.
	CapabilityGitRemote = 4
	// ClientCapability is the highest format this build can read.
	ClientCapability = CapabilityGitRemote
)

// CapabilityHeader carries a request's client capability. Missing or malformed
// values are treated as baseline-only: legacy clients can never receive a format
// they cannot read.
const CapabilityHeader = "X-Aqt-Capability"

// ErrCodeUpgradeRequired is the stable ErrorResponse.Code the server returns with an
// HTTP 426 when a resource's declared min_client exceeds the requester's capability.
const ErrCodeUpgradeRequired = "upgrade_required"

// ErrCodeSnapshotAnchored is the stable ErrorResponse.Code the server returns with an
// HTTP 409 when a prune targets an anchored snapshot. A 409 alone maps to a generic
// version conflict on the client, so the code lets it surface the anchored-specific
// message (which names the `aqt snapshot unanchor` escape hatch) instead.
const ErrCodeSnapshotAnchored = "snapshot_anchored"

// ErrCodeGone is the stable ErrorResponse.Code the server returns with an HTTP 410
// when a public link has expired, reached its read limit, or been reclaimed.
const ErrCodeGone = "gone"

// Stable ErrorResponse.Code tags for the remaining distinct error conditions, so a
// client branches on a machine-readable code instead of string-matching prose (and
// so the server need not echo a raw Go error whose text may carry internal detail).
const (
	// ErrCodeVersionConflict accompanies a 409 when an update's ExpectedVersion no
	// longer matches the stored version (a concurrent write moved it).
	ErrCodeVersionConflict = "version_conflict"
	// ErrCodeQuotaExceeded accompanies a 507 when storing a pack would push the owner
	// past their configured storage quota.
	ErrCodeQuotaExceeded = "quota_exceeded"
	// ErrCodeDeviceLimit accompanies a 403 when attaching a device would exceed the
	// account's device cap.
	ErrCodeDeviceLimit = "device_limit"
	// ErrCodeBadPack accompanies a 400 when an uploaded pack is malformed or fails the
	// server's content-address / slice verification.
	ErrCodeBadPack = "bad_pack"
	// ErrCodeResourceTooLarge accompanies a 400 when a resource upload's envelope
	// header exceeds the wire cap. ChunkRefs is the only field that can grow that
	// far, so it means the folder's chunk-ref set no longer fits one manifest PUT —
	// distinct from a corrupt envelope, which no retry or resize would fix either.
	ErrCodeResourceTooLarge = "resource_too_large"
	// ErrCodeNotFound accompanies a 404 for a missing (or foreign-owned) resource,
	// device, snapshot, or grant.
	ErrCodeNotFound = "not_found"
	// ErrCodeInvalidCursor accompanies a 400 when a pagination cursor does not decode.
	ErrCodeInvalidCursor = "invalid_cursor"
	// ErrCodeInvalidLimit accompanies a 400 when a pagination limit is not a positive
	// integer.
	ErrCodeInvalidLimit = "invalid_limit"
	// ErrCodeTooManyIDs accompanies a 400 when a check/locate/object request carries
	// more ids than the per-request cap allows.
	ErrCodeTooManyIDs = "too_many_ids"
	// ErrCodeGrantLimit accompanies a 400 when a resource already carries the maximum
	// number of grants.
	ErrCodeGrantLimit = "grant_limit"
	// ErrCodeBlockLimit accompanies a 400 when an account's share-block list is full,
	// so a client can tell "lift a block first" from a malformed request.
	ErrCodeBlockLimit = "block_limit"
	// ErrCodeSenderBlocked accompanies a 403 when the grantee has blocked incoming
	// grants from the caller. It is the one place a grant write distinguishes a real
	// account from a decoy, and only to the one account the grantee deliberately
	// blocked; answering 201 and dropping the row would tell the owner their grant
	// landed when nobody will ever see it.
	ErrCodeSenderBlocked = "sender_blocked"
	// ErrCodeAccountExists accompanies a 409 when a signup names an email that already
	// has an account AND proves ownership of it, so confirming its existence leaks
	// nothing. A signup that cannot prove ownership never sees this code.
	ErrCodeAccountExists = "account_exists"
	// ErrCodeRateLimited accompanies a 429. The response also carries Retry-After.
	ErrCodeRateLimited = "rate_limited"
	// ErrCodeInvalidPolicy accompanies a 400 when a link lifecycle policy is invalid
	// (attached to a private resource, or carrying a negative value).
	ErrCodeInvalidPolicy = "invalid_policy"
	// ErrCodeIdempotencyConflict means one key was reused for a different payload.
	ErrCodeIdempotencyConflict = "idempotency_conflict"
	// ErrCodeMissingChunks accompanies a 400 when a manifest's chunk refs name objects
	// the server no longer stores: GC swept an uploaded-but-unrooted pack because the
	// push outlived the age guard. Re-running sync re-uploads exactly the missing
	// chunks.
	ErrCodeMissingChunks = "missing_chunks"
	// ErrCodeAccountDisabled accompanies a 403 when an operator has suspended the
	// account. Distinct from a 401 so the client stops rather than looping through
	// re-authentication that cannot succeed.
	ErrCodeAccountDisabled = "account_disabled"
	// ErrCodeInviteRequired accompanies a 403 when signup on an invite-mode server
	// carries a missing or unrecognized invite token, so a client can prompt for a
	// token instead of treating it as a terminal refusal.
	ErrCodeInviteRequired = "invite_required"
	// ErrCodeInvalidChallenge accompanies a 401 when a device-attach names a
	// challenge that is expired, already consumed, or not the caller's. The
	// remediation is to request a fresh challenge and retry, distinct from
	// invalid_credentials where retrying the same inputs cannot succeed.
	ErrCodeInvalidChallenge = "invalid_challenge"
	// ErrCodeInvalidCredentials accompanies the single 401 a failed device-attach
	// collapses to: a missing account, a bad signature, and a bad passphrase
	// verifier are deliberately indistinguishable (no oracle), and the code tags
	// that one condition.
	ErrCodeInvalidCredentials = "invalid_credentials"
	// ErrCodeProofMismatch accompanies a 403 when the passphrase-derived proof on a
	// passphrase change, root-key rotation, or account deletion does not match, so a
	// client re-prompts for the passphrase rather than failing the operation.
	ErrCodeProofMismatch = "proof_mismatch"
	// ErrCodeGitRemotePolicy accompanies a 400 when an operation would expose or
	// reclassify a sealed Git remote resource (share it, make it public, or change
	// its kind).
	ErrCodeGitRemotePolicy = "git_remote_policy"
	// ErrCodeSharedNeedsRefs accompanies a 400 when a refs-less write targets a
	// public or granted resource that has chunk refs. ChunkRefs are the
	// read-authorization scope for non-owner object fetches, so a shared resource
	// must carry them even though private writes may omit them.
	ErrCodeSharedNeedsRefs = "shared_needs_refs"
)

// Status-bucket codes: the generic Code an error carries when the HTTP status is
// the whole distinction a client needs. Every error response carries a Code — a
// condition a client branches on more finely than the status gets one of the
// condition codes above; everything else gets the bucket for its status. Each name
// is the status it buckets, and bucket codes are as stable as condition codes: never
// renamed or repurposed.
const (
	ErrCodeInvalidRequest   = "invalid_request"
	ErrCodeUnauthorized     = "unauthorized"
	ErrCodeForbidden        = "forbidden"
	ErrCodeNotAcceptable    = "not_acceptable"
	ErrCodePayloadTooLarge  = "payload_too_large"
	ErrCodeUnsupportedMedia = "unsupported_media_type"
	// ErrCodeInternal buckets every 5xx; its message never carries internal detail.
	ErrCodeInternal = "internal"
)
