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
	// ErrCodeDropsRoots accompanies a 400 when a replace would clear every chunk root
	// of an object-backed resource.
	ErrCodeDropsRoots = "drops_roots"
)
