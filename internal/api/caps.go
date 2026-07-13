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
	// ClientCapability is the highest format this build can read.
	ClientCapability = CapabilityRootKeyRotation
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
// message (which names the `aqt snapshot anchor --remove` escape hatch) instead.
const ErrCodeSnapshotAnchored = "snapshot_anchored"

// ErrCodeGone is the stable ErrorResponse.Code the server returns with an HTTP 410
// when a public link has expired, reached its read limit, or been reclaimed.
const ErrCodeGone = "gone"
