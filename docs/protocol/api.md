# Server HTTP API

Zero-knowledge REST over HTTPS. Auth is a bearer device token (`Authorization:
Bearer <token>`); the server authenticates *accounts*, never sees keys. All bodies
are opaque bytes or opaque metadata.

This is the wire contract. The compatibility *policy* built on top of it — which
capability number belongs to which release, how to stage a format bump, what the
client prints on a `426` — is [`../compatibility.md`](../compatibility.md). Operator
configuration (quotas, rate limits, TLS, proxies) is
[`../deploy.md`](../deploy.md), which is authoritative for defaults.

## Request contract

**Capability header.** Every request carries `X-Aqt-Capability: <n>`, a small
integer naming the highest encrypted-resource format the client can read. A resource
write may declare `minClient` — the lowest capability that can read the formats it
seals — which the server stores per resource and copies onto snapshots taken from it.
On a read (`GET /v1/resources/:id`, snapshot fetch) or an overwriting write, a
requester whose capability is below the resource's stored `min_client` gets
`426 Upgrade Required` with a structured body
(`{ error, code: "upgrade_required", minClient }`) *before* any payload — an
actionable "upgrade aqt" instead of a downstream decryption failure. A request with
no (or an unparseable) capability header fails closed to `1` (baseline). A declared
`minClient` above the writer's own capability is rejected `400`; an omitted
declaration stores the baseline.

`GET /v1/resources` is the deliberate exception: the listing never `426`s, because
refusing the whole list over one too-new row would hide every resource the client
*can* read. Each item echoes its `minClient` instead, and a client below that bar
names the release the row needs rather than rendering it as unreadable.

**Media types.** Resource representations are explicit, versioned contracts:

- JSON: `application/vnd.aqt.resource+json; version=1`
- Binary resource envelope: `application/vnd.aqt.resource+octet-stream; version=1`
- Object frames: `application/vnd.aqt.object-frames; version=1`

`Accept` selection honors media parameters and quality values; if none of the
offered representations is supported the server returns `406`. Resource writes accept
the versioned JSON or envelope media type and return `415` for unsupported or
malformed `Content-Type` values. The unversioned `application/json` and
`application/octet-stream` forms stay accepted as aliases, so a hand-rolled request
(`curl`) does not have to name a versioned media type.
Public DTO fields are lower camel case and do not depend on Go field names.

The resource envelope is a four-byte unsigned big-endian JSON-header length, a
lower-camel JSON header of at most 32 MiB, then the sealed blob ciphertext as the
remainder. The request header carries visibility, sealed metadata, wrapped key, blob
nonce, chunk refs, expected version, minimum client capability, and lifecycle
policy. `chunkRefs` is the only header field that grows with the resource — one
64-hex id per ref — so the 32 MiB header bound caps a *shared* folder's chunk
count at roughly 500k (about 3.8 GiB at the official client's default ~8 KiB chunk
profile); a header past the bound is `400 resource_too_large`. A private write
omits `chunkRefs` entirely (see client-managed GC below), so private folders have
no such ceiling. The response header also carries the resource id and accepted
version.
Object-frame responses repeat a four-byte unsigned big-endian length followed by
exactly that object ciphertext, in request order. Object requests are capped at
10,000 ids and every decoded length is bounds-checked before allocation or slicing.

**Concurrency and replay.** Resource and snapshot creates may send an
`Idempotency-Key` of at most 128 bytes. Keys are scoped to the account and operation,
recorded atomically with the create, and replay the original stable response. Reusing
a key for another payload returns `409 idempotency_conflict`. The official client
retries only these key-backed creates. Replacements use `expectedVersion`; visibility
changes include the same field, and deletes use an `If-Match` resource version. Stale
mutations return `409 version_conflict`. Creates return `201`; replacements and
in-place mutations return `200` (or `204` when no response body is defined). The one
exception is the grant upsert: re-posting an existing grantee — the rotation path —
returns `201` with no body, like the first post.

## Routes

```text
POST   /v1/account                  Create account. Body: { email, kdf, publicKey, wrappedRoot,
                                     authVerifier, deviceName, inviteToken? }
                                     → { ownerHandle, deviceId, token }  (stores kdf + Ed25519 public key)
GET    /v1/account/salt?email=…      → { kdf, wrappedRoot }  (needed to re-derive on a new machine;
                                     an unknown email gets an indistinguishable decoy — see the
                                     threat model's account-enumeration section)
POST   /v1/auth/challenge            Body: { email } → { challengeId, nonce }  (one-time, short-lived)
POST   /v1/devices                   Attach device. Body: { email, challengeId, signature,
                                     authVerifier, deviceName }.
                                     Server verifies the Ed25519 signature over the nonce — no secret sent. → { deviceId, token }
GET    /v1/devices                   List the account's attached devices (owner token).
                                     Paginated (?limit=, ?cursor=)
                                     → { devices: [{ id, name }], nextCursor? }
                                     The server never marks a device; `current` is a client-side
                                     annotation the CLI adds for its own device. Names are
                                     client-supplied labels, not secrets.
DELETE /v1/devices/:id               Revoke a device.
DELETE /v1/account                   Erase the account and everything under it. Body: { authVerifier }
                                     — the passphrase proof, so a device token alone cannot destroy an
                                     account. 400 if it is absent, 403 if it does not match or the
                                     account is suspended.
                                     → { ownerHandle, resources, snapshots, devices, packs, objects,
                                         grants, bytes?, fileErrors? }  (a receipt; every token dies)

POST   /v1/resources                 Create (server-assigned id). Same body/echo as PUT below.
PUT    /v1/resources                 Replace in place (id set, owner-checked, version++). An id-less body
                                     is also accepted here and dispatched as a create.
                                     Body: { blob, encryptedMeta, visibility,
                                             wrappedKey?, expireSeconds?, maxReads? }  // blob = { nonce, ciphertext };
                                                                                       // wrappedKey only for private;
                                                                                       // policy only for public
                                     → { id, version, expiresAt?, maxReads?, onExpiry? }  // echoes the accepted policy
GET    /v1/resources/:id             → { blob, encryptedMeta, visibility, wrappedKey?, version }
                                     Public ids are fetchable without auth. A private id needs the owner
                                     token OR a grant to the caller; a grantee gets the grant wrap and the
                                     owner handle in place of the owner's wrapped key (see grants below).
                                     Anyone else gets 404, so a private id is not an existence oracle.
                                     410 Gone (code "gone") if the public link has expired, exhausted its
                                     read limit, or been reclaimed. Owner reads are never counted or expired
                                     (until reclaimed).
POST   /v1/resources/:id/visibility  Body: { visibility, expireSeconds?, maxReads?, chunkRefs? }
                                     Used by `share`/`unshare`; rotation just replaces the blob. Echoes the
                                     accepted policy; a private flip clears it. A public flip sends the
                                     resource's current chunkRefs: refs-less private pushes leave the stored
                                     read scope stale, and this is the operation that mints readers.
DELETE /v1/resources/:id
GET    /v1/resources                 List owner's resources (ids + encrypted meta + visibility + minClient +
                                     grantCount, so `share ls` skips grant fetches for ungranted resources).
                                     Never 426s (see the capability header above). Paginated
                                     (?limit=, ?cursor=) → { resources, nextCursor? }; see pagination below.
PUT    /v1/resources/:id/metadata    Replace only the sealed metadata (a rename), leaving the blob
                                     and objects untouched. Owner only, `expectedVersion`-checked.
POST   /v1/public/resources/:id/objects  Unauthenticated. Body: { ids } → positional length-prefixed
                                     object slices. Serves exact objects of a PUBLIC resource, each id
                                     of which must be referenced by that resource (the share-link read
                                     path for a public/gated streamed file or folder). ≤10,000 ids per call.
GET    /v1/public/resources/:id/preflight  Unauthenticated, uncounted. → { id, encryptedMeta, minClient,
                                     expiresAt?, maxReads?, reads? }. Lets the browser share page decide
                                     whether a counted fetch is supported and worth spending, without
                                     serving ciphertext or key material. 410 like any dead link.

# Account maintenance (owner token). None of these re-encrypt a resource:
PUT    /v1/account/passphrase        Re-wrap the root key under a new passphrase. Bumps the auth epoch
                                     (every other device's token dies) and rotates the stored verifier.
PUT    /v1/account/root-key          Compromise recovery: swap in a fresh root key with every re-wrapped
                                     key and migrated identity, atomically, keeping only this device.
GET    /v1/account/usage             → { storageBytes, quotaBytes?, packs, objects, resources, snapshots,
                                     devices, max*? }  What `aqt usage` reports, including the caps that
                                     actually apply to this account.

# Snapshots (owner token): immutable copies of a resource version, held as roots by
# a client prune's reachability walk. The
# ciphertext is reused, not re-uploaded, and min_client is copied from the source at
# capture time so a restore is gated exactly like a resource read:
POST   /v1/snapshots                 Body: { resourceId, encryptedLabel?, anchor?, automatic? } → SnapshotInfo
GET    /v1/snapshots                 List (?resource=, ?limit=, ?cursor=) → { snapshots, nextCursor? }
GET    /v1/snapshots/:id             → { snapshot, blob, minClient? }; 426 like a resource read.
POST   /v1/snapshots/:id/anchor      Body: { anchored }. An anchored snapshot is exempt from every
                                     retention path; deleting one is 409 `snapshot_anchored`.
DELETE /v1/snapshots/:id
POST   /v1/resources/:id/auto-snapshot   Body: { enabled }. Per-resource opt-out from the server's
                                     scheduled snapshot job.

# Account-to-account grants (read-only). A grant is the resource's content key
# HPKE-wrapped (RFC 9180, X25519+ChaCha20-Poly1305) client-side to the grantee's
# published enc key, bound via HPKE info to (resource id, owner handle, grantee
# handle); the server stores and serves it opaquely. GET /v1/resources/:id honors
# a grant like ownership on the READ path only (returns the grant wrap + owner
# handle instead of the owner's wrapped key); every mutation stays owner-scoped:
GET    /v1/account/keys?email=...    Grant-target lookup: { handle, publicKey, encPublicKey, encKeySig }.
                                     Unknown emails (or accounts predating enc keys) get a deterministic,
                                     correctly self-signed decoy — no existence oracle.
PUT    /v1/account/enc-key           Backfill the caller's X25519 enc key; the Ed25519 self-signature is
                                     verified against the account identity key before storing.
POST   /v1/resources/:id/grants      Owner only. Body: { granteeHandle, wrappedKey, chunkRefs? }. Upsert
                                     (rotation re-wraps by re-posting). chunkRefs refreshes the read scope
                                     like the visibility flip above, for the same reason. No grantee-
                                     existence check (decoy handles must be accepted indistinguishably).
GET    /v1/resources/:id/grants      Owner only: { grants: [{ granteeHandle, createdAt }], nextCursor? }.
                                     Paginated (see below).
DELETE /v1/resources/:id/grants/:grantee  Revoke one grant. The client then rotates the content key
                                     (private resources) and re-wraps surviving grantees.
GET    /v1/shares                    Grantee-scoped incoming grants (id, ownerHandle, wrap, sealed meta). Paginated.
DELETE /v1/shares/:id                Grantee only (predicate: grantee_handle = caller). Declines one incoming
                                     grant → { ownerHandle, removed, blocked }. ?block=true also refuses that
                                     account's future grants (403 sender_blocked) and drops the shares it has
                                     already sent; 400 block_limit when the caller's block list is full.
                                     Never bumps resources.version: that is the owner's CAS token.
GET    /v1/share-blocks              Accounts the caller refuses grants from:
                                     { blocks: [{ ownerHandle, createdAt }], nextCursor? }. Paginated.
DELETE /v1/share-blocks/:owner       Lift one block.
POST   /v1/resources/:id/objects     Authed. Same body/framing/caps as the public variant, gated on
                                     ownership OR a grant instead of visibility — a grantee reads exact
                                     membership-checked slices, never raw pack ranges (packs interleave
                                     the owner's other resources).

# Tracked folders: the folder's blob is a sealed root pointing at the manifest
# objects, so it uses the resource routes above; a PUT of a public or granted
# resource additionally carries chunkRefs (file-object ids ∪ manifest-object ids
# the root references) as its readers' fetch scope. Objects ship inside raw packs;
# all routes require the owner token:
POST   /v1/chunks/check              Body: { ids } → { missing }   (have/want before packing). ≤10,000 ids/call.
POST   /v1/chunks/locate             Body: { ids } → { locations: [{ id, packId, off, len }] }. ≤10,000 ids/call.
PUT    /v1/packs/:id                  Body: raw pack bytes (octet-stream). id = sha256(pack);
                                     server verifies the address and every object slice. Range-able GET.
                                     → { storedObjects }
GET    /v1/packs/:id                  → raw pack bytes; supports Range (pull fetches only the needed span)
POST   /v1/gc                        Pack maintenance: sweeps packs a prune emptied, repacks sparse ones
                                     → { deletedPacks, freedBytes, repackedPacks, reclaimedBytes }

# Client-managed GC: clients compute reachability over their decrypted roots and
# prune; the server never decides an object is garbage on its own.
GET    /v1/chunks                    Complete object inventory, 10,000 ids per fixed page (?cursor=)
                                     → { ids, nextCursor }
POST   /v1/chunks/delete             Body: { ids } (≤10,000) → { deleted, skippedRecent, freedBytes }.
                                     Ids in packs inside the GC grace window are skipped, not failed —
                                     a concurrent push may be about to reference them.
```

## Client-managed garbage collection

Only the client can compute true reachability — it holds the keys — so garbage
collection is the client's job. The server keeps every stored object until its
owner explicitly deletes it through `POST /v1/chunks/delete` (the official
client's `aqt prune`, which decodes every resource and snapshot, diffs the
reachable closure against the `GET /v1/chunks` inventory, and deletes the rest).
The server's own maintenance only tidies what a prune leaves behind: it sweeps
emptied packs and compacts sparse ones, never choosing victims itself.

`chunkRefs` therefore no longer carries reachability. It survives for one job: the
scope of object ids a non-owner reader of a public or granted resource may fetch.
Private writes may omit it — which also lifts the header-size ceiling on private
folder size — while a refs-less write against a shared resource that has refs is
`400 shared_needs_refs`, and the operations that mint a reader (`SetVisibility`,
`POST /v1/resources/:id/grants`) accept `chunkRefs` to refresh the scope.

A current client assumes a current server: it never sends refs on a private write,
and a pre-client-GC server — whose sweep would read that as unreferenced data —
must not be pointed at by one. There is no negotiation; server and clients upgrade
together (pre-1.0 there is exactly one deployment). Deleting a resource only
unroots it (bytes return at the next prune); `DELETE /v1/account` still erases
everything immediately.

`GET /livez` is the liveness probe and `GET /readyz` admits traffic only while
storage is available and the server is not shutting down.

## Account deletion

`DELETE /v1/account` erases the account, its devices, resources, snapshots, grants,
objects, packs, and the ciphertext files behind them. Grants *to* the account go too:
its published key is gone, so those wraps could never be opened again.

The row deletions are one transaction and are authoritative; the files are unlinked
after it commits, so any the server could not remove are counted back in
`fileErrors` — the account is gone either way, but that ciphertext is still on the
operator's disk. `bytes` is the total `GET /v1/account/usage` reports, so it matches
what the caller confirmed against, and is absent rather than approximated if the
server could not read one.

The request carries the passphrase-derived verifier, checked inside the deleting
transaction, so a device token on its own is not authority to destroy an account and
a passphrase change cannot land between the proof and the erasure it authorizes. That
same read re-checks suspension, which the middleware answers from a cache an operator
in another process cannot invalidate; every other route tolerates that window, and
this one cannot.

An operator reaches the same store-level erasure through `aqt-server admin accounts
delete`, authorized by filesystem access to the data directory rather than by a
passphrase, and not through this route.

## Pagination

Every list endpoint (`/v1/resources`, `/v1/shares`, `/v1/share-blocks`,
`/v1/snapshots`, `/v1/devices`, `/v1/resources/:id/grants`) pages rather than buffering the whole set: `?limit=`
(default 100, clamped to 1000) and an opaque `?cursor=`; the response keeps its items
array and adds `nextCursor` (empty on the last page). Cursors are keyset seeks over
each list's ordering key, so paging is stable under concurrent inserts. A
non-positive `limit` is `400 invalid_limit`; a corrupt `cursor` is
`400 invalid_cursor`. The Go client follows `nextCursor` transparently, so its list
methods still return the whole slice to CLI callers.

## Error codes

Every error response carries a stable snake_case `code` in the `{ error, code }`
body, at one of two levels of precision. A shipped code is never renamed or
repurposed either way.

Condition codes tag the conditions a client branches on more finely than the HTTP
status — `upgrade_required`, `version_conflict`, `idempotency_conflict`,
`quota_exceeded`, `device_limit`, `bad_pack`, `gone`, `snapshot_anchored`,
`not_found`, `too_many_ids`, `grant_limit`, `sender_blocked`, `block_limit`,
`invalid_policy`, `invalid_cursor`, `invalid_limit`, `rate_limited`,
`account_exists`, `account_disabled`, `missing_chunks`
(the manifest's refs name objects the owner no longer stores — a prune reaped an
upload that outlived the grace period; re-running sync re-uploads them),
`invite_required`
(signup on an invite-mode server without a valid token), `invalid_challenge`
(request a fresh attach challenge and retry), `invalid_credentials` (the single
401 a failed attach collapses to; retrying the same inputs cannot succeed),
`proof_mismatch` (the passphrase-derived proof on a passphrase change, root-key
rotation, or account deletion did not match), `git_remote_policy` (the
operation would share, publish, or reclassify a sealed Git remote resource), and
`resource_too_large` (the upload's `chunkRefs` set overran the 32 MiB header), and
`shared_needs_refs` (a refs-less write targeted a public or granted resource, whose
`chunkRefs` scope non-owner reads) — so a client that acts on one of them matches
the code rather than the prose.

Every other error carries the bucket code for its status: `invalid_request`
(400), `unauthorized` (401), `forbidden` (403), `not_acceptable` (406),
`payload_too_large` (413), `unsupported_media_type` (415), and `internal` (any
5xx). For these the status is the whole distinction; the bucket code exists so
`code` is always present and a client never needs a missing-field special case.

The `error` message stays written for a human either way. Do not string-match it;
it is not a contract, and the server never echoes a raw Go error whose text might
carry internal detail. `426` additionally carries `minClient`.

## Rate limiting

The authenticated group is rate-limited per device token (a coarse token bucket with
a generous burst, so a large sync or clone is unaffected), with a second, far tighter
limiter on the expensive `POST /v1/gc` keyed per owner. Unauthenticated auth routes
are limited separately. The bucket key is the TCP peer address regardless of any
`X-Forwarded-*` header, so a spoofed header cannot mint fresh buckets. Limits are
configured in [`../deploy.md`](../deploy.md).

A throttled request is answered with `429 Too Many Requests` carrying the wait twice,
both derived from one limiter result:

- `Retry-After`, in the delay-seconds form, computed from the bucket's own refill
  rate — so observing it is exactly long enough, not a guess.
- `retryAfterSeconds` in the structured body, alongside `"code": "rate_limited"`.

The **header is authoritative** whenever it survives and parses. The body value
exists only as a fallback for an intermediary that strips unknown headers; a client
that sees both must prefer the header.

### Client behavior

- Both forms RFC 9110 defines are accepted: delay-seconds and an HTTP-date. A
  negative or unparseable value is rejected in favor of the next fallback; a value in
  the past, or below the floor, is raised to 1s; an excessive one is clamped to 30s,
  so a hostile server cannot park a client indefinitely.
- **One cooldown is shared across every request the client makes.** A sync fires many
  chunk, pack, and object requests concurrently against one bucket; without a shared
  floor each would ride out its own `Retry-After` and they would all wake together,
  reproducing the burst that tripped the limit. Any 429 publishes its deadline and
  every other in-flight request observes it before sending. A later deadline always
  wins over a shorter overlapping one.
- Each waiter adds its own bounded positive jitter (up to 750ms) above the shared
  deadline, so they do not resume on the same instant.
- Three budgets bound the retrying: at most 3 retries per request, at most 30s per
  wait, and at most 60s summed across one request's waits. Waits are cancellable, so
  `^C` during a backoff returns immediately.
- Only bodyless or replayable requests are retried. A request whose body cannot be
  rewound is never sent twice, whatever the server answers.
- Exhaustion returns `*client.RateLimitedError` (carrying `Attempts`, `LastDelay`,
  and `NextRetryAt`), which still satisfies `errors.Is(err, client.ErrRateLimited)`.
  It maps to **exit code 5**, the retryable network code, so cron and `watch --once`
  treat throttling as "try again later" rather than a permanent failure.

Neither signal changes an encrypted format, so `api.ClientCapability` is not bumped.
`Retry-After` is authoritative; `retryAfterSeconds` is the body fallback for a caller
that only parses JSON.

## Public-link lifecycle

`PUT /v1/resources` and the visibility endpoint accept an optional `expireSeconds`
(a TTL — the server stores `expires_at = now + expireSeconds`, so client clock skew
never matters) and `maxReads` on a public resource. The server enforces both: a
non-owner read past the expiry or the read limit gets `410 Gone` with
`{ error, code: "gone" }`; only successful non-owner serves count toward `maxReads`,
and concurrent reads cannot over-serve (the count is committed under a per-resource
lock).

Both responses **echo** the accepted policy (`expiresAt`, `maxReads`). That echo is
the enforcement handshake a client fails closed against; the handshake and the
`onExpiry` reclaim/retire distinction are documented in
[`../compatibility.md`](../compatibility.md#public-link-lifecycle-no-capability-bump).

Expired links (immediately) and exhausted ones (after a grace window so an in-flight
streamed pull can finish) are reclaimed by the GC sweep: the ciphertext blob and its
objects are deleted and the row kept as a `reclaimed` tombstone that keeps returning
`410` rather than decaying to `404`. The object-read endpoint 410s on
expiry/reclamation immediately, and on `maxReads` exhaustion only once the same
10-minute grace window has passed — inside it the objects keep serving, so the final
permitted streamed pull is never cut off mid-flight.

## What the server enforces

Ownership, visibility (a private id returns 404 to anyone but the owner),
public-link lifecycle (expiry and read limits), capability floors, quotas and rate
limits, and integrity at the storage layer. It performs **no** decryption, merge, or
filename inspection. An over-quota pack put returns `507`, which the client surfaces
distinctly.

Per-owner quotas cap physical storage — packs, resource blobs, retained snapshots,
and attributable database growth — plus resource, snapshot, object, and device
counts. The byte counter is maintained incrementally inside the pack put, GC, and
repack transactions (a column on `accounts`, backfilled on migration), so a quota
check is one indexed read and never scans the objects table. Every knob, its default,
and the per-account override are in [`../deploy.md`](../deploy.md).

Registration mode (`open` or `invite`) is an operator setting with a privacy
consequence; see [`../threat-model.md`](../threat-model.md#account-enumeration) for
what each mode does and does not close. A client whose server runs in invite mode
passes the token via `aqt signup --invite` (or `AQT_INVITE_TOKEN`); `aqt login`
attaches a device to an account that already exists and needs no invite.
