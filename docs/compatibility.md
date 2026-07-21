# Client capability negotiation

Status: **implemented** in `internal/api` (`caps.go`), `internal/client`,
`internal/server`, and the `cmd/aqt` sealing sites.

Encrypted-resource formats occasionally change in ways an older client cannot read
(the v0.2.0 id-binding boundary is the first). Without negotiation, an under-capable
client reads such a resource and fails deep in the crypto with a bare
`decrypt failed (wrong key or corrupted)` — indistinguishable from a real key error.
Capability negotiation replaces that with an actionable `426 Upgrade Required` at the
API layer, *before* any payload is served.

## Capability table

| Capability | Release | Formats it can read |
| ---------- | ------- | ------------------- |
| `1` (baseline)   | v0.1.0 | unbound (v1 AAD) roots and metadata |
| `2` (id-binding) | v0.2.0 | resource-id-bound (v2 AAD) roots, metadata, snapshot labels |
| `3` (root rotation) | v0.3.0 | account root-key rotation and migrated identities |

`api.ClientCapability` is `3` today. Capability 3 is required for the root-key recovery API because it changes the account signing and encryption identities.

## Negotiation flow

- Every client request carries `X-Aqt-Capability: <n>` (`api.CapabilityHeader`),
  set to `api.ClientCapability`.
- A write (`PUT /v1/resources`) may declare `minClient`: the lowest capability that
  can read the formats it seals. The sealing sites set it — id-bound folder/pack
  updates and key rotation declare `2`; unbound creates and one-shot `push` declare
  `1` (baseline). The server stores it per resource. A snapshot copies the value from
  its source resource at capture time.
- On a **read** (`GET /v1/resources/:id`, `GET /v1/snapshots/:id`) or an
  **overwriting write** of an existing resource, the server compares the requester's
  capability to the resource's stored `min_client`. If the requester is below it, the
  server answers `426 Upgrade Required` with
  `{ "error": "...", "code": "upgrade_required", "minClient": <n> }` and no payload.
  The client maps this to `client.ErrUpgradeRequired` (exit code `6`) and prints the
  server's message verbatim.
- Write-side validation: a declared `minClient` above the writer's own capability is
  `400` (a client cannot write content it could never read back); an omitted
  declaration stores `1` (a legacy writer never over-restricts a resource). An update
  *may* lower `min_client` — a capable client legitimately rewrites a resource in an
  older format, making it readable by older clients again.

### The missing-header rule

Missing or malformed `X-Aqt-Capability` values are treated as capability **1** (baseline), not as v0.2. This deliberately ends header-less compatibility at the id-binding boundary: a legacy client trying to read a capability-2 or newer resource receives `426 Upgrade Required` before any ciphertext is served, rather than a downstream AEAD failure.

This is a breaking server policy for header-less v0.2-era binaries. Upgrade every client before deploying it.

## Public-link lifecycle (no capability bump)

Server-enforced link lifecycle (`--expire`/`--max-reads`/`--burn`) is a separate
compatibility axis from the sealed-format capability above. It changes no encrypted
format, so `api.ClientCapability` is **not** bumped and no `min_client` is set for it.

Instead it uses an **enforcement echo**: a `PUT /v1/resources` (or visibility change)
that carries a policy gets the accepted `expiresAt`/`maxReads` echoed back in the
response. A server that predates the feature ignores the unknown request fields and
echoes nothing. A new client therefore **fails closed** — it deletes the just-created
resource (or reverts the visibility flip) and errors, rather than hand out a link the
server will never actually expire. Upgrade the server before relying on lifecycle flags.

### What expiry does to the resource (`onExpiry`)

A policy also says what firing it means, and the two answers are not interchangeable:

- `reclaim` — destroy the content: blobs deleted, objects unrooted, the owner's wrapped
  key cleared, and a tombstone that returns `410` forever. `aqt push --public` (with
  `--burn`/`--expire`) asks for this: the resource and its link were minted together.
- `retire` — take only the link down: visibility flips back to private and the policy
  clears, leaving the content, keys and objects untouched. `aqt share` asks for this,
  because the resource it links to existed first and outlives the link. A shared synced
  folder is still the copy every other device pulls from.

`onExpiry` rides the same echo. A server that predates it echoes nothing and reclaims
unconditionally, so a client that asked to `retire` fails closed rather than mint a link
whose expiry would delete the folder behind it. `reclaim` is the default everywhere, so
old clients and old servers keep their existing behavior.

Retiring does not rotate the content key — the server holds none — so an expired link's
fragment is dormant, not dead: it opens the resource again if the resource is ever made
public again. `aqt unshare <id>` rotates the key, which is what kills every link ever
issued for a resource.

Upgrade the **client** too, not just the server. A client that predates `onExpiry` cannot
ask for `retire`, so its `aqt share <folder> --expire` still reclaims the folder when the
link fires, and the server cannot second-guess it: resource metadata is sealed, so it
cannot tell a folder from an ephemeral paste.

## Rollout rules

- **Upgrade the server before clients.** Older servers have no `min_client` column and
  ignore the header, so they neither store nor enforce; new clients still interoperate
  (an old server returns `min_client` `0`, treated as baseline).
- **A new capability `N` is only safe to *write* once every reading device runs a
  client with capability ≥ `N`.** The server now enforces this: a write in the new
  format declares `min_client = N`, and any device below `N` reading it gets `426`
  instead of a silent AEAD failure. Stage a format bump by upgrading all readers
  first, then letting writers start declaring the higher `min_client`.

## Bumping the capability in a future PR

When a new write format lands that older releases cannot read:

1. Add the new constant to `internal/api/caps.go` and set
   `ClientCapability` to it.
2. At each sealing site that writes the new format, declare
   `MinClient: api.Capability<New>` on the `PutResourceRequest` (see
   `cmd/aqt/sync.go`, `cmd/aqt/pack.go`, `cmd/aqt/share.go`, `cmd/aqt/push.go`).
   Sites still writing an older format keep their lower declaration.
3. Add a `### Breaking Changes` / `### Changed` note to `CHANGELOG.md` and extend the
   capability table above.

No server change is needed to gate the new boundary — the `min_client` mechanism is
format-agnostic; it only compares integers.


## Resource wire protocol v1

Resource representations are explicit, versioned contracts:

- JSON: `application/vnd.aqt.resource+json; version=1`
- Binary resource envelope: `application/vnd.aqt.resource+octet-stream; version=1`
- Object frames: `application/vnd.aqt.object-frames; version=1`

`Accept` selection honors media parameters and quality values. If none of the offered representations is supported, the server returns `406`. Resource writes accept the versioned JSON or envelope media type and return `415` for unsupported or malformed `Content-Type` values. The unversioned `application/json` and `application/octet-stream` forms remain compatibility aliases for pre-v1 clients. Public DTO fields are lower camel case and do not depend on Go field names.

The resource envelope is a four-byte unsigned big-endian JSON-header length, a lower-camel JSON header of at most 32 MiB, then the sealed blob ciphertext as the remainder. The request header carries visibility, sealed metadata, wrapped key, blob nonce, chunk roots, expected version, minimum client capability, and lifecycle policy. The response header also carries the resource id and accepted version. Object-frame responses repeat a four-byte unsigned big-endian length followed by exactly that object ciphertext, in request order. Object requests are capped at 10,000 ids and every decoded length is bounds-checked before allocation or slicing.

Clients send `X-Aqt-Capability`; the server returns `426` before serving or overwriting a resource whose sealed format the client cannot read. Resource and snapshot creates may send an `Idempotency-Key` of at most 128 bytes. Keys are scoped to the account and operation, recorded atomically with the create, and replay the original stable response. Reusing a key for another payload returns `409 idempotency_conflict`. The official client retries only these key-backed creates. Replacements use `expectedVersion`; visibility changes include the same field, and deletes use an `If-Match` resource version. Stale mutations return `409 version_conflict`. Creates return `201`; replacements and in-place mutations return `200` (or `204` when no response body is defined).
