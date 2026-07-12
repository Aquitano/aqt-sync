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

`api.ClientCapability` is the highest a build supports; it is `2` today. Negotiation
itself changes no encrypted format, so shipping it did not bump the number.

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
  `{ "error": "...", "code": "upgrade_required", "min_client": <n> }` and no payload.
  The client maps this to `client.ErrUpgradeRequired` (exit code `6`) and prints the
  server's message verbatim.
- Write-side validation: a declared `minClient` above the writer's own capability is
  `400` (a client cannot write content it could never read back); an omitted
  declaration stores `1` (a legacy writer never over-restricts a resource). An update
  *may* lower `min_client` — a capable client legitimately rewrites a resource in an
  older format, making it readable by older clients again.

### The missing-header rule

A request with no `X-Aqt-Capability` header, or an unparseable one, is assumed to be
capability **2**. The header ships only after v0.2.0, so any header-less request comes
from a client no newer than v0.2.x, whose newest release reads capability-2 (id-bound)
resources. Assuming `2` keeps released v0.2.0 binaries working against id-bound
resources; genuinely pre-0.2 clients are indistinguishable from v0.2.x on the wire, so
they keep the status-quo AEAD failure — but only on capability-2 resources, the
boundary that predates the mechanism. A malformed value is a client bug, not an attack
surface, so it also assumes `2` rather than rejecting.

Because of this rule, negotiation cannot retroactively protect the v0.2.0 id-binding
boundary (a pre-0.2 client is assumed to be `2` and still hits the AEAD failure on an
id-bound resource). It protects the **next** boundary, once every reader advertises a
capability.

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
public again. `aqt private <id>` rotates the key, which is what kills every link ever
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
