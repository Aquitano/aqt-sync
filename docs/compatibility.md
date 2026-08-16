# Client capability negotiation

Status: **implemented** in `internal/api` (`caps.go`), `internal/client`,
`internal/server`, and the `cmd/aqt` sealing sites.

This is the compatibility *policy*: which capability belongs to which release, how to
stage a format bump, and what a client does when it is refused. The wire mechanism it
rides on — the header, the `426` body, media types, `429` framing — is
[`protocol/api.md`](protocol/api.md).

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
| `3` (root rotation) | v0.4.1 | account root-key rotation and migrated identities |
| `4` (Git remote) | v0.5.0 | sealed `gitremote` RefsRoot resources and their private-only server policy |

The release column names the first version a user could install. Root-key rotation
appears under `v0.3.0` in the changelog, which was never tagged, and shipped in the
`v0.4.0` tag, which published no artifacts because its signing key was lost. Both are
recorded as such in the changelog. Capability 3 therefore first reached clients in
v0.4.1.

`api.ClientCapability` is `4` today. Capability 3 is required for root-key recovery;
capability 4 is required for encrypted Git remote resources. `aqt repo create` declares
`minClient: 4`, so older clients receive `426 Upgrade Required` before the server
serves or overwrites a root they cannot interpret.

## Support policy

aqt is pre-1.0 and has one maintainer. This is what that can actually keep, stated
narrowly so it is not quietly broken later.

- **The current capability level and the one below it stay readable.** A client at
  `ClientCapability` reads everything sealed at `ClientCapability` or one level below.
- **A format break lands only behind a capability bump.** Nothing changes an encrypted
  format without incrementing `ClientCapability` and declaring the higher `min_client`
  at the sealing site, so an under-capable client gets a `426` naming what to install
  rather than a decrypt failure it cannot diagnose.
- **A level stays readable for at least two minor releases, and is never dropped in a
  patch release.** Dropping one is a `### Breaking Changes` entry in `CHANGELOG.md`,
  announced at least one release before the one that does it.
- **Servers are backward compatible over the same window.** Nothing server-side
  refuses a client for being old except a resource's own `min_client`, so a current
  server serves a client one capability behind.
- **Nothing beyond that is promised.** There is no LTS line, no backport of fixes to
  old tags, and no support for a fleet running mixed versions longer than an upgrade
  takes. Fixes ship on `main` and in the next release.

Two clean breaks predate this policy and are not covered by it: tree v2 (first-class
directories and subtree dedup — folders written before it are not read at all) and
the v2 AAD id binding (a folder synced by an id-binding client no longer opens on a
client from before it). Both are recorded in `CHANGELOG.md`.

Negotiation is one-directional: a client announces its capability in a header and no
route reports back what the server supports, so every server-side feature that is not
a sealed format needs its own
[enforcement echo](#public-link-lifecycle-no-capability-bump) to probe for — a server
capability discovery endpoint is an open item.

## Negotiation flow

- Every client request carries `X-Aqt-Capability: <n>` (`api.CapabilityHeader`),
  set to `api.ClientCapability`.
- A write (`PUT /v1/resources`) may declare `minClient`: the lowest capability that
  can read the formats it seals. The sealing sites set it — id-bound folder updates
  and key rotation declare `2`; Git-remote roots declare `4`; unbound creates and
  one-shot `push` declare `1` (baseline). The server stores it per resource. A
  snapshot copies the value from its source resource at capture time.
- On a **read** (`GET /v1/resources/:id`, `GET /v1/snapshots/:id`) or an
  **overwriting write** of an existing resource, the server compares the requester's
  capability to the resource's stored `min_client`. If the requester is below it, the
  server answers `426 Upgrade Required` with
  `{ "error": "...", "code": "upgrade_required", "minClient": <n> }` and no payload.
  The client maps this to `client.ErrUpgradeRequired` (exit code `6`). See
  [Recovering from a 426](#recovering-from-a-426) for what it prints.
- Write-side validation: a declared `minClient` above the writer's own capability is
  `400` (a client cannot write content it could never read back); an omitted
  declaration stores `1` (a legacy writer never over-restricts a resource). An update
  *may* lower `min_client` — a capable client legitimately rewrites a resource in an
  older format, making it readable by older clients again.
- `GET /v1/resources` never `426`s: refusing an account's whole listing over one
  too-new row would hide everything else in it. Each row carries its `minClient`, and
  `aqt ls` renders a row above this build's capability as
  `(needs aqt supporting capability <n>)` — the same actionable answer a `426` gives,
  in the one place the status code cannot be used.

### Recovering from a 426

The message a user sees is composed by the client from facts it knows first-hand —
the running version, the capability this build declares, and the `minClient` the
server reported — not by echoing the server's prose. A compromised or hostile server
controls that prose, so treating it as the instruction would let it tell a user to
run anything. The server's text is still shown, but quoted as `(server said: …)` and
sanitized first: C0/C1 control bytes, DEL, and the Unicode format controls and
separators are stripped and the length is bounded, so it cannot emit escape
sequences, rewrite the line, reorder how the rest of it reads, or forge what looks
like a second line of aqt's own output.

The recovery action names the command that upgrades *this* installation:

| Install | Action in the message |
| ------- | --------------------- |
| standalone | ``run `aqt update` `` |
| build from source | ``rebuild it with `make build` or install a release`` |

`aqt update` only replaces a published release copy. The TUI shows the same routing
condensed to one line on exit `6`.

A server reporting a `minClient` at or below the running capability is contradicting
itself — it refused a client that clears the bar it named. The client reports the
next capability up rather than rendering a message that tells the user to reach a
level they already have.

`errors.Is(err, client.ErrUpgradeRequired)` and exit code `6` are unchanged;
`*client.UpgradeRequiredError` additionally carries `Capability` (what this build
declared) and `Detail` (the sanitized server text).

### The missing-header rule

Missing or malformed `X-Aqt-Capability` values are treated as capability **1**
(baseline), not as v0.2. This deliberately ends header-less compatibility at the
id-binding boundary: a legacy client trying to read a capability-2 or newer resource
receives `426 Upgrade Required` before any ciphertext is served, rather than a
downstream AEAD failure.

This is a breaking server policy for header-less v0.2-era binaries. Upgrade every
client before deploying it.

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
   `MinClient: api.Capability<New>` on the `PutResourceRequest`. `rg 'MinClient:'
   cmd/aqt` lists them all; today they are `cmd/aqt/sync.go`, `cmd/aqt/share.go`,
   `cmd/aqt/push.go`, `cmd/aqt/repo.go`, and the two root flips in
   `cmd/aqt/git_remote_helper.go`.
   Sites still writing an older format keep their lower declaration.
3. Add a `### Breaking Changes` / `### Changed` note to `CHANGELOG.md` and extend the
   capability table above.

No server change is needed to gate the new boundary — the `min_client` mechanism is
format-agnostic; it only compares integers.


## Resource wire protocol v1

The versioned media types, the resource envelope framing, object frames, and the
idempotency and optimistic-concurrency rules are specified in
[`protocol/api.md`](protocol/api.md#request-contract). None of them changes an
encrypted format, so none is gated by `api.ClientCapability`; the unversioned
`application/json` and `application/octet-stream` forms remain aliases for pre-v1
clients.

## Rate limiting (429)

The `429` contract — `Retry-After` as the authoritative signal, `retryAfterSeconds`
as the body fallback, and the client's shared cooldown, jitter, and retry budgets —
is specified in [`protocol/api.md`](protocol/api.md#rate-limiting).

Neither signal changes an encrypted format, so `api.ClientCapability` is not bumped.
An older server that sends only `Retry-After` interoperates unchanged; an older
client that ignores `retryAfterSeconds` reads the header as it always did.
