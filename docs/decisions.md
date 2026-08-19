# Decision log

Questions the original interface spec deliberately left open, and what became of
each. This is history, not specification: every entry says what was decided and
points at the document that now describes the resulting behavior. If the two ever
disagree, the linked document is right.

Entries appear in the order the questions were opened. `CHANGELOG.md` records which
release each landed in.

## Resolved before the first draft shipped

- **Device attach** became an Ed25519 challenge/response, so no secret is sent when a
  device joins an account. See
  [threat model](threat-model.md#the-wrapped-root-model).
- **Resources** gained owner-checked in-place update and a version counter, which is
  what later made optimistic concurrency (`expectedVersion`) possible. See
  [HTTP API](protocol/api.md#request-contract).
- **The passphrase** is cached per session rather than entered per command. See
  [threat model](threat-model.md#client-data-at-rest).

## Storage and sync

- **Large single files / streaming.** A single file at or above ~8 MiB streams
  through the chunk/pack pipeline instead of sealing whole in memory, private, public,
  or gated alike, so the inline body cap no longer bounds file size. Stdin has no size
  to threshold on and still seals inline. See
  [streamed single files](protocol/folder-sync.md#streamed-single-files).

- **Manifest size / subtree dedup.** A chunked folder became a Merkle DAG of
  content-addressed directory nodes rather than one flat manifest, so a moved or
  copied directory dedups for free and a no-op sync does zero node round-trips. It was
  a clean format break (`tree` flag, v2); older folders are not read. See
  [Merkle DAG](protocol/folder-sync.md#merkle-dag-of-directory-nodes).

- **Persistent metadata cache.** Tree walks share an on-disk, content-addressed cache
  of node and chunk-list ciphertexts. Because an object's id is the sha256 of its
  ciphertext, entries are immutable and self-verifying — no invalidation logic exists
  because none can be needed. See [node cache](protocol/folder-sync.md#node-cache).

- **Subpath addressing.** `aqt://<id>/<path>` walks only the path's spine instead of
  materializing the folder. Pack-and-seal folders refuse it, which is the privacy
  trade-off working as intended. See
  [subpath addressing](protocol/folder-sync.md#subpath-addressing).

- **Repack.** Chunk-granular pruning leaves dead bytes inside still-populated
  packs. `RepackOwner` copies the surviving objects into a fresh pack under a
  bounded byte budget and swaps atomically. See
  [garbage collection](protocol/folder-sync.md#garbage-collection).

- **Push throughput / upload overlap.** The push no longer stalls the chunker on each
  pack's two upload round-trips: a bounded pool keeps the CPU sealing the next pack
  while earlier ones are in flight, hiding server ingest time and, over a WAN, the
  sequential RTTs. Server-side, `PutPack` batches the object-index INSERTs, which was
  the dominant SQLite cost of a pack of many small chunks. See
  [storage layout](protocol/folder-sync.md#storage-layout).

- **Client-side crypto parallelism.** Chunk sealing fans across `GOMAXPROCS` workers
  while the split stays on the walk goroutine and one collector reassembles in stream
  order, so the manifest's chunk order is exactly the serial loop's. See
  [chunking and dedup](protocol/folder-sync.md#chunking-and-dedup).

- **Public whole-folder sharing.** Sharing a chunked folder needed no new object
  space: `chunkRefs` already list every node and chunk, so the membership-checked
  public object endpoint serves the whole DAG once the resource is public. See
  [public folder links](protocol/folder-sync.md#public-folder-links).

- **Conflict copies and text merge.** `sync` defaults to report-and-block; `copy`
  preserves the remote side beside a local-wins primary, and `merge` combines
  non-overlapping line edits without ever writing conflict markers, falling back to
  copy for everything it cannot take. See
  [conflict handling](protocol/folder-sync.md#conflict-handling).

## Crypto and identity

- **Argon2id tuning per machine.** The KDF is calibrated on the creating machine to a
  preset's target unlock time, stepping memory down toward a 64 MiB floor rather than
  missing the target. Parameters are public and travel with the account, so every
  device re-derives the same key. See
  [KDF calibration](threat-model.md#kdf-calibration).

- **Defense-in-depth crypto.** The resource id is bound into the AEAD additional data
  (`aqt-<role>-v2:<id>`), so a server swapping whole records between ids fails the tag
  check — and the id verified against is the client's own, not the server's echo.
  Chunk objects and directory nodes stay id-free because binding them would kill
  cross-resource dedup. Four bounded caveats are recorded with the mechanism. See
  [domain separation and record binding](threat-model.md#domain-separation-and-record-binding).

- **Session cache at rest.** The cached master key is sealed under a random
  per-profile key held in the OS keychain, with a machine-bound fallback for hosts
  that have no keychain backend. See
  [client data at rest](threat-model.md#client-data-at-rest).

- **Local base manifest at rest.** `.aqt/base.json` carries per-chunk keys and inline
  plaintext, so it is sealed under the same per-profile key with its own AAD; old
  plaintext bases are read transparently and upgraded on the next sync. See
  [client data at rest](threat-model.md#client-data-at-rest).

## Server exposure

- **Account-enumeration oracle.** `GET /v1/account/salt` returns an indistinguishable
  decoy for an unknown email, with costs drawn per-email from the value set a real
  calibration produces, and open-mode signup answers a duplicate with a success-shaped
  decoy rather than `409` — unless the caller proves ownership with the account's
  passphrase verifier, which does get `409 account_exists`. Only
  `AQT_REGISTRATION=invite` actually closes enumeration.
  See [account enumeration](threat-model.md#account-enumeration).

- **Authenticated-route abuse / quotas.** The authenticated group is rate-limited per
  device token with a tighter per-owner limiter on `POST /v1/gc`, and per-owner quotas
  cap physical storage plus resource, snapshot, object, and device counts. The byte
  counter is maintained incrementally inside the pack put, GC, and repack
  transactions, so a quota check never scans the objects table. See
  [what the server enforces](protocol/api.md#what-the-server-enforces) and
  [deploy.md](deploy.md).

- **Trusted proxies.** Gin's trust-all default was replaced with an explicit list
  (`AQT_TRUSTED_PROXIES`, loopback by default, `none` to trust none). The rate-limit
  bucket key stays on the TCP peer address regardless, so a spoofed forwarded header
  cannot mint fresh buckets. See [deploy.md](deploy.md#configuration).

## Still open

Four limits remain, deliberately. They are listed with the reasoning that keeps them
open in [Still open](threat-model.md#still-open).
