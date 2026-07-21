# Changelog

All notable changes to this project are documented in this file.

## [v0.3.0] - 2026-07-21

### Breaking Changes

- `aqt logout` now revokes this device on the server and deletes its local
  profile. It previously only cleared the cached session key; that behavior is
  now `aqt lock`. Scripts that ran `logout` to drop a cached key must switch to
  `lock`, or they will deauthorize the machine. Recovery is `aqt login` with the
  account passphrase.
- `aqt login` no longer creates accounts. Account creation is `aqt signup`, and
  `--invite` moved with it (`AQT_INVITE_TOKEN` is unchanged). `login` now only
  attaches or unlocks an existing account.
- `AQT_ADDR` defaults to `127.0.0.1:8080` instead of `:8080`, and a non-loopback
  listener serving plain HTTP now refuses to start unless
  `AQT_ALLOW_INSECURE_HTTP=1` is set. Deployments that bound every interface
  must set the address explicitly, front the server with a TLS proxy, or opt in.
- `AQT_QUOTA_BYTES` counts physical storage across packs, resource blobs,
  retained snapshots, and attributable database growth. It previously counted
  stored pack bytes only, so an account near the limit can be over it after
  upgrading without having written anything. Over-quota writes are rejected with
  `507`; nothing is deleted.
- `.aqtconfig` is parsed strictly: unknown fields and invalid values fail at load
  with the file path and field name. A config carrying a typo'd or
  forward-looking key stops working until it is corrected.
- A tracked folder is bound to the profile and account that created it.
  `.aqt/state.json` records the owning profile name and the account signing-key
  fingerprint, and a conflicting explicit `--profile` or `--server` is refused.
  Legacy state adopts the active profile only when that profile's server matches
  the recorded one; otherwise the command fails with instructions rather than
  silently rebinding.
- `-v` is now the shorthand for `--version`. It was previously a no-op verbose
  flag. It is not inherited by subcommands, so `aqt sync -v` fails with an
  unknown-shorthand error instead of silently doing nothing.
- `aqt snapshot restore` is removed in favor of `aqt restore`, which defaults to
  a side-by-side restore instead of an in-place rollback (`--in-place` opts back
  in). `aqt snapshot anchor --remove` is replaced by `aqt snapshot unanchor`.
- `aqt private` and `aqt share --revoke` are removed in favor of `aqt unshare`
  (bare: rotate the key and kill every link; `--with <email>`: revoke one grant).
- The `426` error body's `min_client` field is renamed `minClient`, matching
  every other field's camel case.

### Upgrading

- Several of the changes above make a misconfigured client refuse to sync rather
  than sync wrongly: strict `.aqtconfig`, tracked-folder identity binding, the
  physical quota, and the loopback listener default. Each one reports why, but an
  unattended `aqt watch` or cron sync can stop without anyone reading the output.
  Check those jobs after upgrading.
- Server upgrades apply schema migrations in place and are safe. Rolling a data
  directory **back** to an older server binary is not: the older build finds a
  `user_version` above its own migration count, skips the loop, and opens the
  newer schema anyway. It does not understand the columns added since, so it
  would prune anchored snapshots and serve links that should return `410`. Take a
  copy of the data directory before upgrading if a rollback needs to stay open.
- `aqt push --public` with `--expire`, `--max-reads`, or `--burn` destroys the
  content when the policy fires — that is what an ephemeral upload asks for.
  `aqt share` on an existing resource instead retires the link and keeps the
  data, and fails closed against a server too old to honor that distinction.

### Added

- `aqt signup` creates an account and attaches the device; `aqt lock` forgets the
  cached key while keeping the device attached. Together with the narrowed
  `login` and `logout`, each account command now does one thing.
- Resource representations are explicit, versioned media types
  (`application/vnd.aqt.resource+json; version=1`, the matching
  `+octet-stream` envelope, and `application/vnd.aqt.object-frames; version=1`).
  `Accept` selection honors media parameters and quality values, returning `406`
  when nothing offered is supported and `415` for an unsupported write
  `Content-Type`. The unversioned `application/json` and
  `application/octet-stream` forms remain aliases for pre-v1 clients. See
  "Resource wire protocol v1" in `docs/compatibility.md`.
- Resource and snapshot creates accept an `Idempotency-Key` (at most 128 bytes),
  scoped to the account and operation and recorded atomically with the create, so
  a retried create replays the original response instead of duplicating. Reusing
  a key for a different payload returns `409 idempotency_conflict`. The client
  retries only these key-backed creates, and only on transport failures and
  transient `5xx` — never on a definitive `4xx` or a `507` quota rejection.
- Mutations carry preconditions: visibility changes send `expectedVersion` and
  deletes send an `If-Match` resource version, so a stale mutation returns
  `409 version_conflict` instead of clobbering a concurrent write.
- Per-account row limits `AQT_MAX_RESOURCES`, `AQT_MAX_SNAPSHOTS`, and
  `AQT_MAX_OBJECTS` (`0` = unlimited) bound an account's footprint beyond bytes.
- The server splits liveness from readiness: `GET /livez` always answers while
  the process is up, and `GET /readyz` checks storage and returns `503` during
  shutdown or when storage is unavailable — use it for traffic admission.
  (`/healthz` is retained as an alias.) Shutdown is coordinated: readiness fails
  first, then HTTP, metrics, snapshot, and GC work share the
  `AQT_SHUTDOWN_GRACE` deadline (default `20s`) before the store closes.
- Server configuration fails closed. Every numeric and duration environment
  variable is validated at startup and a malformed value aborts the boot instead
  of silently falling back to a default.
- Destructive batches are preflighted: `aqt rm`, `aqt snapshot prune`, and
  `aqt devices rm` validate and deduplicate every target before acting on any of
  them, and report per-target `succeeded`/`failed`/`not_attempted` results in a
  stable `--json` envelope. See `docs/cli.md`.
- Tracked-folder and export writes are atomic. `clone` (owned, link, and grant),
  directory pulls, snapshot export, and side-by-side restore stage into a sibling
  temp directory and rename on success, so an interrupted transfer commits a
  complete tree or leaves the destination untouched. `aqt init` stages `.aqt` and
  the starter ignore file before creating the remote resource and deletes that
  resource if the local commit fails, so a failed `init` is side-effect-free on
  both ends.
- `.aqtconfig` accepts an optional `version` field (absent or `0` and `1` are
  accepted; higher is refused).
- The TUI covers the rest of the CLI: push, init, clone (including `--adopt`),
  device management, and starting or stopping the watch agent from the status
  panel; pull, share expiry and read limits, account grants and revocation, and
  the auto-snapshot toggle from the resources panel; and restore, export,
  retention, and filtering from the snapshots panel.
- Share links open in the browser. A CSP-locked share page served from the
  server decrypts inline public and password-gated files client-side against
  pinned same-origin crypto runtimes, with line-numbered text previews and a
  Raw/Download path. The key never leaves the URL fragment, and a wrong password
  fails locally without consuming a read.
- Browser recipients of a share link can now open folders and streamed files, not
  just single inline files. A folder link renders a navigable listing with
  decrypted names and sizes, fetching only the directory nodes a path needs (spine
  reads) and decrypting per-file on click with a download progress indicator;
  streamed files decrypt and save the same way. Everything stays client-side: the
  key never leaves the URL fragment, and browsing a folder still counts as one read
  against a `--max-reads` link (object fetches are uncounted). Very large files
  (over 512 MiB) and packed folders remain CLI-only, and the page says so. The
  page vendors a pinned pure-JS zstd decoder (`fzstd`) for aqt's chunk/node codec.
- A standalone Next.js landing site (`landing/`) with a pixel-editorial design,
  reduced-motion behavior, and local setup documentation.
- Every list endpoint (`/v1/resources`, `/v1/shares`, `/v1/snapshots`,
  `/v1/devices`, `/v1/resources/:id/grants`) is now paginated with `?limit=`
  (default 100, max 1000) and an opaque `?cursor=`, returning `nextCursor`
  alongside the existing items array. The Go client follows the cursor
  transparently, so CLI callers still get the whole slice in one call.
- `POST /v1/resources` creates a resource (server-assigned id); `PUT
  /v1/resources` is now the in-place update. The client uses `POST` for creates.
  The legacy `PUT`-create path still works for older clients.
- `429` responses carry a `Retry-After` header (whole seconds) computed from the
  tripped limiter's refill rate.
- Everyday resource management no longer requires copying opaque ids: `share`,
  `unshare`, `rm`, and `info` accept a unique decrypted name or a local tracked
  path. `aqt mv` (`rename`) re-seals only client-encrypted metadata, `info` shows
  link expiry/read limits, and `ls` adds `-l`, filtering, and name/size/date sorts.
- `aqt passphrase rotate-root` performs account-compromise recovery: it creates a
  new root key, atomically rewraps all recoverable resource and snapshot keys plus
  incoming grants, migrates the account signing/encryption identities, and revokes
  every device except the initiating one (which receives a fresh token). Future
  convergent writes use the new root-derived identity.
- Capability negotiation now fails closed for missing or malformed headers.
  Header-less legacy clients are baseline-only and receive `426 Upgrade Required`
  before an id-bound or newer resource is served.
- Account-to-account sharing: `aqt share <id> --with <email>` grants a specific
  account read-only access to a file or chunked folder — no public link, no key
  in any URL. Every account now publishes an X25519 encryption key (derived from
  the master key like the signing key, self-signed with the Ed25519 identity
  key; existing accounts backfill it on next login), and a grant is the
  resource's content key HPKE-wrapped (RFC 9180) to the grantee, bound to
  (resource, owner, grantee) so the server cannot replay it elsewhere. The
  grantee sees the share under `aqt shares` and pulls or clones it read-only;
  all mutations stay owner-scoped server-side. `aqt unshare <id> --with <email>` deletes the
  grant and rotates the content key (re-wrapping remaining grantees), so
  revocation is forward-secure immediately. Grant-target lookups answer unknown
  emails with a deterministic decoy (no account-existence oracle), and
  `aqt contacts verify <email>` prints key fingerprints to check the
  trust-on-first-use pin out-of-band. The server still stores only ciphertext.
- Public whole-folder sharing: `aqt share <folder-id>` now mints a fragment link
  for a chunked folder (password gating, `--expire`, `--max-reads`, and `--burn`
  work as for files; a clone counts as one read). A link holder — no account
  needed — runs `aqt clone <link>` to materialize the tree read-only, or
  `aqt pull <link>/<subpath>` to fetch a single entry or subtree; all reads go
  through the existing membership-checked public object endpoint, and there is
  no unauthenticated write path, so links are strictly pull-only.
  `aqt unshare <folder-id>` rotates the folder key root-only (nodes and chunks
  stay deduplicated) so old links die. Pack-and-seal folders remain unshareable.
- Prometheus metrics for the server, exposed on a separate operator-only listener
  (`AQT_METRICS_ADDR`, default off): per-route request/latency/status counters
  (410/426 included), pack transfer volume, GC sweep results, and per-account
  storage gauges computed from SQLite at scrape time. See "Monitoring" in
  `docs/deploy.md`.
- `aqt usage` (and `GET /v1/account/usage`) shows the account's server-side
  storage: pack bytes against the quota, plus resource, snapshot, pack, object,
  and device counts. `--json` for scripts.
- `aqt tui` — a lazygit-style terminal dashboard. Four panels (status, files,
  snapshots, resources) over a main detail pane: local changes stay live via
  kernel file events, incoming changes are decrypted client-side exactly like
  `aqt status`, snapshots diff against the live tree on demand, and resources
  can be shared (with expiry/burn), rotated private, or deleted. Every mutating
  action re-runs the corresponding `aqt` command and streams its output into a
  log pane, so the TUI adds no new write paths and everything it does is
  reproducible at the shell. Requires an unlocked session or prompts for the
  passphrase in-app; reads happen in-process against the existing client layer.
- `aqt checkpoint <name>` saves a named, anchored snapshot that retention never
  prunes, and `aqt restore <name>` brings it back — side-by-side by default, or
  in place with `--in-place`. `aqt snapshot anchor <id>` anchors and
  `aqt snapshot unanchor <id>` unanchors an existing snapshot. Anchoring fails closed
  against an older server that would silently ignore it.
- `aqt sync --conflicts=copy` (also `conflicts: "copy"` in `.aqtconfig`) resolves a
  two-sided change Dropbox-style: the local version stays at its path and the remote
  version is written alongside as `<name>.conflict-<host>-<timestamp>`, then the sync
  continues at exit 0. The default (`--conflicts=block`) and `--force` are unchanged.
  Copy mode is refused with `--force`, `--reconcile`, `--accept-rollback`,
  `--push-only`/`--pull-only`, and on pack-and-seal folders.
- Server-enforced lifecycle controls on public share links. `aqt push` and `aqt share`
  accept `--expire <dur>` (e.g. `30m`, `24h`, `7d`), `--max-reads <n>`, and `--burn`
  (shorthand for `--max-reads 1`). An expired or exhausted link returns `410 Gone`
  (new exit code `7`); the ciphertext is then reclaimed while the link keeps reporting
  `410`. Zero-knowledge is preserved — the server gates the opaque id and never sees the
  plaintext or the fragment key. New clients fail closed against an older server that
  does not enforce the policy (no capability bump; see `docs/compatibility.md`).
- Client capability negotiation. Every request advertises which encrypted-resource
  formats the client can read (`X-Aqt-Capability`), and resource writes record the
  lowest capability that can read them. A client too old to read a resource now gets
  an actionable `Upgrade Required` error (exit code `6`) before any download, instead
  of a bare decryption failure. This is forward-looking: it gates the next format
  boundary once every device advertises a capability. See `docs/compatibility.md`.
- Streamed (large) files can now be shared publicly with `aqt share`, gated with
  a password, and pulled by anyone holding the link — no account required.
- `aqt push --public` (and `-P`) now streams a large file through the chunk
  pipeline instead of sealing it whole in memory.
- `aqt unshare` rotates a streamed file's key by re-wrapping its root and making
  it private again, so a previously shared link no longer decrypts or fetches it.
- `--password-stdin` on `push`, `share`, `pull`, `cat`, and `info` reads a link
  password from stdin instead of the command line. `-P/--password` still works,
  but it puts the secret in the process's argv, which is world-readable on the
  local machine; prefer the new flag in scripts. `aqt tui` now uses it for
  password-gated shares.

### Changed

- Every distinct API error condition now carries a stable snake_case `code` in
  the error body (quota, version conflict, device limit, bad pack, too-many-ids,
  grant limit, invalid policy/cursor/limit, drops-roots, not-found, idempotency
  conflict — alongside the existing upgrade-required/gone/snapshot-anchored). The
  client maps by code, and the server no longer echoes raw Go error text that
  could leak internal detail.
- `POST /v1/chunks/check` and `/v1/chunks/locate` now cap a request at 10,000
  ids (`400 too_many_ids`), matching the object endpoints; the client batches
  `check` like it already batched `locate`.
- Public DTO fields are lower camel case and no longer depend on Go field names.
- Standardized the CLI surface: `contacts rm` is canonical (`remove` remains an
  alias); pull, restore, and snapshot export use `-o/--out`; snapshot retention
  uses `--since/--before`; `snapshot create` accepts a positional label;
  `snapshot unanchor` replaces `anchor --remove`; the no-op verbose flag is gone
  and `-v` prints the version; `ls` accepts subpaths only in refs; and `cat` is
  the sole stdout-fetch command.
- Restore is one command: `aqt restore <name-or-id>` accepts checkpoint names and
  snapshot ids and defaults **side-by-side** (into `aqt-restore-<id>`, or
  `--out <dir>`); `--in-place` opts into the destructive rollback.
  `aqt snapshot restore` is removed — it defaulted the opposite way for the
  same action.
- Sharing is one family: `aqt share ls [<id>]` lists outgoing access (public
  links with their server-reported lifecycle policy, and account grants), and
  `aqt unshare <id> [--with <email>]` replaces both `aqt private` (bare: rotate
  the key, kill every link) and `aqt share --revoke` (`--with`: revoke one
  grant). `aqt shares` (incoming) and `aqt contacts` are unchanged.
- `--json` now works on `share`, `unshare`, `sync` (summary, dry-run plan, and
  conflict lists), `status` (local + incoming), `whoami`, `shares`, `contacts`,
  `rm`, `clone`, `restore`, `pull`, `devices rm`, `snapshot export`, and the
  explicit-id half of `snapshot prune`. A command that does not implement
  `--json` now errors instead of silently printing prose.
- Destructive commands confirm uniformly: `rm` (including `--with-snapshots`),
  `devices rm`, `logout --all-devices`, `unshare`, `snapshot prune`, and
  in-place restore all prompt, accept `-y`, and abort on a non-terminal stdin
  without it.
- `aqt agent start [dir] [--foreground]` starts the watch daemon (alias for
  `aqt watch -d`), completing the `agent start|stop|status|logs` lifecycle tree.
- The share page's `500` now renders the same styled page as its `404`/`410`.
- The share page reports a link's remaining reads before decrypting and no longer
  consumes one while checking whether it can be opened at all.
- The TUI reports which stage of a public-link build failed (fetch, key recovery,
  unwrap, encode) instead of collapsing every cause into one message.
- `DESIGN.md`, `README.md`, and the landing page match the shipped CLI: the
  nonexistent `aqt diff` example is gone, and `--password-stdin`, `--progress`,
  `sync --reconcile/--rehash/--accept-rollback`, `clone --adopt`,
  `rm --with-snapshots`, the full login/passphrase surface, the
  snapshot/checkpoint/restore reference, `aqt shares`, `aqt contacts`, and the
  account-grant workflow are all documented.

### Fixed

- A download response no longer exposes a link's lifecycle fields (expiry, read
  counts, create/update timestamps) to public-link recipients or grantees; they
  are returned to the owner only. Enforcement is unchanged.
- `aqt logout` no longer strands a machine whose token was already revoked
  elsewhere (a passphrase change on another device): a `401` or `404` on the
  current-device revoke is treated as already done and the local profile is
  still removed.
- `aqt signup` refuses to overwrite an existing local profile, which would orphan
  that device's server-side token, and an email conflict now points at
  `aqt login` instead of blaming the passphrase.
- `--ttl` between zero and one second is rejected: it truncated to `0` on disk,
  which means "cache forever" — the inverse of the intent.
- Reclaimed tombstones are excluded from an account's modeled quota bytes, so a
  delete-heavy account can get back under quota without touching every tombstone
  by hand.
- Usage accounting tolerates a missing blob file: one orphaned row no longer
  breaks metrics, puts, and auto-snapshots account-wide.
- `idempotency_keys` rows older than 48h are reaped by the per-owner GC; the
  table stores full JSON responses and previously grew without bound.
- Auto-snapshot runs compute an account's usage once per owner rather than once
  per due resource, which stats every blob the owner has.
- `aqt mv` against a server too old for the resource-metadata endpoint now
  reports that the server lacks rename support (upgrade it) instead of a bare
  "not found".
- `aqt mv` warns when the new name already belongs to another resource, so a
  later name-based ref does not silently become ambiguous.
- `aqt info` no longer prompts for the passphrase twice when session caching is
  unavailable: the master key is unlocked once per invocation.
- Local file errors (`aqt push missing-file`) no longer exit with code 5
  ("network, retry later"): `*fs.PathError` satisfies the `net.Error` interface
  and was misclassified. They now exit 1.
- Bare `aqt <word>` no longer uploads a file that happens to match a typo'd
  subcommand: the push sugar requires a path separator, or an interactive
  confirmation when the bare word names an existing file.
- `-P`/`--password` without a value now prompts for the password (hidden, on a
  terminal), as DESIGN.md promised; an inline value must be attached
  (`-P<pw>`/`--password=<pw>`), and `--password-stdin` remains for pipes.
- `aqt push --help` renders `--name` as a plain string flag (backticks in the
  usage string were parsed by cobra as a flag type).
- `aqt push <dir>` explains the `init`/`sync`/`clone` folder workflow instead of
  failing with a raw `read ...: is a directory`.
- `aqt passphrase rotate-root` without a terminal requires `-y` instead of
  silently proceeding to revoke every other device.
- TUI: folders can be shared from the resources panel (the "folders cannot be
  shared publicly yet" guard was stale since chunked-folder links shipped), and
  the help overlay no longer lists tracked-folder-only keys outside one.
- A file changed on both devices to the same content but different permissions
  is now reported as a conflict instead of being silently treated as converged,
  matching how directory modes already reconcile. Found by a new property-based
  test suite (pgregory.net/rapid) over the sync planner.
- The expiry sweep could reclaim a link that had just been re-shared. Between the
  unlocked scan and the per-resource lock, a concurrent update can reset the
  link's lifecycle while leaving `reclaimed = 0`; the under-lock re-check tested
  only that flag, so it still tombstoned the row and destroyed its only wrapped
  key. It now re-runs the full lifecycle predicate under the lock.
- A conflict copy could be planned onto a path the same sync was about to write
  (a remote entry due for download, or another copy planned in the same pass),
  so one side's bytes were overwritten moments after being saved. Copy names now
  bump past everything the sync will materialize, not just what is already on disk.

## [v0.2.0] - 2026-07-09

### Breaking Changes

- A tracked folder that is synced with `v0.2.0` is no longer readable by
  `v0.1.0` clients. Folder roots and metadata are now authenticated against
  their resource ID to detect server-side record swaps. Upgrade every device
  that accesses a shared tracked folder before allowing a `v0.2.0` client to
  sync it. New clients remain compatible with folders last written by `v0.1.0`.

### Added

- `aqt clone --adopt` binds an existing local directory to a matching remote
  folder without downloading files that already match by hash.
- `aqt pull`, `aqt cat`, and `aqt ls` support a path within a chunked folder
  reference, such as `aqt://<folder-id>/docs/guide.md`.
- `aqt status` reports incoming server changes by default; `--offline` retains
  the local-only behavior for scripts.
- `--progress` shows an opt-in transfer progress bar for `sync` and `clone` on
  terminals.
- New folders start with editable build-artifact and cache exclusions in
  `.aqtignore`. Existing ignore files are unchanged.

### Changed

- Remote tree walks use a bounded local ciphertext cache and shared range
  fetches, reducing repeated clone, find, and snapshot-diff transfers.
- `aqt watch` uses filesystem events where available, with polling retained as
  a safety fallback.
- Long transfers use a progress-stall watchdog instead of fixed request and
  server body-transfer timeouts.

### Fixed

- Share URLs now use their embedded server host for `pull`, `cat`, and `info`,
  without sending an account token to a foreign host.

## [v0.1.0] - 2026-06-28

- Initial public release.
