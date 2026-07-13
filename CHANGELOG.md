# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- `aqt passphrase rotate-root` performs account-compromise recovery: it creates a new root key, atomically rewraps all recoverable resource and snapshot keys plus incoming grants, migrates the account signing/encryption identities, and revokes every device except the initiating one (which receives a fresh token). Future convergent writes use the new root-derived identity.

- Capability negotiation now fails closed for missing or malformed headers. Header-less legacy clients are baseline-only and receive `426 Upgrade Required` before an id-bound or newer resource is served.

- Account-to-account sharing: `aqt share <id> --with <email>` grants a specific
  account read-only access to a file or chunked folder — no public link, no key
  in any URL. Every account now publishes an X25519 encryption key (derived from
  the master key like the signing key, self-signed with the Ed25519 identity
  key; existing accounts backfill it on next login), and a grant is the
  resource's content key HPKE-wrapped (RFC 9180) to the grantee, bound to
  (resource, owner, grantee) so the server cannot replay it elsewhere. The
  grantee sees the share under `aqt shares` and pulls or clones it read-only;
  all mutations stay owner-scoped server-side. `--revoke <email>` deletes the
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
  `aqt private <folder-id>` rotates the folder key root-only (nodes and chunks
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
  prunes, and `aqt restore <name>` rolls the tracked folder back to it — in place
  by default, or side-by-side with `--into <dir>`. `aqt snapshot anchor <id>
  [--remove]` anchors or unanchors an existing snapshot. Anchoring fails closed
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
- `aqt private` rotates a streamed file's key by re-wrapping its root and making
  it private again, so a previously shared link no longer decrypts or fetches it.
- `--password-stdin` on `push`, `share`, `pull`, `cat`, and `info` reads a link
  password from stdin instead of the command line. `-P/--password` still works,
  but it puts the secret in the process's argv, which is world-readable on the
  local machine; prefer the new flag in scripts. `aqt tui` now uses it for
  password-gated shares.

### Fixed

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
