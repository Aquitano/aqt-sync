# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Prometheus metrics for the server, exposed on a separate operator-only listener
  (`AQT_METRICS_ADDR`, default off): per-route request/latency/status counters
  (410/426 included), pack transfer volume, GC sweep results, and per-account
  storage gauges computed from SQLite at scrape time. See "Monitoring" in
  `docs/deploy.md`.
- `aqt usage` (and `GET /v1/account/usage`) shows the account's server-side
  storage: pack bytes against the quota, plus resource, snapshot, pack, object,
  and device counts. `--json` for scripts.

### Fixed

- A file changed on both devices to the same content but different permissions
  is now reported as a conflict instead of being silently treated as converged,
  matching how directory modes already reconcile. Found by a new property-based
  test suite (pgregory.net/rapid) over the sync planner.

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
