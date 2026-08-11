# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- `aqt account delete` (alias `aqt account unregister`) erases your own account and
  everything stored under it: devices, resources, snapshots, grants, objects, packs,
  and every ciphertext file behind them. Grants *to* the account go too — its
  published key is gone, so those wraps could never be opened again. Until now the
  only way out was to ask the server's operator, which is a poor answer for a
  product whose whole claim is that the operator cannot read your data.

  The request carries the passphrase-derived verifier, not just a device token: a
  token can leak from a stolen laptop, a backup, or a CI secret, and this is the one
  operation no restore undoes. The proof is checked inside the same transaction that
  does the deleting, so a passphrase change cannot land between the proof and the
  erasure it authorizes. The client checks the passphrase locally against the cached
  wrapped root first, so a typo fails without a round trip, and the confirmation
  wants the account email typed back rather than a `y`. `-y/--yes` skips that
  confirmation but never the passphrase. A suspended account cannot delete itself,
  so an operator hold still holds. On success the local profile, cached session, and
  keychain entries are removed; tracked folders keep their local files.

  The receipt reports the storage total on the same basis `aqt usage` does, so it is
  the number the confirmation quoted rather than a smaller one covering only the
  ciphertext files; if the server cannot read a total it reports none instead of
  approximating. Files it could not unlink are counted back to the caller — the rows
  are gone, so the account is deleted regardless, but the ciphertext may still be on
  the operator's disk, and the person who asked to be erased is the one who needs to
  know to ask about it.

- Install scripts for macOS, Linux, and Windows, served from the landing site:
  `curl -fsSL https://aqt-sync.vercel.app/install.sh | sh` and
  `iwr -useb https://aqt-sync.vercel.app/install.ps1 | iex`. Each reads the release's
  signed update manifest to learn which archive belongs to the platform, then refuses
  a download whose length or SHA-256 disagrees with what that manifest declares —
  neither script guesses an asset name. `--server` also installs `aqt-server`,
  `AQT_INSTALL_DIR` relocates the install, and `--version` pins a release. Installing
  a release archive is also what makes `aqt update` work afterwards: the previously
  advertised `go install` produced a binary stamped `dev`, which the updater declines
  to replace because its version names no release. The scripts live in `scripts/` and
  are copied into the site's `public/` at build time, so there is one copy to review.

### Changed

- `aqt update` no longer requires the GitHub CLI. The repository is public, so the
  default is now a plain HTTPS read of the release assets — no tool to install, no
  `gh auth login`. The stable channel resolves through GitHub's
  `releases/latest/download/` redirect, which is by definition the newest
  non-prerelease, so the routine check costs no API call and cannot be rate limited;
  `--prerelease` asks the public API for the newest release including prereleases,
  which no static URL exposes. `gh` is still tried, but only after the HTTPS read
  fails and only when it is already installed, which keeps a private fork or mirror
  updating. `AQT_UPDATE_BASE_URL` still overrides everything for a mirror or
  self-hoster. None of this moves the trust boundary: the manifest signature is
  checked against the keys compiled into the binary whichever transport supplied the
  bytes, and the archive is checked against the size and digest that manifest
  declares.
- A source build now reports its version as `dev` rather than a hardcoded
  `0.3.0-dev`. The old default named a release that was never tagged, so
  `aqt --version` on any source build claimed to be something it was not.

### Fixed

- HTTPS artifact downloads no longer fail on GitHub's own redirect. Release downloads
  leave `github.com` for a signed, expiring `*.githubusercontent.com` asset URL, and
  the update client refused every cross-host redirect — so the HTTPS path could never
  have downloaded a real release, only the single-origin fixtures the tests serve.
  That one hop is now permitted, matched against `githubusercontent.com` and its
  subdomains (the leading dot keeps a lookalike domain out); every other cross-origin
  redirect is still refused, and a differing port still counts as a different origin.

- `aqt` is now a multi-call binary, so encrypted Git remotes no longer need a second
  executable. Git discovers a remote helper by exec'ing `git-remote-<transport>`;
  invoked under the name `git-remote-aqt` — matched exactly, plus `.exe`, so renaming
  the binary cannot change what it runs — `aqt` runs its own `git-remote-helper`
  subcommand. `aqt git setup` creates that link beside the running binary (symlink,
  falling back to a hard link and then a copy on Windows, where symlinks need
  Developer Mode), reports where it went, and warns when the directory is not on
  `PATH` or another `git-remote-aqt` comes first. It refuses a directory Homebrew,
  WinGet, or Scoop owns, because a package that records every file it installs should
  ship the link itself; `--dir` puts one anywhere else. Re-running is a no-op, and
  replacing an existing helper asks first.

  This closes the gap where `aqt update` upgraded only the client: there is now one
  file to replace, so the two can no longer disagree about protocol or crypto. A
  symlink resolves by name and follows the update; the hard-link and copy fallbacks
  stay bound to the file the update renamed away, so the update reports the stale
  link and names the command that remakes it.

### Removed

- The standalone `git-remote-aqt` archive and the `cmd/git-remote-aqt` binary it was
  built from. Releases now publish `aqt` and `aqt-server` only, so an install script
  that fetches `git-remote-aqt_<version>_<os>_<arch>` needs updating: download `aqt`
  and run `aqt git setup`. A standalone helper already on disk keeps working — it
  execs the `aqt` beside it, and the subcommand it targets is unchanged — so no
  existing checkout breaks at the moment of upgrade.

## [v0.6.0] - 2026-08-09

### Changed

- A `426 Upgrade Required` now ends in the command that upgrades *this* install
  instead of generic prose. The client composes the message from facts it knows
  first-hand — the running version, the capability this build declares, and the
  `minClient` the server reported — and routes the action by install ownership:
  `aqt update` for a standalone copy, the owning package manager's command for a
  Homebrew/WinGet/Scoop copy, `make build` for a source build. The server's text is
  still shown but quoted and sanitized (C0/C1 controls and DEL stripped, length
  bounded), so a hostile server cannot emit escape sequences, rewrite the line, or
  forge what looks like a second line of aqt's own output. A server reporting a
  `minClient` the running build already satisfies is contradicting itself; the client
  reports the next capability up rather than naming a bar the user already clears.
  `errors.Is(..., ErrUpgradeRequired)` and exit code `6` are unchanged, and the TUI
  carries the same routing condensed to one line.
- `429` retries are now coordinated across the whole client. A sync fires many chunk,
  pack, and object requests concurrently against one limiter bucket; each used to ride
  out its own `Retry-After` and they all woke together, reproducing the burst that
  tripped the limit. Any 429 now publishes its deadline to a client-wide cooldown that
  every other in-flight request observes before sending, a later deadline always wins
  over a shorter overlapping one, and each waiter adds bounded positive jitter (up to
  750ms) so they do not resume on the same instant. `Retry-After` is accepted in both
  RFC 9110 forms (delay-seconds and HTTP-date); past or malformed values fall back
  safely and excessive ones are clamped, so a hostile server cannot park a client.
  Three budgets bound the retrying — 3 retries per request, 30s per wait, 60s summed —
  and waits are context-cancellable. Only replayable requests are ever retried.
- Exhausted rate limiting now returns a typed `*client.RateLimitedError` carrying the
  attempt count, last delay, and next safe retry time, and maps to **exit code 5**
  (retryable network) instead of a generic exit 1, so cron and `watch --once` treat
  throttling as "try again later" rather than a permanent failure. It still satisfies
  `errors.Is(..., ErrRateLimited)`.

### Added

- A `429` response carries `retryAfterSeconds` in its structured body alongside the
  `Retry-After` header, both derived from the same limiter result, so a client behind
  an intermediary that strips unknown headers still learns the real refill time. The
  header stays authoritative whenever it survives and parses. No encrypted format
  changes, so the client capability is not bumped and old clients and servers
  interoperate unchanged.
- The project is licensed under AGPL-3.0-or-later: client, `git-remote-aqt`
  helper, server, and landing site. `AQT_SOURCE_URL` overrides the source link the
  share page offers, for operators running a modified server. The value must be an
  absolute `http(s)` URL or the server refuses to start.
- `aqt-server admin accounts list|show|quota|disable|enable|delete` gives an
  operator the account lifecycle the server previously had no answer for: every
  policy was a global environment variable, so a single account could not be
  inspected, capped, suspended, or removed without editing the database by hand.
  The verbs act on the data directory directly — filesystem access to it is
  already the trust boundary, so an admin HTTP API would add remotely reachable
  privileged surface without adding capability — and are safe to run against a
  live server. Accounts are addressed by email, owner handle, or an unambiguous
  handle prefix; an ambiguous prefix is refused rather than resolved.
- Per-account storage quotas (`admin accounts quota`). `AQT_QUOTA_BYTES` becomes
  the default rather than the only setting, and three states stay distinct: an
  explicit byte cap, `unlimited` (which stays exempt when the server default
  changes), and `default` (inherit again). `aqt usage` now reports the cap that
  actually applies instead of the server-wide one.
- Account suspension (`admin accounts disable`/`enable`). A suspended account's
  devices receive `403` with code `account_disabled` — deliberately not `401`,
  which would loop the user through a re-login that cannot succeed. Nothing is
  deleted and no key is destroyed, so restoring is immediate and the existing
  device tokens keep working. A running server observes a suspension written by
  the admin process within 10 seconds.
- Account deletion (`admin accounts delete`). Erases the account, its devices,
  resources, snapshots, grants, objects, packs, and every ciphertext file behind
  them, including grants *to* the account from other owners (its published key is
  going away, so those wraps could never be opened again) and superseded blob
  files a reseal left on disk. Rows commit as one transaction so the account never
  half-exists; files are removed afterwards, and any that could not be are reported
  by path. `--dry-run` reports the scope without touching anything, and without a
  terminal the command refuses rather than let a prompt read EOF as consent.

`aqt-server` with no arguments, and every existing environment variable, behave
exactly as before, so systemd units and container commands are unaffected.

### Fixed

- Releases now publish the `git-remote-aqt` helper. It was built by `make build` but
  attached to no release, and Git resolves an `aqt::` remote only by executing a
  program named exactly `git-remote-aqt` on `PATH` — so encrypted Git remotes were
  unusable for anyone who installed aqt from a release rather than building from
  source. The helper is cross-compiled for the same five targets as the client and
  ships as its own archive (`git-remote-aqt_<version>_<os>_<arch>`) beside the `aqt`
  and `aqt-server` ones, because `aqt update` refuses a client archive holding any
  entry other than the `aqt` executable. The signed update manifest is unaffected: it
  looks up one exact archive name per platform rather than scanning the release
  directory, so the new archives can neither be mistaken for a client build nor
  duplicate a platform. `aqt update` still replaces only the client, so the helper is
  upgraded by unpacking the matching archive from the same release.
- A resource update that repeats the blob nonce already stored is refused with a
  `400`. Blobs are addressed by id+nonce and treated as immutable per nonce, so a
  repeated nonce made the write target the *live* file: it was truncated before the
  transaction opened, and any later failure (such as dropped chunk roots or a
  failed commit) ran the cleanup that deletes the new file —
  deleting the blob the committed row still named and leaving the resource
  undecryptable. Every reseal draws a fresh nonce, so no correct client is affected.
- A failed signup no longer reports an unrelated server error as "email already
  registered". The SQLite constraint match behind that mapping tested for
  `constraint failed`, which the driver also emits for `NOT NULL` and `CHECK`
  violations; it now matches `UNIQUE constraint failed`.
- Pack compaction no longer over-charges an owner's storage quota when the compacted
  pack's content address collides with a pack the owner already stores. The swap
  added the new pack's bytes unconditionally, but a pre-existing row's bytes were
  already counted, so the counter drifted upward permanently — it has no ceiling and
  feeds the quota check on every upload.

### Security

- Updated `golang.org/x/text` and `golang.org/x/net` to patch
  GO-2026-5970 in automatic-TLS host validation and remove GO-2026-5942 from
  the dependency graph.
- Raised the landing site's transitive security floors for PostCSS, nanoid,
  js-yaml, and both supported brace-expansion major lines, resolving
  GHSA-fxqj-rqcc-2cmp, GHSA-2v37-7h3g-55p8, GHSA-5p4m-2wfm-xmqj, and
  GHSA-rgw5-rvv9-x895.

## [v0.5.0] - 2026-08-07

### Added

- Encrypted Git remotes: `aqt repo create|ls|info|gc|restore|rm` and the
  `git-remote-aqt` helper make `git clone aqt::<repo>`, fetch, push, force-push,
  tags, and ref deletion work through the existing zero-knowledge pack API.
  Pushes use fast-forward checks plus bounded version-CAS retries; bundle chains
  compact automatically or via `repo gc`, snapshotting the pre-compaction root;
  `repo restore` rolls back to that root after snapshotting the current chain.
  SHA-1 and SHA-256 clone formats are negotiated through Git's remote-helper
  object-format extension. Already-full GC and same-version CAS retries reuse
  their bundle/snapshot work.
- Pre-compaction and pre-restore snapshots are anchored at creation so scheduled
  auto-retention cannot prune a rollback before its swap is validated. Once its
  swap commits, a compaction lists the remote's checkpoints server-side and
  releases every one but its own, so after each successful compaction exactly one
  rollback per remote stays anchored, no matter how many compactions, CAS retries,
  or restores preceded it.
  A user's `aqt checkpoint` is anchored but not automatic and is never released.
- `aqt sync --conflicts=merge` (and `.aqtconfig` `conflicts: "merge"`) performs
  bounded three-way text merges for non-overlapping edits and falls back to the
  collision-safe conflict-copy behavior for overlaps, binary/oversized files,
  delete/modify conflicts, or unavailable base chunks. It never writes conflict
  markers, and a post-CAS drift check preserves edits made while a merge PUT is
  in flight. Clean results are also checked line-by-line against all three inputs,
  so adjacent unterminated hunks cannot synthesize content by concatenation. A
  merged result stays in memory until the post-CAS write, so a per-sync budget
  (128 MiB) bounds what a sync with many conflicting text files holds at once;
  conflicts past it take the streaming copy path and are reported on stderr, and
  a re-run merges them.
- `aqt diff [path...] [dir]` renders unified local-versus-base diffs;
  `--remote` shows incoming changes and `--against <snapshot-id>` compares a
  snapshot with the working tree without requiring `base.json`. Binary,
  oversized, and excessive-edit-distance changes use a one-line marker.
  `--against <snapshot-id>` reads the snapshot's manifest for a path-level
  answer (`--name-status`, `--json`) instead of reconstructing its tree, so
  classifying a 4 MB folder moves 736 bytes rather than the whole folder, and
  nothing lands in the temp directory. Only the unified text diff, which needs
  both sides' bytes, still reconstructs.
- `aqt diff --against=remote` compares the working tree with the folder's current
  remote state directly, the one question `status` (base-relative, two independent
  halves) and `sync --dry-run` (a three-way plan) could not answer: two sides that
  converged on the same content report no differences even while both are ahead of
  the base. `--name-status` (implied by `--json`) lists classified paths instead of
  file content — `A` added, `M` modified, `P` permissions, `T` type, `D` deleted,
  `R` renamed — and works for every `diff` mode. Every mode is read-only: nothing is
  uploaded, nothing lands in the working tree, and neither `base.json` nor the
  recorded remote version is touched. JSON output always carries `complete` and, when
  file-level comparison was unavailable, a stable `reason`, so a caller never reads
  an empty change list as a clean tree; the human rendering says the same in prose.
  A locked session prompts on a terminal and never under `--json` or a non-terminal
  stdin, where it reports `reason: "session-locked"` with both sides still named.
  Pack-and-seal folders are streamed back and hashed in memory for a truthful
  per-entry answer; their unified text diff reconstructs the remote into a
  temporary directory instead. The TUI exposes the same comparison (`C` on the
  files panel) through the same result type.

### Fixed

- Git bundles are built inside a private (0700) temporary directory instead of at
  a reserved-then-deleted path in the shared one. `git bundle create` requires a
  path that does not exist, and the old dance left a window in which another local
  user could plant a symlink on the freed name and capture the bundle — the
  repository in plaintext. Bundles written for `git bundle unbundle` to read moved
  with them.
- A Git-remote push no longer costs one `git` process per (pushed ref, remote ref)
  pair. Deciding whether the remote already had a tip ran `git merge-base` against
  every remote ref in turn, so push time grew with the product of the two ref
  counts: pushing 80 unrelated branches to a remote holding 60 took 10s, and a CAS
  retry paid it again. Reachability is now one `git rev-list` per pushed tip
  against the whole remote frontier, and object presence one `git cat-file
  --batch-check` for the whole chain (fetch included). The same push takes 0.9s.
- Pack-and-seal sync missed changes that touched no file. Its local-change gate
  consulted the file planner alone, so an empty directory appearing or
  disappearing, or a directory's mode being edited, was reported as already
  synced and never pushed. The pack archive now carries a header per tracked
  directory (so an extract restores empty directories and directory modes rather
  than inferring parents from file paths), and a pull prunes tracked directories
  the remote dropped. A pack folder written by an older client re-ships once on
  the first sync after upgrading, then converges.
- Restoring a folder that tracks a non-writable directory no longer fails part
  way through: directory modes are applied once the tree has landed, so a
  directory cannot lock out the contents that belong inside it.

### Changed

- One manifest-delta module (`syncengine.Diff`) now defines a changed tree for
  every tracked-folder caller: `status` (local and incoming), the TUI's files
  panel, both sync adapters' local-change gates, and `snapshot diff`. It
  classifies files, symlinks, and directories across additions, removals,
  content, mode, and type changes. `status` gained `mode` and `type` rows and
  prints directories with a trailing slash; `snapshot diff` gained `m` and `t`
  gutter marks and now reports symlink retargets, directories, and directory
  modes, which its Merkle-tree walk previously dropped. `status --json` and
  `snapshot diff --json` keep their existing `added`/`modified`/`deleted`
  buckets and add a `changes` array carrying the classification behind them.
- Client capability 4 gates the sealed `gitremote` root format. Git remotes are
  private-only in this release; public visibility and grants are refused
  server-side. Upgrade every Git-remote reader before creating one.
- Both sync adapters now share one prologue (`syncSession`): state and base
  loading, the missing-base refusal, session acquisition, resource fetch, key
  unwrap, metadata decode, format check, and rollback classification are defined
  once instead of mirrored per adapter. Rollback classification now runs before
  the content key is unwrapped and the metadata decoded on both paths, so a
  rolled-back server is reported ahead of a cross-mode `.aqtconfig` mismatch (and
  ahead of a keyless resource) on the pack-and-seal path, which previously masked
  it behind those errors. Every message and exit code is otherwise unchanged.

## [v0.4.1] - 2026-08-01

### Added

- Tagged releases now publish a canonical update manifest (`aqt-update.json`) and a
  detached Ed25519 signature (`aqt-update.json.sig`) alongside the archives,
  checksums, SBOM, and attestations. The manifest carries the version, channel,
  publication time, and one exact name/size/SHA-256/URL tuple per published platform.
- `aqt update --check` reports whether a newer release is published. It verifies the
  signature against keys compiled into the binary before trusting any field, selects
  only the `aqt` archive for the running OS and architecture, and never modifies the
  installation. `--prerelease` opts into the beta channel; `--json` emits
  `currentVersion`, `availableVersion`, `channel`, `status`, and `releaseUrl`.
  Unknown keys, bad signatures, malformed or oversized metadata, duplicated
  platforms, missing platform builds, and downgrades all fail closed. Source builds
  report that automatic updates do not apply to them.
- `cmd/updatectl`, the release-side tool that generates, signs, and verifies the
  manifest. Signing runs in a protected `release-signing` environment; key custody,
  rotation with overlapping keys, and compromise recovery are documented in
  `docs/updates.md`.
- `aqt update` now installs the release it finds, after showing the transition and
  asking for confirmation; `--yes` is the explicit non-interactive path and `--check`
  keeps the old report-only behavior. The archive is downloaded into the install
  directory and verified against the signed length and SHA-256 as it arrives,
  unpacked to exactly one regular `aqt` executable (path traversal, links, devices,
  duplicates, extra payloads, and decompression bombs are all refused), and run to
  confirm it reports the promised version before the installed binary is touched. The
  old binary is renamed aside rather than overwritten — the one operation Windows
  refuses on a running image — and renamed back on any failure. Permissions are
  preserved; setuid, setgid, and sticky bits are dropped.
- Installation ownership detection. Homebrew, WinGet, and Scoop installations are
  recognized from the resolved executable path and the receipts beside it rather than
  from what `PATH` resolves to, and are reported with their owner's upgrade command
  instead of being replaced. Source builds refuse self-replacement. aqt never invokes
  a package manager itself.
- `aqt update policy [off|notify|auto]`, an opt-in global policy stored atomically.
  The default `off` means installing aqt adds no background network traffic. `notify`
  and `auto` check at most once per 24 hours with a five-second timeout, only after a
  command that succeeded on a terminal, and never for `--json`, `--quiet`,
  non-interactive scripts, or watch agents; a failed check never changes the exit
  status or output of the command that triggered it. `auto` installs stable releases
  only — never a prerelease, a downgrade, unsigned metadata, or an asset for another
  platform — and its install is budgeted separately from the check, at two minutes,
  because it moves an archive rather than a few kilobytes of metadata.
- A global watch-agent registry, so an update started in one folder can see agents
  running in every other. `auto` defers while any registered agent is live and reports
  how to complete the install; entries are dropped on clean shutdown and reaped when
  the process is gone.

### Changed

- Replaced the unrecoverable signing key from the unpublished v0.4.0 attempt and
  added an encrypted recovery-copy procedure. v0.4.1 is the first release that
  publishes updater metadata and binaries signed by a compiled trust root.
- The release workflow is split into `build` and a tag-only `publish` job. Checksums
  and attestations are computed after signing, so the update manifest, its signature,
  and the SBOM are all covered. A manual `workflow_dispatch` run builds and uploads
  archives without signing, attesting, or publishing.
- Windows now runs the native build, vet, formatting, and test gate on every pull
  request and push to `main`, instead of discovering platform regressions only when a
  release tag is built.

### Fixed

- Updated the landing site to patched Next.js, PostCSS, Sharp, and
  `brace-expansion` releases, clearing the known high-severity dependency alerts
  present when v0.4.0 was tagged.
- Windows tests now isolate profiles, sessions, and contact pins through `AppData`,
  keep Go sources and digest-pinned embedded JavaScript on LF bytes, accept CRLF in
  the documented config example, and avoid asserting POSIX permissions or umask
  behavior that Windows does not implement.

## [v0.4.0] - 2026-08-01

No release artifacts were published. The signing key was lost before publication,
and this tag is superseded by v0.4.1.

## [v0.3.0] - 2026-07-21

Never tagged or published — the date is when the work landed on `main`. Everything
below first reached users in v0.4.1, since v0.4.0 published no artifacts either.
Kept as written because other documents cite these changes; do not treat `v0.3.0`
as an installable version.

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

Release-audit fixes. Every item below is a defect found auditing this release
before tagging; each is covered by a regression test.

- `aqt lock` and `aqt logout` no longer destroy every tracked folder's sync base.
  `.aqt/base.json` was sealed under the session key, which locking deletes, so
  the next `aqt sync` in each folder reported no base and demanded `--reconcile`
  (which resurrects deletions). The base now has its own key that survives both.
- `aqt passphrase rotate-root` no longer wedges every tracked folder on every
  device. Rotation mints a new signing key, and folders were bound to that key's
  fingerprint with no bypass. Binding is now on the account's owner handle, which
  rotation preserves; the recorded fingerprint is refreshed as folders are used.
- `aqt unshare` can always kill a link. On a folder whose tree could not be
  re-sealed under the current account key — what a root-key rotation leaves
  behind until the next sync — the rotation refused and the folder stayed public
  with its original link still decrypting. It now falls back to making the
  resource private and says plainly that the key was not rotated.
- `AQT_QUOTA_BYTES` is enforced on in-place updates. The check ran only on
  create, so a `PUT` carrying an id wrote up to the route cap regardless of
  quota. An update is charged the difference between its new and current bytes,
  so a same-size rewrite is not charged twice.
- A refused read no longer spends a `--burn` / `--max-reads` permit. A `426`
  (client too old) or `406` (unacceptable `Accept`) served no bytes but had
  already counted the read, so a link-unfurling bot could exhaust a burn link and
  the intended recipient got `410` forever.
- `DeleteGrant` rolls back the transaction whose statement failed. It previously
  returned without one, and since the store has a single writer connection the
  abandoned transaction held it permanently — every later write on the server,
  for any account, blocked until the process was restarted.
- Reclaimed link tombstones can be deleted. `aqt rm` fetched the resource version
  first and a tombstone answers `410`, so the row `aqt ls` told you to remove
  could not be removed. Mutations now pin the version they already hold and
  tolerate a tombstone.
- `aqt restore --in-place` holds the sync lock across the tree swap and the sync
  that publishes it. A concurrent `aqt watch` could otherwise observe the
  half-swapped root, take the lock first, and commit the mass deletion to the
  server and every other device. The lock is now re-entrant within a process.
- Resource ids no longer begin with `-`, which cobra parsed as a flag cluster,
  making roughly one resource in 65 unaddressable as a bare argument to `rm`,
  `info`, `share`, `unshare`, `mv`, `pull`, and `cat`. Both id generators fold
  the leading character identically, so a decoy account handle stays
  indistinguishable from a real one. Ids minted before this are repaired at the
  CLI layer and remain usable.
- `aqt restore -o` and `aqt snapshot export -o` no longer silently overwrite an
  existing file at the destination; both take `--force`, matching `aqt pull`.
- `aqt rm --with-snapshots` re-lists snapshots after the delete, so one pinned by
  the scheduled job mid-command is not left behind under a `succeeded` result. A
  snapshot that cannot be deleted no longer reports the resource delete as failed
  (a retry then hit "resource not found").
- Clone, share-clone, `pullSubtree`, snapshot export, and side-by-side restore
  respect the umask again when creating their destination directory:
  `umask 077; aqt clone <id> ~/secrets` produced `0755` and now produces `0700`.
- A tracked folder is no longer locked out by an explicit `--profile` naming a
  different local profile for the same account, which a restored `$HOME` produces.
- `aqt login --email <other-account>` refuses to overwrite a profile already
  logged into a different account, which orphaned that device's server-side
  session with no way to revoke it. `aqt signup` already refused this.
- A grant re-wrap re-verifies the grantee's pinned keys against the server, as a
  fresh share does. A grantee who had rotated their own root key previously had
  their working wrap silently and permanently replaced with a dead one by an
  unrelated revocation.
- `aqt unshare --with <email>` on a public resource no longer reports a bare
  "revoked": removing the grant does not remove access while the resource is
  public, and stdout now says so.
- Scripted `aqt signup` works again. The passphrase confirmation is skipped
  without a terminal, instead of reading twice and failing with "passphrases do
  not match".
- A duplicate signup that proves ownership (by presenting the account's own
  passphrase verifier) gets a clear `409 account_exists` instead of the
  enumeration decoy, which authenticates nothing and previously left the real
  owner with an opaque error. `DESIGN.md` now states plainly that open
  registration is enumerable regardless, and that invite mode is what closes it.
- Content objects stop serving 10 minutes after a link's last read is spent.
  Exhaustion did not gate them at all, so a recipient (or anyone they forwarded
  the link to) could keep pulling the bytes until the GC sweep ran — up to
  `AQT_GC_INTERVAL + 1h`, about seven hours at the defaults.
- An idempotent create replay is no longer refused with `507` at a quota or row
  cap: the limit check ran before the store consulted the idempotency table, so a
  `push` whose response was lost reported "storage quota exceeded" for a resource
  that already existed.
- `POST /v1/snapshots` against a reclaimed tombstone returns `410` instead of
  `500`, which the client's idempotent retry treated as worth repeating.
- Paginated listings are bounded: a server returning a constant or unchanging
  cursor now ends the listing with an error rather than spinning `aqt ls`
  forever. The stall guard never fired because every request completed normally.
- Clients honour `Retry-After` on `429`, retrying a bounded number of times
  instead of failing the command, and `429` carries the `rate_limited` code like
  every other error condition.
- Shutdown fails readiness before closing listeners, so a load balancer sees a
  `/readyz` `503` and drains rather than connection-refused. A timed-out drain
  can no longer consume up to twice `AQT_SHUTDOWN_GRACE`.
- Account usage no longer runs one `os.Stat` per resource and per snapshot on
  every resource create, snapshot create, pack `PUT`, and Prometheus scrape.
  Blob sizes are recorded on write (migration 16); rows predating it fall back to
  a stat until they are next rewritten.
- The browser share page bounds allocations from attacker-declared lengths: the
  zstd frame's declared size is checked before the decompressor allocates from
  it, the inline path is bounded rather than unchecked, and assembly is capped by
  what the chunk list actually references rather than the entry's declared size.
- Vendored browser crypto runtimes are pinned by the SHA-256 of the files as
  served, enforced by a test. The README's npm digests verify the packages the
  builds came from and cannot detect an edit to a re-wrapped single-file build.
- Pagination cursors escape their parts, so a grantee handle containing the
  separator (handles are deliberately unvalidated) cannot forge an extra field.
- `aqt snapshot auto --on/--off --json` emits JSON instead of prose on stdout.
- `DESIGN.md` §3.6 documents `aqt signup` and `aqt lock`, and no longer shows
  `login --invite` or the `--kdf-*` flags, which moved to `signup`.
- The landing site sends CSP, HSTS, `nosniff`, `Referrer-Policy`, and
  `X-Frame-Options`, and pins `postcss` to the patched line so the transitive
  `8.4.31` advisory no longer appears.
- `make restore-drill` works again. It created the account with
  `aqt login --kdf-*`, which moved to `signup`, so the only end-to-end proof that
  a backup is restorable had been failing silently. It now runs in CI.

Other fixes in this release:

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
