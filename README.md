# aqt

Zero-knowledge encrypted file and folder sync. The client encrypts everything
before it leaves the machine; the server stores only ciphertext and opaque
metadata and never sees a key, a filename, or a plaintext byte.

- **End-to-end encrypted** — XChaCha20-Poly1305 with role-separated AADs; keys are
  derived from a passphrase via calibrated Argon2id and never transmitted.
- **Content-addressed sync** — folders sync as a Merkle-DAG of convergent-encrypted
  chunks with per-account dedup, or as a single sealed pack that leaks no structure.
- **Self-hostable** — one static Go binary (`aqt-server`) plus a SQLite data
  directory. The data dir is 100% ciphertext, so it can be backed up anywhere.

See [docs/architecture.md](docs/architecture.md) for the design and an index of every
specification document, [docs/threat-model.md](docs/threat-model.md) for what the
server can and cannot see, and [docs/protocol/](docs/protocol/) for the wire formats.

## Install

macOS and Linux:

```
curl -fsSL https://web.sync.aquitano.me/install.sh | sh
```

Windows (PowerShell):

```
iwr -useb https://web.sync.aquitano.me/install.ps1 | iex
```

Both scripts read the release's signed update manifest to learn which archive
belongs to your platform, check the download against the size and SHA-256 the
manifest declares, and install to `~/.local/bin` (`%LOCALAPPDATA%\Programs\aqt` on
Windows). `--server` also installs `aqt-server`; `AQT_INSTALL_DIR` picks a different
location. Add `--version=vX.Y.Z` to pin a release.

The script trusts the origin it downloads from — verifying an Ed25519 signature in
shell is not practical. Everything after that does not: `aqt update` checks the
manifest signature against keys compiled into the binary. To verify the first
install too, download from the [releases
page](https://github.com/Aquitano/aqt-sync/releases) and check the build provenance:

```
gh attestation verify aqt_<version>_<os>_<arch>.tar.gz --repo Aquitano/aqt-sync
```

### From source

Requires Go (see `go.mod` for the version). Pure Go — no CGO, no system libraries.

```
make build          # builds ./bin/aqt and ./bin/aqt-server (+ the git-remote-aqt link)
make test           # go test ./...
make restore-drill  # full backup -> restore -> byte-diff proof (see below)
```

A source build reports its version as `dev`, and `aqt update` reports it rather than
replacing it: its version string says nothing about which release it corresponds to,
so there is nothing safe to compare against. Use a release build for self-updates.

## Client quickstart

```
# Point at a server and create an account (or attach a new device to an existing one).
aqt --server https://aqt.example.com login --email you@example.com

# Push a single file, privately (default) or as a public link.
aqt push secret.env
aqt push notes.md --public

# Everyday resource management accepts a unique name, id, or tracked path.
aqt info secret.env
aqt mv secret.env production.env
aqt share production.env --expire 24h
aqt ls -l --filter env --sort date

# Track a folder and sync it two-way, like git.
aqt init ~/vault
aqt sync ~/vault

# Merge non-overlapping text edits; overlaps/binary/delete-modify cases preserve
# the remote version as <name>.conflict-<host>-<timestamp>.
aqt sync ~/vault --conflicts=merge

# Review local edits as a unified diff, or inspect incoming changes only.
aqt diff ~/vault
aqt diff --remote ~/vault

# Restore a tracked folder on another machine after `aqt login` there.
aqt clone <folder-id> ~/vault

# Bind an existing local directory to a remote folder, reusing matching files by
# hash instead of re-downloading; one-sided differences surface as conflicts.
aqt clone --adopt <folder-id> ~/vault

# Store Git history as an encrypted remote instead of syncing live .git files.
aqt repo create vault-history
git remote add origin aqt::vault-history
git push -u origin main
```

`aqt <path>` with no subcommand is shorthand for `aqt push <path>`. Run `aqt --help`
for the full command set (`ls`, `find`, `cat`, `share`, `unshare`, `shares`,
`contacts`, `snapshot`, `checkpoint`, `restore`, `watch`, `devices`, `passphrase`, …).

Leaving is a client command, not a support ticket: `aqt account delete` erases the
account and every byte stored under it, and asks for the passphrase rather than
trusting the device token alone. It cannot be undone — the server holds no keys, so
there is nothing to restore from.

Grant a resource read-only to another account by email with `aqt share <id> --with
<email>`; the recipient sees it under `aqt shares` and pulls or clones it, while you
can never modify their copy. `aqt contacts` lists the accounts pinned on first use for
`--with` sharing — `aqt contacts verify <email>` compares fingerprints out-of-band and
`aqt contacts rm <email>` drops a pin so the next share re-pins.

## TUI

`aqt tui` opens a lazygit-style dashboard over the tracked folder you are in:
local and incoming changes (kept live by file events), snapshots and checkpoints,
and every pushed resource, with single-key actions — `s` sync, `c` checkpoint,
`d` diff a snapshot against the live tree, `R` restore, `y` copy a ref or share
link, `s` share with expiry/burn options, `?` for all keys. Actions run the
corresponding `aqt` command and stream its output into a log pane, so everything
the TUI does is reproducible at the shell. Outside a tracked folder the
resources and snapshots panels still work account-wide.

`aqt checkpoint <name>` saves a named, anchored snapshot that retention never prunes,
and `aqt restore <name>` brings it back (side-by-side by default; `--in-place` rolls
the live tracked folder back). The name is sealed on this machine like any snapshot
label. Anchor or unanchor an existing snapshot with `aqt snapshot anchor <id>` and
`aqt snapshot unanchor <id>`.

The client refuses to send its bearer token over plain HTTP to any non-loopback
host, so an offsite server must serve HTTPS. `http://localhost:8080` is exempted for
local development.

## Self-hosting the server

```
# Local / development: plain HTTP on :8080.
AQT_DATA_DIR=./aqt-data ./bin/aqt-server

# Production: terminate TLS natively or behind a reverse proxy.
AQT_DATA_DIR=/var/lib/aqt-server AQT_ADDR=:443 \
  AQT_TLS_CERT=/etc/aqt/fullchain.pem AQT_TLS_KEY=/etc/aqt/privkey.pem \
  ./bin/aqt-server
```

`GET /livez` is the liveness probe; `GET /readyz` admits traffic only while storage is available and the server is not shutting down. `/healthz` remains a liveness compatibility alias.
`AQT_METRICS_ADDR` exposes Prometheus metrics (request rates, GC activity,
per-account storage) on a private listener, and `aqt usage` shows an account its
own storage footprint.

The full operator runbook — every environment variable, TLS options (static certs,
built-in Let's Encrypt, or a reverse proxy), a systemd unit, Docker/Compose, and the
backup-and-restore procedure — is in **[docs/deploy.md](docs/deploy.md)**.

## Staying current

`aqt update` reports whether a newer release has been published and installs it after
asking. It verifies a signed release manifest against signing keys compiled into the
binary before trusting any of its contents, checks the archive against the signed
length and digest, and keeps the previous binary until the new one has run and
reported the expected version. `--check` changes nothing; `--yes` skips the prompt;
`--prerelease` opts into the beta channel; `--json` is machine-readable.

Only a standalone installation is replaced — which is what the install scripts
produce. A build from source, or a copy some package manager owns, is reported with
the command its owner expects and is never overwritten. aqt is not published through
Homebrew, WinGet, or Scoop; that detection exists so a third-party package would
never be clobbered.

Nothing checks on its own by default. `aqt update policy notify` prints one line a day
when a release is available; `auto` also installs stable releases once no watch agent
is using the binary. Both run only after a successful command on a terminal and never
change that command's output or status.

Installation ownership, the install and rollback sequence, recovery from an
interrupted update, the manifest format, signing-key custody, and rotation policy are
in **[docs/updates.md](docs/updates.md)**.

## Backing up a git repository

`.git` is ignored by folder sync. Back up repository history with an encrypted
`aqt::` Git remote; see
**[docs/git-repositories.md](docs/git-repositories.md)**.

## Proving restore works

For a backup tool, a restore you have never run is not a backup. The shell drill
exercises the full cycle — realistic tree and encrypted Git remote → cold backup of
the server data dir → fresh server from the copy → clean-machine recovery from email
and passphrase → folder byte/mode/symlink diff plus Git clone, `git fsck`, and exact
branch/tag ref comparison:

- `make restore-drill` (or `scripts/restore-drill.sh`) — against real built binaries.
- `go test ./cmd/aqt -run TestFullBackupRestoreDrill` — the in-process folder-restore
  twin, run on every CI build.

## License

Copyright (C) 2026 Thomas Breindl.

AGPL-3.0-or-later, across the whole repository: the `aqt` client, `aqt-server`,
and the landing site. Full text in
[LICENSE](LICENSE).

Self-hosting a **modified** server entitles its users to your source.
`AQT_SOURCE_URL=https://…` replaces the upstream link the share page offers.
Unmodified releases need nothing.

The browser decrypt page bundles libsodium, hash-wasm, and fzstd under their own
MIT and ISC terms; those texts sit next to the assets in
`internal/server/webassets/`.
