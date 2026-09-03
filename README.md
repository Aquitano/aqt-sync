<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
  <img alt="aqt — zero-knowledge encrypted file and folder sync" src="docs/assets/banner-light.svg">
</picture>

[![linux](https://github.com/Aquitano/aqt-sync/actions/workflows/linux.yml/badge.svg)](https://github.com/Aquitano/aqt-sync/actions/workflows/linux.yml)
[![windows](https://github.com/Aquitano/aqt-sync/actions/workflows/windows.yml/badge.svg?event=pull_request)](https://github.com/Aquitano/aqt-sync/actions/workflows/windows.yml)
[![release](https://img.shields.io/github/v/release/Aquitano/aqt-sync?color=1d1c19&labelColor=544e42)](https://github.com/Aquitano/aqt-sync/releases)
[![license](https://img.shields.io/badge/license-AGPL--3.0--or--later-1d1c19?labelColor=544e42)](LICENSE)

aqt syncs files and folders between your machines through a server you run yourself.
Everything is encrypted on your machine before upload. The server stores ciphertext and
the metadata it needs to route requests, and never sees a key, a filename, or a plaintext
byte.

- **Push a file** and get a private ref or a public link (`aqt push`).
- **Sync a folder** two-way, git-style, with snapshots and conflict handling (`aqt sync`).
- **Back up Git history** to an encrypted `aqt::` remote (`git push origin main`).
- **Run the server** as one static Go binary with a SQLite data directory.

Encryption is XChaCha20-Poly1305. Argon2id turns your passphrase into a key that wraps a
random root key, and the root key never leaves your machine. Unchanged chunks are not
re-sent, and a file that appears in several folders is stored once.

## Install

macOS and Linux:

```
curl -fsSL https://web.sync.aquitano.me/install.sh | sh
```

Windows (PowerShell):

```
iwr -useb https://web.sync.aquitano.me/install.ps1 | iex
```

Both scripts read the signed release manifest, check the archive against its declared
size and SHA-256, and install to `~/.local/bin` (`%LOCALAPPDATA%\Programs\aqt` on
Windows). Useful options:

| Option | Effect |
| --- | --- |
| `--server` / `-Server` | also install `aqt-server` |
| `--version=vX.Y.Z` / `-Version vX.Y.Z` | pin a release |
| `AQT_INSTALL_DIR` | install somewhere else |

The install script trusts what the origin serves. Every later `aqt update` verifies the
manifest signature against keys compiled into the binary. To verify the first install too,
download from the [releases page](https://github.com/Aquitano/aqt-sync/releases) and
check the build provenance:

```
gh attestation verify aqt_<version>_<os>_<arch>.tar.gz --repo Aquitano/aqt-sync
```

### From source

Pure Go, no CGO. The Go version is in `go.mod`.

```
make build          # ./bin/aqt, ./bin/aqt-server, ./bin/git-remote-aqt
make test
```

A source build calls itself `dev` and is never replaced by `aqt update`.

## Quickstart

Create an account on the first machine, then attach every other machine to it:

```
aqt --server https://aqt.example.com signup --email you@example.com
aqt --server https://aqt.example.com login  --email you@example.com
```

Push files. Private is the default; `--public` mints a shareable link:

```
aqt push secret.env
aqt push notes.md --public
aqt share secret.env --expire 24h
aqt ls -l
```

Most commands accept a unique name, an id, or a tracked path. `aqt <path>` alone is
shorthand for `aqt push <path>`.

Track a folder and sync it two-way:

```
aqt init ~/vault
aqt sync ~/vault
aqt diff ~/vault                 # local edits as a unified diff
aqt sync ~/vault --conflicts=merge
aqt clone <folder-id> ~/vault    # restore on another machine
```

Store Git history as an encrypted remote:

```
aqt repo create vault-history
git remote add origin aqt::vault-history
git push -u origin main
```

`aqt --help` lists everything. A few more things worth knowing about:

- `aqt tui` opens a lazygit-style dashboard for the tracked folder you are in. Every
  action runs the matching `aqt` command and streams its output into a log pane.
- `aqt snapshot` lists, diffs, exports, and prunes folder snapshots. `aqt checkpoint
  <name>` takes one that retention never prunes, and `aqt restore <name>` brings it back.
- `aqt watch` keeps a tracked folder in sync from file events, in the foreground or as a
  background agent (`aqt agent start`).
- `aqt share <id> --with <email>` grants read-only access to another account. Verify
  their fingerprint out-of-band with `aqt contacts verify <email>`.
- `aqt update` installs a newer release after verifying its signed manifest.
  `aqt update policy notify` prints one line a day when one is available.
- `aqt account delete` erases the account and every byte under it. There is no undo,
  because the server holds no keys.

## Self-hosting

```
# Development: plain HTTP on :8080.
AQT_DATA_DIR=./aqt-data ./bin/aqt-server

# Production: TLS natively or behind a reverse proxy.
AQT_DATA_DIR=/var/lib/aqt-server AQT_ADDR=:443 \
  AQT_TLS_CERT=/etc/aqt/fullchain.pem AQT_TLS_KEY=/etc/aqt/privkey.pem \
  ./bin/aqt-server
```

The client refuses to send its token over plain HTTP to anything but loopback, so an
offsite server has to serve HTTPS. `GET /livez` and `GET /readyz` are the probes, and
`AQT_METRICS_ADDR` exposes Prometheus metrics on a private listener.

Nothing in the data directory identifies your content, so you can back it up somewhere
you do not control. `make restore-drill` proves the whole cycle against real binaries:
back up, start a fresh server from the copy, recover from an email and a passphrase,
and byte-diff the result.

## Documentation

| Document | Covers |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Design, locked decisions, package layout |
| [docs/threat-model.md](docs/threat-model.md) | Key hierarchy, what the server can and cannot see |
| [docs/cli.md](docs/cli.md) | Exit codes, `--json` shapes, what scripts can rely on |
| [docs/deploy.md](docs/deploy.md) | Every environment variable, TLS, systemd, Docker, backup and restore |
| [docs/updates.md](docs/updates.md) | Signed manifest, signing-key custody, install and rollback |
| [docs/git-repositories.md](docs/git-repositories.md) | Encrypted Git remotes |
| [docs/compatibility.md](docs/compatibility.md) | Capability negotiation and format rollout |
| [docs/decisions.md](docs/decisions.md) | Design questions and how each was answered |
| [docs/protocol/](docs/protocol/) | Wire formats: HTTP API, folder sync, git remote |

## Contributing

Build, test, and commit conventions are in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026 Thomas Breindl. AGPL-3.0-or-later for the whole repository; full text
in [LICENSE](LICENSE).

Self-hosting a **modified** server entitles its users to your source. Set
`AQT_SOURCE_URL` to point the share page at it. Unmodified releases need nothing.
The browser decrypt page bundles libsodium, hash-wasm, and fzstd under their own MIT
and ISC terms, kept next to the assets in `internal/server/webassets/`.
