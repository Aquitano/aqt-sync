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

See [DESIGN.md](DESIGN.md) for the full protocol and threat model.

## Build

Requires Go (see `go.mod` for the version). Pure Go — no CGO, no system libraries.

```
make build          # builds ./bin/aqt and ./bin/aqt-server
make test           # go test ./...
make restore-drill  # full backup -> restore -> byte-diff proof (see below)
```

## Client quickstart

```
# Point at a server and create an account (or attach a new device to an existing one).
aqt --server https://aqt.example.com login --email you@example.com

# Push a single file, privately (default) or as a public link.
aqt push secret.env
aqt push notes.md --public

# Track a folder and sync it two-way, like git.
aqt init ~/vault
aqt sync ~/vault

# On a two-sided change, keep local and save the remote version alongside as
# <name>.conflict-<host>-<timestamp> instead of blocking on the conflict.
aqt sync ~/vault --conflicts=copy

# Restore a tracked folder on another machine after `aqt login` there.
aqt clone <folder-id> ~/vault

# Bind an existing local directory to a remote folder, reusing matching files by
# hash instead of re-downloading; one-sided differences surface as conflicts.
aqt clone --adopt <folder-id> ~/vault
```

`aqt <path>` with no subcommand is shorthand for `aqt push <path>`. Run `aqt --help`
for the full command set (`ls`, `find`, `cat`, `share`, `private`, `snapshot`,
`checkpoint`, `restore`, `watch`, `devices`, `passphrase`, …).

`aqt checkpoint <name>` saves a named, anchored snapshot that retention never prunes,
and `aqt restore <name>` rolls the tracked folder back to it (in place by default,
`--into <dir>` for side-by-side). The name is sealed on this machine like any snapshot
label. Anchor or unanchor an existing snapshot with `aqt snapshot anchor <id> [--remove]`.

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

`GET /healthz` returns `200 {"status":"ok"}` for load-balancer and container probes.
`AQT_METRICS_ADDR` exposes Prometheus metrics (request rates, GC activity,
per-account storage) on a private listener, and `aqt usage` shows an account its
own storage footprint.

The full operator runbook — every environment variable, TLS options (static certs,
built-in Let's Encrypt, or a reverse proxy), a systemd unit, Docker/Compose, and the
backup-and-restore procedure — is in **[docs/deploy.md](docs/deploy.md)**.

## Backing up a git repository

`.git` is ignored by default. Backing up a repository's local-only history has
trade-offs (torn-write windows, the git-busy guard); see
**[docs/git-repositories.md](docs/git-repositories.md)**.

## Proving restore works

For a backup tool, a restore you have never run is not a backup. Two equivalent
drills exercise the full cycle — realistic tree → cold backup of the server data dir
→ fresh server from the copy → clean-machine recovery from email + passphrase →
`clone` → byte/mode/symlink diff:

- `make restore-drill` (or `scripts/restore-drill.sh`) — against real built binaries.
- `go test ./cmd/aqt -run TestFullBackupRestoreDrill` — the in-process twin, run on
  every CI build.
