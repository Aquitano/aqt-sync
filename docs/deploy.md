# Operating aqt-server

`aqt-server` is a single static binary that serves the zero-knowledge sync API over
HTTP(S) and stores everything under one data directory. It performs no decryption,
merge, or filename inspection — the data directory is entirely ciphertext and opaque
metadata.

- [Build and run](#build-and-run)
- [Configuration](#configuration)
- [TLS](#tls)
- [systemd](#systemd)
- [Docker](#docker)
- [Backup and restore](#backup-and-restore)
- [Health checks and upgrades](#health-checks-and-upgrades)

## Build and run

Pure Go, no CGO:

```
go build -o aqt-server ./cmd/aqt-server
AQT_DATA_DIR=./aqt-data ./aqt-server        # plain HTTP on :8080
```

The data directory holds a SQLite database plus `packs/` and `blobs/` subdirectories.
Point `AQT_DATA_DIR` at persistent storage; everything else the server needs is in
environment variables.

Clients refuse to send their bearer token over plain HTTP to any non-loopback host,
so a server reachable from other machines **must** serve HTTPS (see [TLS](#tls)).
Plain HTTP is fine for `localhost` and for a server that sits behind a
TLS-terminating reverse proxy on the same host.

## Configuration

Every knob is an environment variable. The zero value is the safe self-hosted
default: open registration, no quotas, loopback-only proxy trust, plain HTTP.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AQT_DATA_DIR` | `./aqt-data` | Data directory (SQLite + `packs/` + `blobs/`). Back this up. |
| `AQT_ADDR` | `:8080` | Listen address. Use `:443` when terminating TLS natively. |
| `AQT_DEBUG` | unset | Any non-empty value enables Gin debug mode and verbose logging. |
| `AQT_TLS_CERT` / `AQT_TLS_KEY` | unset | PEM certificate + private key for native TLS. Set both or neither. |
| `AQT_TLS_AUTOCERT_DOMAINS` | unset | Comma-separated hostnames for automatic Let's Encrypt certificates. |
| `AQT_TLS_AUTOCERT_CACHE` | `<data dir>/autocert` | Directory where autocert stores issued certificates. |
| `AQT_TLS_AUTOCERT_EMAIL` | unset | Optional ACME contact address. |
| `AQT_REGISTRATION` | `open` | `open` or `invite`. Invite mode gates every signup on a token. |
| `AQT_INVITE_TOKENS` | unset | Comma-separated invite secrets (required in invite mode). |
| `AQT_QUOTA_BYTES` | `0` | Per-owner stored-pack-byte cap. `0` = unlimited. |
| `AQT_MAX_DEVICES` | `0` | Per-account device cap. `0` = unlimited. |
| `AQT_AUTH_RATE` | `0` | Authenticated requests/sec per device token. `0` = default (50). |
| `AQT_AUTH_BURST` | `0` | Authenticated burst per device token. `0` = default (500). |
| `AQT_TRUSTED_PROXIES` | loopback | Comma-separated proxy CIDRs/hosts whose `X-Forwarded-*` is trusted. `none` trusts none. |
| `AQT_SNAPSHOT_INTERVAL` | `24h` | Scheduled snapshot cadence. `0` disables. |
| `AQT_SNAPSHOT_KEEP` | `30` | Scheduled snapshots retained per resource. `0` keeps all. Anchored snapshots (`aqt checkpoint`) are exempt and never pruned. |
| `AQT_GC_INTERVAL` | `6h` | Scheduled garbage-collection cadence. `0` disables. |
| `AQT_METRICS_ADDR` | unset | Prometheus `/metrics` listen address (e.g. `127.0.0.1:9091`). Unset disables. See [Monitoring](#monitoring). |

Notes:

- **Registration.** For a private single-user or family server, `open` is fine
  (signup is not an existence oracle — an unknown email gets an indistinguishable
  decoy). For anything internet-facing where you do not want strangers creating
  accounts, use `invite`:
  ```
  AQT_REGISTRATION=invite AQT_INVITE_TOKENS=$(openssl rand -hex 16)
  ```
  Clients pass the token with `aqt login --invite <token>` or `AQT_INVITE_TOKEN`.
- **Trusted proxies.** Behind a reverse proxy, set `AQT_TRUSTED_PROXIES` to the
  proxy's address/CIDR so the share-page URL honors `X-Forwarded-Proto`. The
  rate-limit bucket keys on the real TCP peer regardless, so this is display-only.
- **Quotas** are the main abuse control on a shared server; combine `AQT_QUOTA_BYTES`
  and `AQT_MAX_DEVICES` with `invite` registration.

## TLS

Pick one of three approaches.

### 1. Native static certificates

Supply a certificate and key (for example from certbot, your CA, or an internal PKI):

```
AQT_ADDR=:443 \
AQT_TLS_CERT=/etc/aqt/fullchain.pem \
AQT_TLS_KEY=/etc/aqt/privkey.pem \
./aqt-server
```

The server negotiates TLS 1.2+ and loads the key pair at startup (a bad path fails
fast rather than on the first handshake). Reload after certificate renewal by
restarting the service.

### 2. Native Let's Encrypt (autocert)

For a public hostname that resolves to the server, let it obtain and renew
certificates automatically:

```
AQT_ADDR=:443 \
AQT_TLS_AUTOCERT_DOMAINS=aqt.example.com \
AQT_TLS_AUTOCERT_EMAIL=admin@example.com \
./aqt-server
```

Issuance uses the TLS-ALPN-01 challenge over port 443, so no separate port-80
listener is required — but the domain must resolve to this host and `:443` must be
reachable from the internet. Certificates are cached under
`AQT_TLS_AUTOCERT_CACHE` (default `<data dir>/autocert`); keep that directory on
persistent storage so restarts do not re-issue.

### 3. Reverse proxy

Terminate TLS at Caddy, nginx, or a load balancer and forward plain HTTP to the
server bound on loopback. Example `deploy/Caddyfile`:

```
aqt.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Run the server with `AQT_ADDR=127.0.0.1:8080` and set
`AQT_TRUSTED_PROXIES` to the proxy's address. An equivalent nginx location:

```
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 64m;   # resource blobs / packs can reach ~32-64 MiB
}
```

## systemd

`deploy/aqt-server.service` runs the server as a locked-down dynamic user with a
managed state directory. Install it:

```
sudo cp aqt-server /usr/local/bin/
sudo cp deploy/aqt-server.service /etc/systemd/system/
# Put secrets and overrides here (AQT_REGISTRATION, AQT_INVITE_TOKENS, TLS paths, …):
sudo install -m 0640 /dev/null /etc/aqt-server.env
sudo systemctl daemon-reload
sudo systemctl enable --now aqt-server
```

The unit sets `AQT_DATA_DIR=/var/lib/aqt-server` (created and owned via
`StateDirectory`) and grants `CAP_NET_BIND_SERVICE` so it can bind `:443` without
root. If you use native static certificates, grant the service read access to them
with `ReadOnlyPaths=` in a drop-in, or copy them under the state directory.

On stop/restart, systemd sends `SIGTERM`; the server drains in-flight requests
(up to 20s) and closes the store cleanly before exiting.

## Docker

The repository `Dockerfile` builds a static binary into a distroless image:

```
docker build -t aqt-server .
docker run -d --name aqt-server \
  -p 8080:8080 \
  -v aqt-data:/data \
  -e AQT_REGISTRATION=invite -e AQT_INVITE_TOKENS=change-me \
  aqt-server
```

`AQT_DATA_DIR` defaults to `/data` in the image; mount a volume there. The image
has no shell, so define health checks in your orchestrator against `GET /healthz`
rather than a container `HEALTHCHECK`.

`deploy/docker-compose.yml` wires the server to a Caddy sidecar that terminates TLS
and auto-provisions a certificate:

```
cd deploy && docker compose up -d
```

Edit the `Caddyfile` hostname and set `AQT_TRUSTED_PROXIES` to the compose network
subnet before exposing it.

## Backup and restore

The data directory is the entire server state and is 100% ciphertext plus opaque
metadata, so it can be copied to any untrusted location.

### Taking a backup

- **Cold copy (simplest).** Stop the server, copy `AQT_DATA_DIR`, restart. SQLite is
  checkpointed on clean shutdown, so the copy is consistent:
  ```
  systemctl stop aqt-server
  cp -a /var/lib/aqt-server /backup/aqt-$(date +%F)
  systemctl start aqt-server
  ```
- **Online snapshot.** Take a filesystem/volume snapshot (LVM, ZFS, btrfs, cloud
  disk snapshot) of the whole data directory. This captures the SQLite database and
  the `packs/`/`blobs/` trees atomically.
- **Streaming.** The `packs/` and `blobs/` objects are content-addressed and
  write-once, so an `rsync` of them is safe to run live; pair it with a SQLite
  streaming backup (for example litestream) of the database file for near-continuous
  coverage. Restore then needs both halves from the same point in time, so prefer a
  filesystem snapshot unless you specifically need streaming.

### Restoring

1. Provision a new machine, install `aqt-server`, and place the backed-up data
   directory at `AQT_DATA_DIR`.
2. Start the server (with TLS as above).
3. On a client, `aqt login` (recovers the account from the email + passphrase and
   attaches this device), then `aqt clone <folder-id>` for each tracked folder, or
   `aqt pull` for individual files.

**Rollback guard.** If you restore an *older* snapshot than a client has already
seen, that client refuses to sync (it treats the regression as a hostile rollback
that would delete newer local files). Re-run the sync with `--accept-rollback` on
each client to reconcile from the restored state; one-sided differences surface as
conflicts to review. This is expected and protective — do not disable it globally.

### Proving it works

Run the drill after any change to the storage or restore path — a restore you have
never exercised is not a backup:

```
make restore-drill        # or: scripts/restore-drill.sh
```

It builds both binaries, pushes a realistic tree (nested dirs, a binary, an
executable, a Unicode name, a tracked `.git`), takes a cold backup, stands up a fresh
server from the copy, recovers on a clean client config from email + passphrase,
clones, and diffs the result against the original. `go test ./cmd/aqt -run
TestFullBackupRestoreDrill` is the in-process twin that runs on every CI build.

## Monitoring

Set `AQT_METRICS_ADDR` to expose Prometheus metrics on a separate plain-HTTP
listener:

```
AQT_METRICS_ADDR=127.0.0.1:9091 ./aqt-server
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: aqt
    static_configs:
      - targets: ["127.0.0.1:9091"]
```

Bind it to loopback or a private interface, never to the public address: the
metrics carry no plaintext, names, or emails, but they do enumerate per-account
opaque owner handles with storage totals, which is operator data. There is no
auth on the endpoint; the binding is the access control.

What you get:

- `aqt_http_requests_total{method,route,status}` and
  `aqt_http_request_duration_seconds` — request rates, latencies, and error
  counts per route (expired-link `410`s and upgrade-required `426`s show up as
  status labels).
- `aqt_pack_bytes_received_total` / `aqt_pack_bytes_served_total` /
  `aqt_public_object_bytes_served_total` — transfer volume.
- `aqt_gc_runs_total{trigger}`, `aqt_gc_packs_deleted_total`,
  `aqt_gc_bytes_freed_total`, `aqt_gc_packs_repacked_total`,
  `aqt_gc_bytes_reclaimed_total` — reclamation activity.
- `aqt_accounts` and per-account gauges keyed by owner handle:
  `aqt_account_storage_bytes` (the quota counter), `aqt_account_objects`,
  `aqt_account_resources`, `aqt_account_snapshots`, `aqt_account_devices`.
- Standard Go runtime and process metrics.

Per-account gauges are computed from SQLite at scrape time, so they are exact
with no refresh lag. Users can see their own numbers without operator access
via `aqt usage` (`GET /v1/account/usage`).

## Health checks and upgrades

- **Health.** `GET /healthz` returns `200 {"status":"ok"}` without authentication.
  It touches no state, so use it for liveness/readiness probes.
- **Upgrades.** Build the new binary, replace it, and restart the service. The
  graceful shutdown drains in-flight requests, so a restart does not sever an
  upload mid-write. Storage formats are versioned; a newer server reads older data.
- **Scheduled jobs.** Snapshots and GC run on the server timers above; there is no
  external cron to configure. Set the intervals to `0` to disable either.
