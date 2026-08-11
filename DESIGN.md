# aqt — Design & Interface Spec

**This document has moved into `docs/`.** It was one ~1,100-line file covering the
threat model, the whole CLI surface, three wire formats, the HTTP API, and a
resolution log — which made it the file most likely to go stale, and the one most
likely to restate a fact that already lived somewhere else.

Start at **[docs/architecture.md](docs/architecture.md)**, which holds the locked
decisions, the package layout, and an index of every specification document.

This file stays at its old path because it is cited from past pull requests and
issues. The headings below reproduce the original section titles so existing
`DESIGN.md#…` deep links still land; each one says where its content went and holds
nothing else.

---

## 1. Locked decisions

→ [docs/architecture.md](docs/architecture.md#locked-decisions)

## 2. Trust & crypto model

→ [docs/threat-model.md](docs/threat-model.md)

## 3. CLI surface

→ `aqt --help` for commands and flags, which are generated from the code that parses
them. [docs/cli.md](docs/cli.md) holds what `--help` cannot express: exit codes,
`--json` envelopes, and what each comparison command compares.

### 3.1 Push — the hero command

→ [docs/cli.md](docs/cli.md#push) for the output contract;
[docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#streamed-single-files)
for how a large file streams.

### 3.2 Pull / receive

→ `aqt --help`;
[docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#subpath-addressing) for
the `aqt://<id>/<path>` form.

### 3.3 Visibility / lifecycle

→ [docs/threat-model.md](docs/threat-model.md#what-revocation-actually-guarantees)
for what revocation guarantees;
[docs/protocol/api.md](docs/protocol/api.md#public-link-lifecycle) for server
enforcement.

### 3.4 Tracked folder (git-style)

→ [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md);
[docs/cli.md](docs/cli.md#four-questions-four-commands) for which command compares
which two states.

### 3.5 Watch daemon

→ [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#watch-daemon)

### 3.6 Identity

→ [docs/threat-model.md](docs/threat-model.md#the-wrapped-root-model) for the
wrapped-root key model; [docs/protocol/api.md](docs/protocol/api.md#account-deletion)
for account deletion.

### 3.7 Snapshots, checkpoints & restore

→ `aqt --help`; routes in
[docs/protocol/api.md](docs/protocol/api.md#routes).

### 3.8 Updates

→ [docs/updates.md](docs/updates.md)

### 3.9 Encrypted Git remotes

→ [docs/git-repositories.md](docs/git-repositories.md) for the workflow;
[docs/protocol/git-remote.md](docs/protocol/git-remote.md) for the format.

## 3a. Project layout & status

→ [docs/architecture.md](docs/architecture.md#package-layout)

## 4. Module interfaces (Go packages)

Dropped. The Go package signatures in `internal/` were always the authoritative
interfaces; the TypeScript sketches under this heading predated the Go build and were
labelled as such.

### 4.1 Crypto (`@aqt/crypto`)

→ `internal/crypto`; the model is in
[docs/threat-model.md](docs/threat-model.md#key-hierarchy).

### 4.2 Sync engine (`@aqt/sync`)

→ `internal/syncengine`; tracked-state binding and atomic materialization are in
[docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#tracked-state).

### 4.2a Folder sync — implemented design

→ [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md)

### 4.2b Encrypted Git remote — implemented design

→ [docs/protocol/git-remote.md](docs/protocol/git-remote.md)

### 4.3 Server HTTP API (`@aqt/server`)

→ [docs/protocol/api.md](docs/protocol/api.md)

### 4.4 Identity / local keystore (`@aqt/identity`)

→ `internal/identity`; what is stored on disk and how it is sealed is in
[docs/threat-model.md](docs/threat-model.md#client-data-at-rest).

## 5. Resolved behavior and open limitations

→ [docs/decisions.md](docs/decisions.md) for the resolution log.

### Still open

→ [docs/threat-model.md](docs/threat-model.md#still-open)
