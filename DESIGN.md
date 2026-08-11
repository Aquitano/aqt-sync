# aqt — Design & Interface Spec

**This document has moved into `docs/`.** It was one ~1,100-line file covering the
threat model, the whole CLI surface, three wire formats, the HTTP API, and a
resolution log — which made it the file most likely to go stale, and the one most
likely to restate a fact that already lived somewhere else.

Start at **[docs/architecture.md](docs/architecture.md)**, which holds the locked
decisions, the package layout, and an index of every specification document.

This file stays at its old path because it is cited from past pull requests and
issues. It carries no content of its own.

## Where each section went

| Was | Now |
| --- | --- |
| <a id="1-locked-decisions"></a>§1 Locked decisions | [docs/architecture.md](docs/architecture.md#locked-decisions) |
| <a id="2-trust--crypto-model"></a>§2 Trust & crypto model | [docs/threat-model.md](docs/threat-model.md) |
| <a id="3-cli-surface"></a>§3 CLI surface | `aqt --help` for commands and flags; [docs/cli.md](docs/cli.md) for exit codes, output contracts, and comparison semantics |
| <a id="31-push--the-hero-command"></a>§3.1 Push | [docs/cli.md](docs/cli.md#push); streaming in [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#streamed-single-files) |
| <a id="32-pull--receive"></a>§3.2 Pull / receive | `aqt --help`; subpath form in [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#subpath-addressing) |
| <a id="33-visibility--lifecycle"></a>§3.3 Visibility / lifecycle | [docs/threat-model.md](docs/threat-model.md#what-revocation-actually-guarantees) and [docs/protocol/api.md](docs/protocol/api.md#public-link-lifecycle) |
| <a id="34-tracked-folder-git-style"></a>§3.4 Tracked folder | [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md); comparison commands in [docs/cli.md](docs/cli.md#four-questions-four-commands) |
| <a id="35-watch-daemon"></a>§3.5 Watch daemon | [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#watch-daemon) |
| <a id="36-identity"></a>§3.6 Identity | [docs/threat-model.md](docs/threat-model.md#the-wrapped-root-model); account deletion in [docs/protocol/api.md](docs/protocol/api.md#account-deletion) |
| <a id="37-snapshots-checkpoints--restore"></a>§3.7 Snapshots, checkpoints & restore | `aqt --help`; routes in [docs/protocol/api.md](docs/protocol/api.md#routes) |
| <a id="38-updates"></a>§3.8 Updates | [docs/updates.md](docs/updates.md) |
| <a id="39-encrypted-git-remotes"></a>§3.9 Encrypted Git remotes | [docs/git-repositories.md](docs/git-repositories.md) for the workflow, [docs/protocol/git-remote.md](docs/protocol/git-remote.md) for the format |
| <a id="3a-project-layout--status"></a>§3a Project layout & status | [docs/architecture.md](docs/architecture.md#package-layout) |
| <a id="4-module-interfaces-go-packages"></a>§4 Module interfaces | Dropped. The Go signatures in `internal/` were always authoritative; the TypeScript sketches predated the build |
| <a id="41-crypto-aqtcrypto"></a>§4.1 Crypto | Dropped — see `internal/crypto`, and [docs/threat-model.md](docs/threat-model.md#key-hierarchy) for the model |
| <a id="42-sync-engine-aqtsync"></a>§4.2 Sync engine | Dropped — see `internal/syncengine`; tracked state in [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md#tracked-state) |
| <a id="42a-folder-sync--implemented-design"></a>§4.2a Folder sync | [docs/protocol/folder-sync.md](docs/protocol/folder-sync.md) |
| <a id="42b-encrypted-git-remote--implemented-design"></a>§4.2b Encrypted Git remote | [docs/protocol/git-remote.md](docs/protocol/git-remote.md) |
| <a id="43-server-http-api-aqtserver"></a>§4.3 Server HTTP API | [docs/protocol/api.md](docs/protocol/api.md) |
| <a id="44-identity--local-keystore-aqtidentity"></a>§4.4 Identity / local keystore | Dropped — see `internal/identity`, and [docs/threat-model.md](docs/threat-model.md#client-data-at-rest) |
| <a id="5-resolved-behavior-and-open-limitations"></a>§5 Resolved behavior | [docs/decisions.md](docs/decisions.md) |
| <a id="still-open"></a>§5 Still open | [docs/threat-model.md](docs/threat-model.md#still-open) |
