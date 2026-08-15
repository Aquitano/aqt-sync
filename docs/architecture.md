# Architecture

Zero-knowledge, end-to-end-encrypted file and folder sync for developers: a private
encrypted pastebin (`aqt push`), a git-style tracked folder (`aqt sync`), an
auto-watch daemon (`aqt watch`), and encrypted Git remotes (`aqt::`). The server only
ever stores ciphertext and opaque metadata; it can never read filenames, contents, or
keys.

## Locked decisions

| Decision | Choice |
| --- | --- |
| Encryption | Full E2E. Server is zero-knowledge. |
| Key derivation | Passphrase → Argon2id(+stored salt) → master key. Re-derivable on any machine. |
| Public sharing | Content key travels in the URL **fragment** (`#…`), never sent to the server. |
| Make private again | Rotate the content key, re-encrypt, old links die. |
| Default visibility | **Private.** `--public` opts into a shareable link. |
| CLI shape | One-liner spine (`aqt push`) + explicit verbs + share/unshare model. |
| Extras | `-P` password gate, clipboard auto-copy. |
| Out of scope | FUSE `mount`. (Root-key rotation shipped as `aqt passphrase rotate-root`.) |
| Runtime | Go. CLI on cobra; server on Gin; SQLite (modernc, pure-Go) + filesystem blobs. |
| Crypto | Argon2id (KDF), XChaCha20-Poly1305 (AEAD), HKDF-SHA256 → Ed25519 auth signing key. |

## Where things are specified

| Document | Covers |
| --- | --- |
| [threat-model.md](threat-model.md) | Key hierarchy, what the server sees, revocation guarantees, deliberate side channels, residual limits |
| [protocol/api.md](protocol/api.md) | HTTP routes, wire representations, pagination, error codes, rate limiting, lifecycle enforcement |
| [protocol/folder-sync.md](protocol/folder-sync.md) | Chunking, convergent encryption, the Merkle DAG, packs and GC, `.aqtignore`/`.aqtconfig`, conflicts, the watch daemon |
| [protocol/git-remote.md](protocol/git-remote.md) | `RefsRoot`, bundle chain, helper dispatch, compaction |
| [compatibility.md](compatibility.md) | Capability negotiation policy, format rollout, the lifecycle enforcement echo |
| [cli.md](cli.md) | Exit codes, `--json` envelopes, comparison-command semantics |
| [deploy.md](deploy.md) | Every operator environment variable, TLS, systemd/Docker, backup and restore |
| [updates.md](updates.md) | Signed release manifest, signing-key custody, install and rollback |
| [git-repositories.md](git-repositories.md) | Encrypted Git remote workflow |
| [decisions.md](decisions.md) | Log of questions the design left open and how each was answered |

## Package layout

```text
cmd/aqt/            CLI: signup/login/logout/lock, whoami, devices, passphrase, account, push, pull, cat, ls, info, find, mv, share, unshare, shares, contacts, rm, init/status/sync/clone/diff, snapshot, checkpoint, restore, usage, repo, git setup, watch/agent, tui, update  [implemented]
cmd/aqt-server/     server entrypoint + `admin` account/quota tooling           [implemented + tested]
cmd/updatectl/      release tooling: generate/sign/verify the update manifest   [implemented + tested]
internal/crypto/    key hierarchy + blob sealing (Argon2id, XChaCha20)          [implemented + tested]
internal/compress/  the one pinned zstd codec (convergent ids depend on it)     [implemented + tested]
internal/api/       shared wire types + capability constants                    [implemented]
internal/server/    Gin handlers + SQLite/FS store + packed object store + GC   [implemented + tested]
internal/identity/  local profile, keystore, session cache                      [implemented + tested]
internal/client/    HTTP API client                                             [implemented]
internal/syncengine/  manifest, .aqtignore/.aqtconfig, FastCDC chunking, 3-way plan [implemented + tested]
internal/gitremote/ sealed bundle chain + RefsRoot behind `git-remote-aqt`      [implemented + tested]
internal/update/    signed release manifest, verified download, atomic install  [implemented + tested]
```

The Go package signatures in `internal/` are the authoritative interfaces. The
protocol documents describe formats and behavior; where prose and signatures
disagree, the signatures win.

## Status

Working end-to-end: signup and device attach (Ed25519 challenge/response), device
management, private and public push/pull with the key in the fragment, password-gated
links, `share`/`unshare` with key rotation, `ls` (which decrypts names and sizes
locally from each resource's owner-wrapped key), `find` (fzf fuzzy search across files
and folder contents), and a `login`-cached session key so the passphrase is entered
once per session. Every push wraps the content key under the owner's master key, so
even a public resource can later be shared or rotated. Verified by `go test ./...`
plus live multi-machine cycles.

A public share link (`/x/<id>`) opens a landing page that decrypts inline single files
locally from the `#k.` key or a password-gated `#p.` wrap; streamed files and folders
keep the `aqt pull` fallback. The pinned XChaCha20-Poly1305 and Argon2id browser
runtimes are self-hosted, and the fragment is never sent to the server.

Tracked folders default to **private**. `aqt share <folder-id>` flips a chunked folder
public and mints a fragment link, and a link holder clones or subpath-pulls it
read-only through the public object endpoint. Pack-and-seal folders stay unshareable.

Run locally: `go run ./cmd/aqt-server` (listens on `:8080`; `AQT_DATA_DIR` and
`AQT_ADDR` override), then `aqt --server http://localhost:8080 login`.
