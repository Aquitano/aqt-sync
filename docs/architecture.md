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
cmd/aqt/              CLI commands and TUI
cmd/aqt-server/       server entrypoint and account/quota administration
cmd/updatectl/        release-manifest generation, signing, and verification
internal/api/         shared wire types and capability constants
internal/client/      HTTP API client
internal/cliutil/     formatting and confirmation rules shared by both binaries
internal/compress/    pinned zstd codec; convergent ids depend on its output
internal/crypto/      key hierarchy and blob sealing
internal/folderstate/ tracked-folder state and the sealed base manifest
internal/fsatomic/    write-temp-fsync-rename file replacement
internal/gitremote/   sealed bundle chain and RefsRoot for `git-remote-aqt`
internal/identity/    local profile, keystore, and session cache
internal/packio/      pack upload, range fetching, and range cache
internal/safetext/    control-byte and bidi sanitizer for server-supplied text
internal/server/      Gin handlers, SQLite/filesystem store, packed objects, and GC
internal/syncengine/  manifests, ignore/config rules, chunking, planning, and merge
internal/update/      signed manifests, verified downloads, and atomic install
```

The packages and protocol documents describe the same contracts. A mismatch between
them is a bug; update both in the change that alters the contract.
