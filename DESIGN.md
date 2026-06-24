# aqt — Design & Interface Spec

Zero-knowledge, end-to-end-encrypted file/folder sync for developers. A private
encrypted pastebin (`aqt push`) plus a git-style tracked folder (`aqt sync`) plus
an auto-watch daemon (`aqt watch`). The server only ever stores ciphertext and
opaque metadata; it can never read filenames, contents, or keys.

This document defines the **interfaces** (CLI surface + module contracts). It is
deliberately implementation-free — types and behavior, not code.

---

## 1. Locked decisions

| Decision | Choice |
| --- | --- |
| Encryption | Full E2E. Server is zero-knowledge. |
| Key derivation | Passphrase → Argon2id(+stored salt) → master key. Re-derivable on any machine. |
| Public sharing | Content key travels in the URL **fragment** (`#…`), never sent to the server. |
| Make private again | Rotate the content key, re-encrypt, old links die. |
| Default visibility | **Private.** `--public` opts into a shareable link. |
| CLI shape | One-liner spine (`aqt push`) + explicit verbs + share/private model. |
| Extras in v1 | `-P` password gate, clipboard auto-copy. |
| Out of v1 | standalone `rotate`, `--expire`, `--burn`, `--max-reads`, FUSE `mount`. |
| Runtime | Go. CLI on cobra; server on Gin; SQLite (modernc, pure-Go) + filesystem blobs. |
| Crypto | Argon2id (KDF), XChaCha20-Poly1305 (AEAD), HKDF-SHA256 → Ed25519 auth signing key. |

---

## 2. Trust & crypto model

```
passphrase ──Argon2id(salt)──▶ masterKey            (never leaves the device)
                                  │
                                  ├─ wraps ─▶ contentKey   (random, one per resource)
                                  │
                                  └─ HKDF ─▶ Ed25519 signing key
                                              (public half registered with server;
                                               logins sign a server challenge — no
                                               secret is ever sent)
file ──encrypt(contentKey)──▶ ciphertext + nonce + AEAD tag  ──▶ server (opaque blob)
metadata (real name, size…) ──encrypt(contentKey)──▶ encrypted manifest ──▶ server
```

**What the server stores per resource:** `id`, opaque `ownerHandle`, ciphertext
blob(s), encrypted-metadata blob, a `visibility` flag, a wrapped-key record *only
for private resources owned by an account*, version counter, timestamps. Nothing
plaintext, ever.

**Three reference forms a user can hold:**

| Form | Looks like | Who can decrypt | Used for |
| --- | --- | --- | --- |
| Private ref | `aqt://<id>` | only the owning account (master key unwraps the stored wrapped key) | `.env`-to-your-other-machine |
| Public link | `https://aqt.sh/x/<id>#k.<key>` | anyone with the link (key in fragment) | sharing |
| Gated link | `https://aqt.sh/x/<id>#p.<wrappedKey>` | anyone with the link **and** the password | sharing a secret semi-publicly |

The `k.` / `p.` prefix in the fragment is how the client knows whether to use the
key directly or prompt for a password to unwrap it. The server sees only `<id>`.

---

## 3. CLI surface

`aqt <command> [args] [flags]`. Bare `aqt <path>` is sugar for `aqt push <path>`.

Global flags (all commands): `--server <url>` (self-host; default `https://aqt.sh`),
`--profile <name>`, `--json`, `-q/--quiet`, `-v/--verbose`, `-h/--help`, `-V/--version`.

Exit codes: `0` ok · `1` generic · `3` auth/locked · `4` sync conflict · `5` network.

### 3.1 Push — the hero command

```
aqt push <path>           Encrypt one file, upload ciphertext. PRIVATE by default.
aqt <path>                Sugar for `aqt push <path>`.
aqt push -                Read plaintext from stdin.

  --public            Mint a shareable fragment link instead of a private ref.
  -P, --password      Password-gate a public link (prompts unless value given).
                      Implies --public. Recipient needs link AND password.
  -n, --name <label>  Human label shown in `aqt ls` (encrypted; not in the URL).
      --no-clip       Do not copy the resulting ref/URL to the clipboard.
```

Output (human default): the ref/URL (and `(copied to clipboard)` when applicable),
then a metadata line. With `-q`: only the ref/URL on stdout (pipe-friendly). With
`--json`: `{ id, ref, url?, name?, bytes, visibility }`.

```console
$ aqt .env
aqt://7yQ2pe        (copied to clipboard)
.env · 1.2 KB · private

$ aqt push deploy.log --public
https://aqt.sh/x/9fK2qd#k.Hs7nT4pQ2v…   (copied to clipboard)
deploy.log · 84 KB · public

$ aqt push .env --public -P
Share password: ********
https://aqt.sh/x/Qz81mn#p.R4t…         (copied to clipboard)
.env · 1.2 KB · public · password-gated
```

### 3.2 Pull / receive

```
aqt pull <url|id|ref>     Decrypt to disk (original name in CWD by default).
aqt cat  <url|id|ref>     Decrypt to stdout, never touches disk.

  -o, --out <path>        Write to a specific path.
      --force             Overwrite an existing file.
  -P, --password          Supply a gated link's password non-interactively.
```

```console
$ aqt pull https://aqt.sh/x/9fK2qd#k.Hs7…
wrote ./deploy.log (84 KB)

$ aqt pull aqt://7yQ2pe          # private ref; uses your unlocked master key
wrote ./.env (1.2 KB)
```

### 3.3 Visibility / lifecycle

```
aqt share   <id>          Make a private resource public; print the fragment link.
aqt private <id>          Make public again private: ROTATES the content key,
                          re-encrypts, old links die. Prints the new aqt:// ref.
aqt ls      [--json]      List your resources: name, kind, size, visibility, id.
aqt find    [query]       Fuzzy-search all files + folder contents in fzf; prints
                          the selected resource's ref. --json / --no-fzf for scripts.
aqt info    <id|url>      Metadata for one resource (no decrypt needed for your own).
aqt rm      <id>...       Delete server-side ciphertext + metadata.
```

```console
$ aqt private 9fK2qd
rotated content key — previous link no longer decrypts
aqt://9fK2qd
```

### 3.4 Tracked folder (git-style)

```
aqt init   [<dir>]        Mark a folder tracked. Writes .aqt/ and a starter .aqtignore.
aqt status [<dir>]        Changed / new / deleted / conflicted since last sync.
aqt sync   [<dir>]        Two-way reconcile: encrypt+push local changes, pull remote.
      --push-only / --pull-only / --dry-run / --force
aqt clone  <id|url> [<dir>]  Materialize a tracked folder on a new machine.
```

`.aqtignore` uses gitignore syntax. Conflicts (changed both sides) are left
untouched and reported; `--force` resolves in favor of local.

```console
$ aqt init && aqt sync
tracking ~/secrets → aqt://fold_K9p2
↑ 3 files encrypted and pushed · ↓ 0 · 0 conflicts
```

### 3.5 Watch daemon

```
aqt watch <dir>           Foreground watcher; syncs on change (debounced).
      -d, --daemon        Detach and run in background under the agent.
          --interval <d>  Debounce floor (default 2s).
          --once          Sync now and exit (cron-friendly).
aqt agent status|stop|logs [<dir>]   Manage background watchers.
```

### 3.6 Identity

```
aqt login   [--email <e>]   Prompt passphrase → derive master key → attach device.
aqt logout  [--all-devices] Drop local key material (optionally revoke others).
aqt whoami                  Account, device, key fingerprint, server.
aqt devices [ls | rm <id>]  List / revoke attached devices.
aqt passphrase change       Re-wrap master key under a new passphrase (no re-encrypt).
```

First-run auth is lazy: a push on a fresh machine prompts to create the account.
Because a typo'd first passphrase is **unrecoverable** (zero-knowledge), first run
requires a confirm prompt and an explicit "this cannot be reset" warning.

---

## 3a. Project layout & status

```
cmd/aqt/            CLI: login/logout, whoami, devices, push, pull, ls, find, share, private  [implemented]
cmd/aqt-server/     server entrypoint                                          [implemented]
internal/crypto/    key hierarchy + blob sealing (Argon2id, XChaCha20)         [implemented + tested]
internal/api/       shared wire types                                          [implemented]
internal/server/    Gin handlers + SQLite/FS store + chunk store + GC           [implemented + tested]
internal/identity/  local profile, keystore, session cache                     [implemented + tested]
internal/client/    HTTP API client                                            [implemented]
internal/syncengine/  manifest, .aqtignore/.aqtconfig, FastCDC chunking, 3-way plan [implemented + tested]
```

Working end-to-end today: signup/device-attach (Ed25519 challenge/response),
device management (`devices ls`/`devices rm`, `logout --all-devices` to revoke
other devices), private + public push/pull (key-in-fragment), password-gated
links, `share`, `private` (key rotation), `ls` (decrypts names + sizes locally
from each resource's owner-wrapped key), `find` (fzf fuzzy search across files and
folder contents), and a `login`-cached session key so the passphrase is entered
once per session (`logout` clears it). Every push wraps the content key
under the owner's master key, so even public resources can later be shared/rotated.
Verified by `go test ./...` plus live multi-machine cycles. A public share link
(`/x/<id>`) opens a landing page that resolves the resource and shows the `aqt
pull` command; in-browser decryption is deferred (the CLI does the decrypt).

Tracked folders (`init`/`status`/`sync`/`clone`) sync a directory by chunking its
files (FastCDC), deduplicating chunks per account, and storing a sealed manifest
as an ordinary resource — see 4.2a. v1 tracked folders are **private** (your own
machines), which keeps the chunk store uniformly owner-scoped; sharing a whole
folder publicly is deferred (single-file `--public` already covers sharing).
Not yet built: the `watch` daemon, pack-and-seal folders (`.aqtconfig pack=true`),
public whole-folder sharing, and in-browser decryption on the `/x/<id>` page.

Run locally: `go run ./cmd/aqt-server` (listens on `:8080`, `AQT_DATA_DIR`/`AQT_ADDR`
to override), then `aqt --server http://localhost:8080 login`.

## 4. Module interfaces (Go packages)

Four modules sit under the CLI. The canonical, authoritative interfaces are the Go
package signatures in `internal/`; the sketches below are the original design intent
(written pre-Go) and are kept for context. Keys are always fixed-size byte arrays,
never strings, and never logged.

### 4.1 Crypto (`@aqt/crypto`)

```ts
type MasterKey   = Uint8Array & { readonly __brand: "MasterKey" };
type ContentKey  = Uint8Array & { readonly __brand: "ContentKey" };

interface KdfParams {
  algo: "argon2id";
  salt: Uint8Array;
  opsLimit: number;
  memLimit: number;       // bytes
}

interface WrappedKey {
  ciphertext: Uint8Array; // contentKey encrypted under a wrapping key
  nonce: Uint8Array;
}

interface SealedBlob {
  ciphertext: Uint8Array; // AEAD, chunked stream for large files
  nonce: Uint8Array;
  tag: Uint8Array;
}

// Identity / key hierarchy
function newKdfParams(): KdfParams;                                   // fresh salt + sane defaults
function deriveMasterKey(passphrase: string, p: KdfParams): Promise<MasterKey>;
function generateContentKey(): ContentKey;
function wrapKey(ck: ContentKey, wrappingKey: MasterKey | ContentKey): WrappedKey;
function unwrapKey(w: WrappedKey, wrappingKey: MasterKey | ContentKey): ContentKey;

// Blob sealing
function seal(plaintext: Uint8Array, ck: ContentKey): SealedBlob;
function open(blob: SealedBlob, ck: ContentKey): Uint8Array;          // verifies tag, throws on mismatch

// Share-link fragment encoding (the # part — never reaches the server)
//   public:        "k." + base64url(contentKey)
//   password-gated: "p." + base64url(wrapKey(contentKey, deriveFromPassword(pw)))
function encodeFragment(ck: ContentKey, password?: string): string;
function decodeFragment(fragment: string, password?: string): ContentKey; // throws if pw needed/wrong
```

### 4.2 Sync engine (`@aqt/sync`)

```ts
interface ManifestEntry {
  path: string;        // POSIX relative path (plaintext locally; encrypted on the wire)
  size: number;
  mtimeMs: number;
  contentHash: string; // hash of plaintext, for change detection
  blobId: string;      // server id of the sealed blob
}

interface Manifest {
  version: number;
  entries: ManifestEntry[];
}

type SyncAction =
  | { kind: "upload";   path: string }
  | { kind: "download"; path: string }
  | { kind: "delete-local";  path: string }
  | { kind: "delete-remote"; path: string }
  | { kind: "conflict"; path: string };  // changed both sides since base

interface SyncPlan { actions: SyncAction[]; }

interface IgnoreMatcher { ignores(relPath: string): boolean; }

function loadIgnore(dir: string): IgnoreMatcher;                 // reads .aqtignore (gitignore syntax)
function snapshot(dir: string, ignore: IgnoreMatcher): Promise<Manifest>;
function plan(local: Manifest, base: Manifest, remote: Manifest): SyncPlan;  // three-way diff
```

`base` is the last-synced manifest cached in `.aqt/`. A `conflict` action is never
auto-resolved unless `--force` is passed.

### 4.2a Folder sync — implemented design

The TS sketch above predates the build; the authoritative interfaces are the Go
signatures in `internal/syncengine` and `internal/crypto`. What ships:

**A folder is a resource whose blob is a sealed manifest.** `init` creates a
private resource; `sync` uploads new chunks then PUTs an updated, re-sealed
manifest (version++); `clone` fetches the manifest and the chunks it references.
Ownership, versioning, and the master-key-wrapped content key are inherited from
the resource model unchanged.

**Chunking + dedup.** Files at or below an inline threshold (the FastCDC minimum)
are stored inline in the manifest (which is itself sealed), so a tree of many
tiny files never spawns tiny on-disk blobs. Larger files are split with **FastCDC**
(content-defined, so an edit re-chunks locally around the change). Each chunk is
sealed with **keyed convergent encryption**:

```
convergenceKey = HKDF(masterKey, "aqt-convergence-v1")     // account-scoped, never sent
chunkKey       = HKDF(convergenceKey, sha256(plaintext))    // unique per distinct plaintext
ciphertext     = XChaCha20-Poly1305(chunkKey, nonce=0, plaintext)   // deterministic
chunkID        = hex(sha256(ciphertext))                    // server storage address
```

Same account + same bytes → identical `ciphertext`/`chunkID`, so the server stores
one copy (dedup spans all of the account's folders). Different accounts derive a
different `convergenceKey`, so identical plaintext yields different ciphertext and
ID — no cross-user equality oracle. The zero nonce is safe because `chunkKey`
never repeats for distinct plaintext. The per-chunk `chunkKey` lives only in the
sealed manifest; the server holds ciphertext addressed by `chunkID` and nothing
else. Hex (not base64url) IDs avoid collisions on case-insensitive filesystems.

**Storage layout.** Sealed-blob resources keep `blobs/<id>.bin`. Chunks live in a
content-addressed, per-owner store with two-level fanout:
`chunks/<owner>/<ab>/<cd>/<chunkID>.bin`. The server records, per resource, which
chunk IDs its current manifest references (opaque hashes) so GC has roots.

**GC = mark-and-sweep, per owner.** Roots are the chunk references of the owner's
live resources; chunks not reachable from any root *and* older than an age guard
(so an in-flight upload isn't reaped before its manifest commits) are deleted.
No refcounts — the manifests are the source of truth, which survives crashes.

**`.aqtignore`** uses a pragmatic gitignore subset (comments, anchored paths,
`*`/`?`/`**` globs, trailing-slash dir rules); `.aqt/` is always ignored.
**`.aqtconfig`** (JSON) sets per-folder options; `pack` is reserved for
pack-and-seal (the whole tree tarred into one sealed blob, no chunk-level dedup)
instead of the chunked default — parsed today, but `sync` errors on `pack=true`
until that path is built (the chunked default is what ships).

### 4.3 Server HTTP API (`@aqt/server`)

Zero-knowledge REST over HTTPS. Auth is a bearer device token (`Authorization:
Bearer <token>`); the server authenticates *accounts*, never sees keys. All bodies
are opaque bytes or opaque metadata.

```
POST   /v1/account                  Create account. Body: { email, kdf, publicKey, deviceName }
                                     → { ownerHandle, deviceId, token }  (stores kdf + Ed25519 public key)
GET    /v1/account/salt?email=…      → { kdf }           (needed to re-derive on a new machine)
POST   /v1/auth/challenge            Body: { email } → { challengeId, nonce }  (one-time, short-lived)
POST   /v1/devices                   Attach device. Body: { email, challengeId, signature, deviceName }.
                                     Server verifies the Ed25519 signature over the nonce — no secret sent. → { deviceId, token }
DELETE /v1/devices/:id               Revoke a device.

PUT    /v1/resources                 Create (id omitted) or replace in place (id set, owner-checked, version++).
                                     Body: { ciphertext, encryptedMeta, visibility,
                                             wrappedKey? }   // wrappedKey only for private
                                     → { id, version }
GET    /v1/resources/:id             → { ciphertext, encryptedMeta, visibility, wrappedKey?, version }
                                     Public ids are fetchable without auth; private require the owner token.
POST   /v1/resources/:id/visibility  Body: { visibility, ciphertext, encryptedMeta, wrappedKey? }
                                     Used by `share`/`private`; rotation just replaces the blob.
DELETE /v1/resources/:id
GET    /v1/resources                 List owner's resources (ids + encrypted meta + visibility).

# Tracked folders: the folder's blob IS the sealed manifest, so it uses the
# resource routes above; PUT additionally carries chunkRefs (the chunk ids the
# new manifest references) so the server can root GC. Chunks are opaque,
# content-addressed, owner-scoped, and all require the owner token:
POST   /v1/chunks/check              Body: { ids } → { missing }   (have/want before upload)
POST   /v1/chunks                    Body: { chunks: [{ id, data }] } → { stored }
                                     Server verifies sha256(data)==id, stores under the owner.
POST   /v1/chunks/fetch              Body: { ids } → { chunks: [{ id, data }] }
POST   /v1/gc                        Mark-and-sweep the owner's unreferenced chunks → { deleted }
```

The server enforces: ownership, visibility (a private id returns 404 to anyone but
the owner), and integrity at the storage layer. It performs **no** decryption,
merge, or filename inspection.

### 4.4 Identity / local keystore (`@aqt/identity`)

```ts
interface Profile {
  name: string;            // default "default"
  server: string;
  email: string;
  ownerHandle: string;
  deviceId: string;
}

interface Session {
  profile: Profile;
  masterKey: MasterKey;    // held only while unlocked
}

// Persisted under ~/.config/aqt/ (config + encrypted device token in OS keychain).
function loadProfile(name?: string): Profile | null;
function unlock(profile: Profile, passphrase: string): Promise<Session>;   // derives masterKey
function lock(session: Session): void;                                      // wipes key from memory
function currentSession(): Session | null;                                 // for the watch agent
```

---

## 5. Open implementation questions (not blocking the interface)

- **Large single files / streaming** — `push`/`pull` still seal a whole file in memory under the 32 MiB body cap. Folder sync chunks files (FastCDC) and uploads chunks in batches, so a tracked large file is fine; a single `aqt push` of a >32 MiB file is not yet streamed.
- **Manifest size** — a folder's sealed manifest is one resource blob, so it shares the 32 MiB cap. Huge trees that overflow it would need a split/subtree manifest (deferred).
- **Public whole-folder sharing** — v1 tracked folders are private, so the chunk store is uniformly owner-scoped. Sharing a folder publicly needs its chunks under the folder key (not the account convergence key) in a publicly-readable space — deferred.
- **Argon2id tuning** (`time`/`memory`) per machine.
- **Account-enumeration oracle** — `GET /account/salt` confirms which emails are registered, and auth endpoints have no rate limiting.
- **Defense-in-depth crypto** — AEAD additional-data domain separation across blob/wrap/gated-wrap; complete key wiping (`ContentKey` has no `Wipe`).
- **Session cache at rest** — the cached master key is a plaintext 0600 file (bounded by `--ttl`, cleared by `logout`). An OS-keychain backend or an in-memory agent would remove the on-disk plaintext.
- **Conflict copies** — write `name.conflict-<device>` like Dropbox, or just report and block?

Resolved since the first draft: device attach is now an Ed25519 challenge/response
(no secret sent); resources support owner-checked in-place update + versioning; the
passphrase is cached per session so it is entered once, not per command. Content-
defined chunking + dedup is built for folders (FastCDC + keyed convergent
encryption, §4.2a); chunk lifecycle is mark-and-sweep GC scoped per owner.

These are deliberately left to implementation; the interfaces above don't change
based on how they're answered.
