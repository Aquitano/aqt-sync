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
| Out of v1 | standalone `rotate`, FUSE `mount`. |
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
for private resources owned by an account*, version counter, timestamps, and — for a
public link with a lifecycle policy — an `expires_at` timestamp, a `max_reads` cap, a
`reads` counter, an `exhausted_at` stamp, and a `reclaimed` tombstone flag. Nothing
plaintext, ever.

The lifecycle columns are the one deliberate, documented side channel: expiry
timestamps and read counters are plaintext operational metadata the server necessarily
sees to enforce a policy it cannot read the content of. The server still never sees the
file, its name, or any key; it only knows *when* a link dies and *how many times* it has
been fetched.

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

Exit codes: `0` ok · `1` generic · `3` auth/locked · `4` sync conflict · `5` network ·
`6` upgrade required (the remote resource is sealed in a newer format than this build
reads) · `7` link gone (the public link has expired or reached its read limit) · `75`
deferred (`watch --once` skipped because git was busy; retry later).

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
      --expire <dur>  Server-expire the public link after a duration (30m, 24h, 7d).
      --max-reads <n> Server-expire the public link after n downloads.
      --burn          Burn after reading (shorthand for --max-reads 1).
```

The three lifecycle flags require an explicit `--public`/`-P` (they never silently mint
a link) and are server-enforced: the server gates the opaque `id`, never seeing the
plaintext or the fragment key. An expired or exhausted link returns `410 Gone` (exit
code `7`); the ciphertext is then reclaimed and the id kept as a tombstone that keeps
returning `410` rather than decaying to `404`. A permitted streamed pull that has
consumed the last read gets a grace window so its already-started object fetches finish.
The client fails closed against a server that does not echo the accepted policy (an old
server), deleting the just-created resource rather than handing out a link that would
never expire.

Output (human default): the ref/URL (and `(copied to clipboard)` when applicable),
then a metadata line. With `-q`: only the ref/URL on stdout (pipe-friendly). With
`--json`: `{ id, ref, url?, name?, bytes, visibility }`.

A regular file at or above ~8 MiB streams through the chunk/pack pipeline instead of
sealing whole in memory — private, public, or gated alike. A public or gated streamed
file's objects are read back through the per-resource public object endpoint, so a link
holder can pull it with no account. Stdin has no size to threshold on and always seals
inline.

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
                          --expire/--max-reads/--burn attach a server-enforced
                          lifecycle policy after the fact (see push); re-sharing with a
                          policy resets the read counter.
aqt private <id>          Make public again private: ROTATES the content key,
                          re-encrypts, old links die. Prints the new aqt:// ref.
                          Clears any lifecycle policy (it belongs to the public link).
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

For a streamed (large) file, `private` re-wraps only the root under a fresh key and
flips visibility; the convergent chunk ciphertext and per-chunk keys are unchanged
(re-sealing would break dedup and re-upload the whole file). Revocation of the content
bytes is therefore enforced by the server's visibility check, not by re-encryption: an
old link holder who saved the root's chunk keys could still decrypt the ciphertext if
they somehow obtained it later — but they could equally have saved the plaintext. Either
way the old LINK is dead: the root no longer opens under the old key, and the server
stops serving the objects. (A tracked folder is private-only, so `private` refuses it.)

### 3.4 Tracked folder (git-style)

```
aqt init   [<dir>]        Mark a folder tracked. Writes .aqt/ and a starter .aqtignore.
aqt status [<dir>]        Local changes since last sync, plus incoming changes on the server.
      --offline           Report only local changes; skip the server check.
aqt sync   [<dir>]        Two-way reconcile: encrypt+push local changes, pull remote.
      --push-only / --pull-only / --dry-run / --force
aqt clone  <id|url> [<dir>]  Materialize a tracked folder on a new machine.
```

`.aqtignore` uses gitignore syntax. The starter file seeds common build-artifact
and cache excludes (`node_modules/`, `.next/`, `target/`, `__pycache__/`, `dist/`,
…) so regenerable outputs stay out of the sync by default; edit or `!`-re-include
any line. Conflicts (changed both sides) are left
untouched and reported; `--force` resolves in favor of local. When the target
tree holds a git repository, `init` notices it and asks whether to track the
`.git` directory too — declined by default (it ignores `.git`); accepting writes a
`!.git/` rule into the starter `.aqtignore`. Without a terminal the prompt takes
the default, so scripted `init` stays non-interactive.

```console
$ aqt init && aqt sync
tracking ~/secrets → aqt://fold_K9p2
↑ 3 files encrypted and pushed · ↓ 0 · 0 conflicts
```

### 3.5 Watch daemon

```
aqt watch <dir>           Foreground watcher; syncs on change (debounced).
      -d, --daemon        Detach and run in background under the agent.
          --interval <d>  Debounce floor (default 2s; overrides .aqtconfig).
          --once          Sync now and exit (cron-friendly).
aqt agent status|stop|logs [<dir>]   Manage background watchers.
```

The watcher listens for kernel file events (fsnotify, one watch per non-ignored
directory) and fingerprints the tree (path/size/mtime/mode, no content read) one
debounce interval after a burst settles; a slow safety rescan (5 min) catches
anything the events missed. Where the OS can't watch the tree (e.g. over the
inotify budget), it falls back to polling each `--interval`, backing off toward
30s while idle. A push is **held back while any sub-repo
is mid-operation** — a lock file (`index.lock`, top-level `*.lock`) *or* a paused
state with no lock (`MERGE_HEAD`/`CHERRY_PICK_HEAD`/`REVERT_HEAD`,
`rebase-merge/`, `rebase-apply/`) — so it never captures a half-written or
conflict-marked tree; it resumes when git finishes. The git scan is best-effort
(an unreadable subtree is skipped, not treated as idle) and covers nested repos,
submodules, and worktrees.

`-d` unlocks the session on the launching terminal first (so the detached child,
which has no tty, never needs to prompt), writes a pid + log under `.aqt/`, and
waits for the child to come up. If the cached session later expires, the daemon
stops cleanly (it can't prompt) rather than looping. Per-folder defaults live in
`.aqtconfig` (see §4.2a): `watch.interval` and `watch.gitGuard`.

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

**Wrapped-root key model (implemented).** The account's *master key* is a random
root key (`RK`), minted once at signup and never changed; it wraps content keys and
derives the signing and convergence keys. The passphrase derives an *unlock key*
(`UK = Argon2id(passphrase, salt)`) whose only job is to wrap `RK` — `wrappedRoot =
seal(RK, UK)`, stored server-side (opaque, zero-knowledge) and cached locally. So a
passphrase change is cheap: re-derive `UK`, re-wrap `RK`, upload one record — **no
resource is re-encrypted** (the master key is unchanged). It also bumps an
**auth-epoch**, which invalidates every other device's token (the server rejects a
token whose epoch is behind), and rotates a passphrase **verifier** the server stores
hashed. A device re-attaches by presenting both an Ed25519 challenge signature (proves
`RK`) *and* the verifier (proves the *current* passphrase), so a stale passphrase or a
cached root key alone cannot re-attach after a change. The new-device bootstrap
(`GET /account/salt`) returns `{kdf, wrappedRoot}` and serves an **indistinguishable
decoy** for an unknown email, so it no longer reveals which emails have accounts. True
root-key rotation (re-wrap every resource, for compromise recovery) is a separate,
deferred operation.

---

## 3a. Project layout & status

```
cmd/aqt/            CLI: login/logout, whoami, devices, push, pull, cat, ls, info, find, share, private, rm, watch/agent  [implemented]
cmd/aqt-server/     server entrypoint                                          [implemented]
internal/crypto/    key hierarchy + blob sealing (Argon2id, XChaCha20)         [implemented + tested]
internal/api/       shared wire types                                          [implemented]
internal/server/    Gin handlers + SQLite/FS store + packed object store + GC   [implemented + tested]
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
files (FastCDC), deduplicating objects per account, packing them into raw pack
files, and storing the manifest itself as objects under a tiny sealed root — see
4.2a. v1 tracked folders are **private** (your own machines), which keeps the
object store uniformly owner-scoped; sharing a whole folder publicly is deferred
(single-file `--public` already covers sharing).

The `watch` daemon (`watch`/`agent`) fingerprints a tracked folder (stat only, no
content read) each `--interval` (default 2s) and runs a two-way `sync` once the
tree settles. A push is held back while any sub-repo is mid-operation — both the
lock files git holds while running (`index.lock`, top-level `*.lock`) and the
paused states that carry no lock (`MERGE_HEAD`/`CHERRY_PICK_HEAD`/`REVERT_HEAD`,
`rebase-merge/`, `rebase-apply/`), across nested repos and submodule/worktree
`.git` pointers — so a sync never captures a half-written or conflict-marked tree,
and an edit that lands mid-sync is not lost. `-d/--daemon` detaches the watcher
(pid + log under `.aqt/`, session unlocked up front so the child never prompts);
`aqt agent status|stop|logs` manages it (and won't signal a recycled PID);
`--once` is the cron-friendly single guarded sync. Per-folder defaults
(`watch.interval`, `watch.gitGuard`) live in `.aqtconfig`.

Not yet built: public whole-folder sharing and in-browser decryption on the
`/x/<id>` page.

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

**A folder is a resource whose blob is a sealed manifest root.** `init` creates a
private resource; `sync` streams changed files into packs (uploading the objects
the server lacks) then PUTs an updated root pointer (version++); `clone` fetches
the manifest objects, reassembles the manifest, and streams in the file objects it
references. The manifest is no longer the blob itself: it is chunked through the
same pipeline as file content and stored as objects, and the resource blob is a
tiny sealed `ManifestRoot` naming those objects (so a one-file edit re-uploads a
handful of manifest objects, not the whole manifest — the 64 MiB blob ceiling is
gone). Ownership, versioning, and the master-key-wrapped content key are inherited
from the resource model unchanged.

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

**Chunk granularity is a per-folder tradeoff.** The default profile targets an ~8 KiB
average chunk (min 2K / normal 8K / max 64K), tuned for source trees: fine dedup, but
a large binary pays it in metadata — a 500 MB file is ~64,000 chunks, and every chunk
costs a manifest entry, a server-side SHA-256 verify, and an object-index row. Folders
of large binaries (media, datasets, VM images) can set `chunkProfile: "large"` (64K /
256K / 1M, ~256K average) for ~32x fewer chunks per MB, trading dedup resolution for
far less per-MB metadata and ingest CPU; a `chunk` block sets explicit sizes when
neither preset fits. Because boundaries are derived from these sizes, the choice is
sticky: changing a folder's profile re-chunks it once, with no dedup against the old
profile, so it is a deliberate per-folder decision (and `.aqtconfig` syncs in-tree, so
every clone agrees). Note the profile's `min` is also the inline cutoff, so a coarse
profile inlines larger small files into the (sealed) manifest.

**Storage layout.** Sealed-blob resources keep `blobs/<id>.bin`. Objects (chunks)
are not one file each: they are concatenated into **packs** (~16 MiB), one
immutable content-addressed file with a self-describing trailing index, fanned out
per owner: `packs/<owner>/<ab>/<cd>/<packID>.bin`. A pack ships as raw bytes (no
base64), and a pull range-fetches only the span covering the objects it needs. The
server maps `chunkID → (packID, offset, length)` in an `objects` table and records,
per resource, which object IDs its current root references (opaque hashes) so GC
has roots. Object IDs are still `hex(sha256(ciphertext))`; the dedup key is
unchanged, so pack non-determinism (ordering) does not affect dedup.

**GC = mark-and-sweep at pack granularity, per owner.** Roots are the object
references of the owner's live resources (file-chunk IDs ∪ manifest-object IDs). A
pack is deleted when **none** of its objects is reachable from any root *and* it is
older than an age guard (so an in-flight upload isn't reaped before its manifest
commits). v1 tolerates dead objects inside a still-live pack (repack is a
follow-up). No refcounts — the manifests are the source of truth, which survives
crashes; the resource→objects foreign key is the backstop that rejects a root
referencing an object the owner no longer stores.

**`.aqtignore`** uses a pragmatic gitignore subset (comments, anchored paths,
`*`/`?`/`**` globs, trailing-slash dir rules); `.aqt/` and `.git/` are always
ignored (a tracked tree syncs working files, never a live git directory), though
a later `!`-rule can re-include. **`.aqtconfig`** (JSON) sets per-folder options:

```jsonc
{
  "pack": false,                 // pack-and-seal instead of chunked sync (see below)
  "chunkProfile": "default",     // CDC granularity: "default" (~8K avg) or "large" (~256K avg)
  "chunk": { "min": 65536, "normal": 262144, "max": 1048576 }, // explicit sizes; overrides chunkProfile
  "watch": {
    "interval": "5s",            // watch debounce floor; --interval overrides it
    "gitGuard": true             // hold pushes while a sub-repo is mid-operation (default true)
  }
}
```

`pack` selects pack-and-seal instead of the chunked default: the whole tree is
tarred and sealed under the folder content key into fixed-size segments (a fresh
nonce each, so no chunk-level dedup), streamed through the same packs as file
content so the 64 MiB blob ceiling no longer caps the tree by its byte size — only
the sealed `PackRoot` (a compact segment-id list) rides in the resource blob, so the
practical bound moves to its segment count (hundreds of thousands of 4 MiB segments,
i.e. ~TB scale), the same segmented-manifest limit the chunked path has. It leaks no per-file structure —
the server sees only opaque, per-sync-unique segments — but any change re-ships the
whole folder, and `sync` reconciles it whole-folder last-writer-wins (a change on
both sides is one conflict; `--force` resolves local-wins) rather than merging per
file; `clone` untars it. The `watch` block lets a folder pin its daemon behavior
in-tree, the same way `.aqtignore` pins its exclusions.

**Chunked mode leaks a size-sequence fingerprint (choose pack-and-seal to avoid it).**
FastCDC boundaries are content-derived and the pack index stores each object's
ciphertext length, so the *sequence of chunk sizes* of a file is observable to the
server (and to anyone who reads the object store). The keyed convergence key stops an
attacker *matching chunk hashes* against a candidate file, but not matching that
size-sequence — the classic content-defined-chunking leak. For a known target file an
attacker can therefore confirm its presence from the shapes alone. Pack-and-seal
(`pack: true`) exists precisely to avoid this: it tars the whole tree and seals it into
fixed-size, per-sync-unique segments with no per-file boundary, so it leaks only the
total size. Length-bucket padding of chunk ciphertexts (e.g. quantizing to 4 KiB) would
blunt the chunked-mode leak, but it changes the sealed ciphertext length and so the
chunk content address, breaking dedup identity against existing chunks and rippling
through the manifest and pack format; it is deferred as future work rather than folded
into the seal path here.

### 4.3 Server HTTP API (`@aqt/server`)

Zero-knowledge REST over HTTPS. Auth is a bearer device token (`Authorization:
Bearer <token>`); the server authenticates *accounts*, never sees keys. All bodies
are opaque bytes or opaque metadata.

Every request carries `X-Aqt-Capability: <n>`, a small integer naming the highest
encrypted-resource format the client can read (`1` = v0.1.0 baseline, `2` = v0.2.0
id-binding). A write to `PUT /v1/resources` may declare `minClient` — the lowest
capability that can read the formats it seals — which the server stores per resource
(and copies onto snapshots taken from it). On a read (`GET /v1/resources/:id`, snapshot
fetch) or an overwriting write, a requester whose capability is below the resource's
stored `min_client` gets `426 Upgrade Required` with a structured body
(`{ error, code: "upgrade_required", min_client }`) *before* any payload — an
actionable "upgrade aqt" instead of a downstream decryption failure. A request with
no (or an unparseable) capability header is assumed to be `2`: the header ships only
after v0.2.0, so any header-less client is no newer than v0.2.x, whose newest release
reads id-bound resources; pre-0.2 clients are indistinguishable and keep the
status-quo AEAD failure on id-bound resources only. A declared `minClient` above the
writer's own capability is rejected `400`; an omitted declaration stores the baseline.

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
                                             wrappedKey?, expireSeconds?, maxReads? }  // wrappedKey only for private;
                                                                                       // policy only for public
                                     → { id, version, expiresAt?, maxReads? }  // echoes the accepted policy
GET    /v1/resources/:id             → { ciphertext, encryptedMeta, visibility, wrappedKey?, version }
                                     Public ids are fetchable without auth; private require the owner token.
                                     410 Gone (code "gone") if the public link has expired, exhausted its
                                     read limit, or been reclaimed. Owner reads are never counted or expired
                                     (until reclaimed).
POST   /v1/resources/:id/visibility  Body: { visibility, expireSeconds?, maxReads? }
                                     Used by `share`/`private`; rotation just replaces the blob. Echoes the
                                     accepted policy; a private flip clears it.
DELETE /v1/resources/:id
GET    /v1/resources                 List owner's resources (ids + encrypted meta + visibility).
POST   /v1/public/resources/:id/objects  Unauthenticated. Body: { ids } → positional length-prefixed
                                     object slices. Serves exact objects of a PUBLIC resource, each id
                                     of which must be referenced by that resource (the share-link read
                                     path for a public/gated streamed file). ≤10,000 ids per call.

# Tracked folders: the folder's blob is a sealed ManifestRoot pointing at the
# manifest objects, so it uses the resource routes above; PUT additionally carries
# chunkRefs (file-object ids ∪ manifest-object ids the new root references) so the
# server can root GC. Objects ship inside raw packs; all routes require the owner token:
POST   /v1/chunks/check              Body: { ids } → { missing }   (have/want before packing)
POST   /v1/chunks/locate             Body: { ids } → { locations: [{ id, packId, off, len }] }
PUT    /v1/packs/:id                  Body: raw pack bytes (octet-stream). id = sha256(pack);
                                     server verifies the address and every object slice. Range-able GET.
                                     → { storedObjects }
GET    /v1/packs/:id                  → raw pack bytes; supports Range (pull fetches only the needed span)
POST   /v1/gc                        Pack-level mark-and-sweep → { deletedPacks, freedBytes }
```

**Public-link lifecycle.** `PUT /v1/resources` and the visibility endpoint accept an
optional `expireSeconds` (a TTL — the server stores `expires_at = now + expireSeconds`,
so client clock skew never matters) and `maxReads` on a public resource. The server
enforces both: a non-owner read past the expiry or the read limit gets `410 Gone` with
`{ error, code: "gone" }`; only successful non-owner serves count toward `maxReads`, and
concurrent reads cannot over-serve (the count is committed under a per-resource lock).
Both responses **echo** the accepted policy (`expiresAt`, `maxReads`) — the enforcement
handshake: an old server ignores the unknown request fields and echoes nothing, so a new
client fails closed (it deletes the resource and errors) rather than mint a link that
would never expire. Expired links (immediately) and exhausted ones (after a grace window
so an in-flight streamed pull can finish) are reclaimed by the GC sweep: the ciphertext
blob and its objects are deleted and the row kept as a `reclaimed` tombstone that keeps
returning `410`. The object-read endpoint 410s on expiry/reclamation but *not* on
`maxReads` exhaustion, so the final permitted streamed pull is never cut off mid-flight.

The server enforces: ownership, visibility (a private id returns 404 to anyone but
the owner), public-link lifecycle (expiry and read limits), and integrity at the storage
layer. It performs **no** decryption, merge, or filename inspection.

Deployment hardening is env-configured (all optional; the zero value is the
self-hosted default):

```
AQT_REGISTRATION     open (default) | invite      # invite gates signup on a token
AQT_INVITE_TOKENS    tok1,tok2                     # accepted invite secrets (invite mode)
AQT_QUOTA_BYTES      0                             # per-owner stored-pack-byte cap; 0 = unlimited
AQT_MAX_DEVICES      0                             # per-account device cap; 0 = unlimited
AQT_AUTH_RATE        0                             # authed requests/sec per token; 0 = default (50)
AQT_AUTH_BURST       0                             # authed burst per token; 0 = default (500)
AQT_TRUSTED_PROXIES  (unset = loopback)            # X-Forwarded-* trust; "none" trusts none
```

A client whose server runs in invite mode passes the token via `aqt login --invite`
(or `AQT_INVITE_TOKEN`).

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

- **Large single files / streaming** — a private single file at or above ~8 MiB now streams: `push` chunks it (FastCDC), convergent-seals and packs it in a bounded-memory pass, and stores a tiny sealed `FileRoot` (the resource blob) naming the objects; `pull`/`cat` range-fetch the packs and materialize straight to disk. Memory is O(one pack), and the inline body cap no longer bounds private file size. Smaller files keep the one-shot inline path. Public and gated single files now stream the same way — a link holder reads their objects through the per-resource public object endpoint (`POST /v1/public/resources/:id/objects`), and `share`/`private` re-wrap only the root, so the content bytes are never re-sealed. Stdin still seals in memory under the body cap.
- **Manifest size / subtree dedup** — *implemented (Phase 4):* a chunked folder is now a Merkle DAG of directory nodes. Each directory node lists its name-sorted children and is sealed through the convergent pipeline under a distinct `aqt-treenode-v1` AAD, so a node's content address is its subtree Merkle hash and a moved/copied/renamed directory dedups for free (its node and file chunks are already on the server). The resource blob is a tiny sealed `TreeRoot` under `AADTreeRoot`. Directories are first-class: empty directories round-trip and directory modes propagate. The format is a clean break (`tree` metadata flag, v2); older folders are not read. Spec: `docs/phase4-merkle-dag.md`. The reconcile's remote read is lazy: because directory nodes are content-addressed, the last-synced base tree is sealed in memory and any node the remote shares with it is served from those bytes, so an unchanged subtree is reconstructed without a fetch and only the nodes on a spine that changed since the base hit the network — a no-op sync does zero node round-trips. The level-batched fetch shares one pack source (object locations, spans, and the byte-bounded LRU) across the whole walk, so a pack carrying nodes from several levels is range-fetched once, and a node landing inside an already-fetched span is served from memory. Directory-mode conflicts surface like file conflicts (a plain sync aborts; `--force` takes local). Rename detection is reporting-only: a move dedups its bytes and still executes as delete+add, but `status`, `sync --dry-run`, and `snapshot diff` coalesce an unambiguous delete+add pair (same content address, one path per side) into `renamed old -> new`, with whole-directory moves collapsing to one entry via the stable subtree hash.
- **Persistent metadata cache** — *resolved:* every remote tree walk (clone, cold reconcile, `find`, snapshot diff) shares an on-disk, content-addressed cache of directory-node and chunk-list ciphertexts (default `~/.cache/aqt/nodes`, `AQT_NODE_CACHE_DIR` overrides, `AQT_NO_NODE_CACHE=1` disables). An object's id is the sha256 of its ciphertext, so entries are immutable (no invalidation, ever) and self-verifying (a corrupt file fails its hash check and is dropped); `OpenNode` re-verifies on open either way, so a disk hit is exactly as trustworthy as a server fetch. Only ciphertext is stored — the same bytes the server keeps — and the cache is LRU-pruned to a 256 MiB budget. A repeated `find` or diff over a large account therefore fetches only nodes it has never seen.
- **Subpath addressing** — *resolved:* `aqt://<id>/<path>` addresses one entry inside a chunked folder. `pull`/`cat` walk only the path's spine (one directory node per segment) and fetch just that entry's chunks; pulling a directory materializes its subtree from the subtree's own content-addressed node without touching the rest of the folder; `aqt ls <folder>[/<path>]` lists one directory by fetching the spine plus that node. Pack-and-seal folders refuse with guidance (no per-entry objects exist — the privacy trade-off working as intended).
- **Repack** — *resolved:* `RepackOwner` compacts partially-dead packs (copies live objects into a fresh pack under a bounded byte budget, swapping atomically after a re-check of age and liveness), so dead objects inside still-live packs are now reclaimed.
- **Push throughput / upload overlap** — *resolved:* the push no longer stalls the chunker on each pack's two upload round-trips (`CheckChunks` + `PutPack`). `packUploader` dispatches a full pack to a bounded pool (`uploadConcurrency`), so the CPU keeps sealing the next pack while earlier ones are in flight — hiding both the server ingest time and, over a WAN, the sequential RTTs. The pool bounds in-flight packs (backpressure via `errgroup.SetLimit`), so push memory stays O(a few packs); a snapshot error drains the pool before returning. Server-side, `PutPack` now writes the pack's object-index rows in batched multi-row INSERTs (was one `Exec` per chunk), cutting the dominant SQLite cost of ingesting a pack of many small chunks.
- **Client-side crypto parallelism** — *resolved:* chunk sealing (`SealChunk`: XChaCha20-Poly1305 + two SHA-256s) now fans across GOMAXPROCS workers (`sealStream`), lifting the CPU ceiling for large-file, high-bandwidth pushes. The split stays on the walk goroutine (`SplitStream` reuses its emit buffer, so each piece is copied — via a recycled buffer set — before crossing to a sealer), and a single collector reassembles results in stream order, so the manifest's chunk order and the sink's `Add` sequence are exactly the serial loop's. Backpressure bounds buffered plaintext at O(workers × Max) per file.
- **Public whole-folder sharing** — v1 tracked folders are private, so the object store is uniformly owner-scoped. Sharing a folder publicly needs its objects under the folder key (not the account convergence key) in a publicly-readable space — deferred.
- **Argon2id tuning** (`time`/`memory`) per machine — *resolved:* `crypto.CalibrateKdf` benchmarks the creating machine at signup (and on `passphrase change`) and scales the iteration count to a preset's target unlock time (`interactive` ~0.5s/64 MiB, `moderate` ~1s/256 MiB default, `sensitive` ~2.5s/1 GiB), stepping memory down toward a 64 MiB floor on a machine too slow to fit one pass. Params are public and travel with the account, so every device re-derives the same key; `--kdf-preset` and manual `--kdf-time/--kdf-memory/--kdf-threads` override, and `passphrase calibrate` re-tunes an existing account in place via the cheap wrapped-root re-wrap (no resource is re-encrypted; other devices re-login).
- **Account-enumeration oracle** — *resolved:* unauthenticated auth routes are rate-limited, and `GET /account/salt` returns an indistinguishable decoy `{kdf, wrappedRoot}` for an unknown email instead of a 404. The decoy's Argon2id costs are now drawn per-email (HKDF over the server secret) from the same value set a moderate calibration produces (memory ∈ {64, 128, 256 MiB}, iterations clustered where a ~1 s unlock lands on common hardware) rather than the fixed package default, so a decoy's params no longer stand out. `POST /account` no longer answers `409` on a duplicate email in the default *open* registration mode: it returns the same success shape with a decoy token that grants nothing, so signup stops being an existence oracle (the caller's next authenticated call fails, matching the wrong-passphrase ambiguity). An *invite* mode (`AQT_REGISTRATION=invite` + `AQT_INVITE_TOKENS`) additionally gates every signup on a server-issued token, closing the email-squatting hole for hosted deployments.
- **Authenticated-route abuse / quotas** — *resolved:* the authenticated group is now rate-limited per device token (coarse token-bucket, generous burst so a large sync/clone is unaffected), with a second, far tighter limiter on the expensive `POST /gc` keyed per owner. Per-owner quotas cap stored pack bytes (`AQT_QUOTA_BYTES`) and device count (`AQT_MAX_DEVICES`); `0` means unlimited. The byte counter is maintained incrementally inside the pack put / GC / repack transactions (a column on `accounts`, backfilled on migration), so a quota check is one indexed read and never scans the objects table. An over-quota pack put returns `507`, which the client surfaces distinctly.
- **Trusted proxies** — *resolved:* the Gin engine's trusted-proxy list is set explicitly (`AQT_TRUSTED_PROXIES`, default loopback-only, `none` to trust none), so the `X-Forwarded-*` foot-gun is no longer left at Gin's trust-all default. The rate-limit bucket key stays on the TCP peer address regardless, so a spoofed forwarded header cannot mint fresh buckets.
- **Defense-in-depth crypto** — *resolved:* AEAD additional-data domain separation across blob/wrap/gated-wrap has been in since v1; the resource id is now bound into the AAD as well (`SealBound`/`OpenBound`, tag form `aqt-<role>-v2:<id>` over the meta, inline body, and the FileRoot/TreeRoot/PackRoot resource blobs, plus snapshot labels), so a server swapping whole records (blob + meta + wrapped key are mutually consistent under the per-resource key) between ids fails the tag check. The id the check verifies against is the client's own: `GetResource` rejects a response whose echoed id differs from the requested one (and a filtered snapshot listing rejects rows claiming another resource), so the server cannot satisfy the binding by echoing the id of whatever record it chose to serve. Chunk objects, directory nodes, and pack segments stay id-free — they are content-addressed, client-verified against their address, and reachable only through an id-bound root, and binding them would kill cross-resource dedup. Bounded caveats: (1) a create seals before the server assigns the id, so a resource is unbound until its first re-seal (folder syncs upgrade the root — and once, the metadata — on the next update; a one-shot `push` stays unbound); (2) the v1 fallback that keeps old blobs readable means a server can serve a stale unbound blob (it still cannot forge or cross-open one) — full strictness would need client-generated ids and a fallback cut-off; (3) a snapshot browsed without naming a resource has no client-side expectation to pin its claimed resource id to (in-place restore checks the tracked folder's id; `--into` restores trust the claim); (4) once a folder has synced with an id-binding client, its root no longer opens on clients from before this change — upgrade every device together. Capability negotiation (`X-Aqt-Capability` request header + a per-resource `min_client` the server enforces with `426 Upgrade Required`, see §4.3 and `docs/compatibility.md`) now gates future format boundaries: a client below a resource's declared `min_client` is refused with an actionable upgrade error before any payload, rather than reaching a bare AEAD failure. The boundary already crossed by id-binding predates the mechanism, so a genuinely pre-0.2 client still fails id-bound reads at the AEAD tag (it is assumed capability 2 and cannot be told apart); negotiation protects the *next* boundary, once every reader advertises a capability. Key wiping: `ContentKey.Wipe` exists and every acquisition site scrubs on scope exit, including the longest-lived by-value copies in the sync/pack apply contexts; transient by-value copies on intermediate stack frames remain out of reach, the inherent Go caveat `Wipe` documents.
- **Session cache at rest** — *resolved:* the cached master key is sealed under a random per-profile key kept in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service, via pure-Go `zalando/go-keyring`); the on-disk 0600 file holds only ciphertext + `expiresAt` and is useless without the keychain entry. The device token moves into the keychain too. A host with no keychain backend (headless server), or one that sets `AQT_NO_KEYCHAIN=1`, falls back to the machine-bound key/file, so non-interactive operation is unchanged there. Remaining caveat: a process running as the same user can still reach the keychain (or re-derive the machine key); fully closing that needs a passphrase/biometric-gated agent or hardware enclave, still deferred. Exposure stays bounded by `--ttl` and cleared by `logout`.
- **Local base manifest at rest** — *resolved:* `.aqt/base.json` (the last-synced manifest) carries per-chunk decryption keys and inline small-file plaintext, so it is now sealed at rest under the **same** per-profile sealing key as the session cache (keychain, or machine-bound fallback), with a distinct `aqt-base-at-rest-v1` AAD. A backed-up / cloud-synced / stolen-disk copy is therefore useless off-machine, closing the same vectors the session-cache seal does, and it inherits the same residual caveat (a same-user process that reaches the keychain). The seal is read offline by `status` and before `unlockMaster`, so it uses the sealing key, not the master key. Old plaintext bases are read transparently and upgraded to the sealed form on the next sync (disjoint top-level keys make the two forms unambiguous). Retention note: an atomic rename replaces the file so no torn plaintext lingers, but pre-migration plaintext in freed disk blocks is not scrubbed — a forensic-only residue on the local disk.
- **Conflict copies** — write `name.conflict-<device>` like Dropbox, or just report and block?

Resolved since the first draft: device attach is now an Ed25519 challenge/response
(no secret sent); resources support owner-checked in-place update + versioning; the
passphrase is cached per session so it is entered once, not per command. Content-
defined chunking + dedup is built for folders (FastCDC + keyed convergent
encryption, §4.2a); chunk lifecycle is mark-and-sweep GC scoped per owner.

These are deliberately left to implementation; the interfaces above don't change
based on how they're answered.
