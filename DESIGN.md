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
| Out of v1 | FUSE `mount`. (Root-key rotation shipped as `aqt passphrase rotate-root`.) |
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
| Public link | `https://aqt.example.com/x/<id>#k.<key>` | anyone with the link (key in fragment) | sharing |
| Gated link | `https://aqt.example.com/x/<id>#p.<wrappedKey>` | anyone with the link **and** the password | sharing a secret semi-publicly |

The `k.` / `p.` prefix in the fragment is how the client knows whether to use the
key directly or prompt for a password to unwrap it. The server sees only `<id>`.

---

## 3. CLI surface

`aqt <command> [args] [flags]`. Bare `aqt <path>` is sugar for `aqt push <path>`
when the argument contains a path separator; a bare word that names an existing file
asks for confirmation first (and errors as an unknown command without a terminal),
so a typo'd subcommand never uploads a file.

Global flags (all commands): `--server <url>` (default `http://localhost:8080`; a
share link is served by the server that stores the resource, so the
`aqt.example.com` URLs below stand in for wherever you host it),
`--profile <name>`, `--json`, `-q/--quiet`, `--progress` (live transfer bar on a
terminal, for sync/clone), `-h/--help`, `-v/--version`.

Exit codes: `0` ok · `1` generic · `3` auth/locked · `4` sync conflict · `5` network
(including a rate limit that outlasted the client's retry budget — both are temporary,
so cron retries rather than giving up) · `6` upgrade required (the remote resource is
sealed in a newer format than this build reads; the message names the command that
upgrades this install) · `7` link gone (the public link has expired or reached its read
limit) · `75` deferred (`watch --once` skipped because git was busy; retry later).

### 3.1 Push — the hero command

```
aqt push <path>           Encrypt one file, upload ciphertext. PRIVATE by default.
aqt <path>                Sugar for `aqt push <path>`.
aqt push -                Read plaintext from stdin.

  --public            Mint a shareable fragment link instead of a private ref.
  -P, --password      Password-gate a public link (bare -P prompts on a terminal;
                      an inline value must be attached: -P<pw> or --password=<pw>).
                      Implies --public. Recipient needs link AND password.
      --password-stdin  Read the gate password from stdin, keeping it out of the
                      process table (the path the TUI uses).
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
https://aqt.example.com/x/9fK2qd#k.Hs7nT4pQ2v…   (copied to clipboard)
deploy.log · 84 KB · public

$ aqt push .env --public -P
Share password: ********
https://aqt.example.com/x/Qz81mn#p.R4t…         (copied to clipboard)
.env · 1.2 KB · public · password-gated
```

### 3.2 Pull / receive

```
aqt pull <url|id|ref>     Decrypt to disk (original name in CWD by default).
aqt cat  <url|id|ref>     Decrypt to stdout, never touches disk.

  -o, --out <path>        Write to a specific path (pull only).
      --force             Overwrite an existing file (pull only).
  -P, --password          Gated link's password (bare -P prompts; inline -P<pw>).
      --password-stdin    Read the password from stdin (keeps it out of the process table).
```

```console
$ aqt pull https://aqt.example.com/x/9fK2qd#k.Hs7…
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
                          --with <email> grants one account read-only instead.
aqt share ls [<id>]       List outgoing access: public links (with their lifecycle
                          policy) and account grants — "who has access?".
aqt unshare <id>          Take access back: ROTATES the content key, re-encrypts,
                          old links die. Prints the new aqt:// ref. Clears any
                          lifecycle policy (it belongs to the public link).
                          --with <email> revokes that one grant instead.
                          Asks for confirmation (-y skips).
aqt shares                Incoming: resources other accounts granted you (read-only).
aqt contacts              Accounts pinned on first use for `--with` sharing;
                          `rm <email>` drops a pin, `verify <email>` compares fingerprints.
aqt ls      [--json]      List your resources: name, kind, size, visibility, id.
aqt find    [query]       Fuzzy-search all files + folder contents in fzf; prints
                          the selected resource's ref. --json / --no-fzf for scripts.
aqt info    <id|url>      Metadata for one resource (no decrypt needed for your own).
aqt rm      <id>...       Delete server-side ciphertext + metadata (confirms; -y skips).
                          --with-snapshots also drops every snapshot of each resource.
```

```console
$ aqt unshare 9fK2qd -y
rotated content key — previous link no longer decrypts
aqt://9fK2qd
```

For a streamed (large) file, `unshare` re-wraps only the root under a fresh key and
flips visibility; the convergent chunk ciphertext and per-chunk keys are unchanged
(re-sealing would break dedup and re-upload the whole file). Revocation of the content
bytes is therefore enforced by the server's visibility check, not by re-encryption: an
old link holder who saved the root's chunk keys could still decrypt the ciphertext if
they somehow obtained it later — but they could equally have saved the plaintext. Either
way the old LINK is dead: the root no longer opens under the old key, and the server
stops serving the objects.

### 3.4 Tracked folder (git-style)

```
aqt init   [<dir>]        Mark a folder tracked. Writes .aqt/ and a starter .aqtignore.
aqt status [<dir>]        Local changes since last sync, plus incoming changes on the server.
      --offline           Report only local changes; skip the server check.
aqt sync   [<dir>]        Two-way reconcile: encrypt+push local changes, pull remote.
      --push-only / --pull-only / --dry-run / --force
      --reconcile / --rehash / --accept-rollback
      --conflicts block|copy|merge
aqt clone  <id|url> [<dir>]  Materialize a tracked folder on a new machine.
      --adopt             Bind an existing directory: reuse matching files by hash,
                          reconcile differences as conflicts.
aqt diff [<path>...] [dir]   Unified diff of local changes against the sync base.
      --remote            Diff incoming remote changes against the base instead.
      --against <snapshot-id|remote>  Compare the working tree against a snapshot,
                          or against the folder's current remote state.
      --name-status       List classified paths instead of file content
                          (A added, M modified, P permissions, T type, D deleted,
                          R renamed). Implied by --json.
```

**Four questions, four commands.** They are easy to confuse, so each one names what it
compares:

| command | left | right | answers |
| --- | --- | --- | --- |
| `aqt status` | last-synced base | working tree, *and* current remote | what changed here, and what is waiting there |
| `aqt sync --dry-run` | base + both sides | — | what a reconcile would do (three-way plan) |
| `aqt diff --against=remote` | current remote | working tree | how these two states differ, right now |
| `aqt snapshot diff <id>` | a snapshot | live resource, or a second snapshot | how a past state differs from another |

`status` is base-relative and reports two independent halves, so a path can appear in
both when each side moved; `--against=remote` has no base at all, so two sides that
converged on the same content report *no differences* even while `status` still shows
work pending on each. Neither replaces the other.

Every `diff` mode is read-only: nothing is uploaded, nothing lands in the working
tree, and neither `.aqt/base.json` nor the recorded remote version is touched, so a
comparison can never change what a later `sync` decides to do.

`--against=remote` needs the folder key. It prompts for the passphrase on a terminal
and never otherwise: under `--json` or a non-terminal stdin a locked session reports
`"complete": false` with `"reason": "session-locked"` (both sides and the remote
version still named) rather than blocking on a prompt that nobody would answer. The
same completeness fields appear in the human output as an explicit sentence, so an
incomplete comparison is never mistaken for a clean one. A chunked folder answers
from directory-node metadata alone; a pack-and-seal folder has no per-file remote
metadata, so its whole tree is streamed back and hashed in memory — a truthful
per-entry answer that costs the folder's full download but writes nothing to disk.
That holds for the classified rendering. A unified text diff needs both sides'
bytes, so a pack-and-seal folder is reconstructed into a temporary directory and
removed again on exit; the working tree is still never written.

`.aqtignore` uses gitignore syntax. The starter file seeds common build-artifact
and cache excludes (`node_modules/`, `.next/`, `target/`, `__pycache__/`, `dist/`,
…) so regenerable outputs stay out of the sync by default; edit or `!`-re-include
any line. Conflicts (changed both sides) are left
untouched and reported; `--force` resolves in favor of local. `--conflicts=copy`
(or `conflicts: "copy"` in `.aqtconfig`) instead keeps the local version at its path
and writes the remote one alongside as `<name>.conflict-<host>-<timestamp>`, then
continues (exit 0); the copy is ordinary content the next sync pushes.
`--conflicts=merge` first attempts a bounded three-way line merge for text files;
non-overlapping edits are pushed and reported as `~ merged <path>`, while overlapping,
binary, oversized, delete/modify, or unavailable-base cases use the same copy fallback.
It never writes conflict markers. Git repositories should use an encrypted `aqt::`
remote (§3.8); `.git` stays ignored in normal folder sync.

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
aqt agent start|status|stop|logs [<dir>]   Manage background watchers
                          (`agent start` = `watch -d`; --foreground stays attached).
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
aqt signup  [--email <e>]   Create the account: mint a root key, wrap it under the
                            passphrase, attach this device.
      --invite <t>          Invite token if the server needs one (or AQT_INVITE_TOKEN).
      --kdf-preset/--kdf-time/--kdf-memory/--kdf-threads   Argon2id tuning.
aqt login   [--email <e>]   Prompt passphrase → derive master key → attach device.
                            Does not create accounts; that is `signup`.
      --ttl <d>             Session cache lifetime (0 = until lock/logout).
aqt lock                    Forget the cached key; this device stays attached.
aqt logout  [--all-devices] Revoke this device and delete its local profile
                            (optionally revoke others; -y skips).
aqt whoami                  Account, device, key fingerprint, server.
aqt devices [ls | rm <id>]  List / revoke attached devices.
aqt passphrase change       Re-wrap master key under a new passphrase (no re-encrypt).
aqt passphrase calibrate    Re-tune Argon2id cost, same passphrase (other devices re-login).
aqt passphrase rotate-root  Compromise recovery: mint a fresh root key, re-wrap every
                            resource/snapshot/grant, revoke every other device (-y skips).
aqt account delete          Erase the account and everything stored under it. Needs the
      (alias: unregister)   passphrase, not just this device's token (-y skips the
                            confirmation, never the passphrase).
```

Because a typo'd first passphrase is **unrecoverable** (zero-knowledge), `signup` on a
terminal confirms it and warns explicitly that it cannot be reset. Without a terminal
(a scripted signup) the passphrase is read once and the confirmation is skipped.

**Account deletion.** `aqt account delete` erases the account, its devices,
resources, snapshots, grants, objects, packs, and the ciphertext files behind them,
over `DELETE /v1/account`. Grants *to* the account go too: its published key is gone,
so those wraps could never be opened again. The row deletions are one transaction and
are authoritative; the files are unlinked after it commits, so any the server could
not remove are counted back in `fileErrors` — the account is gone either way, but
that ciphertext is still on the operator's disk. The request carries the
passphrase-derived verifier, checked inside the deleting transaction, so a device
token on its own is not authority to destroy an account and a passphrase change
cannot land between the proof and the erasure it authorizes. That same read re-checks
suspension, which the middleware answers from a cache an operator in another process
cannot invalidate; every other route tolerates that window, and this one cannot. The
client verifies the passphrase locally against the cached `wrappedRoot` first, so a
typo fails without a round trip. On success the local profile, cached session, and
keychain entries go with it; tracked folders keep their plaintext files but their
`.aqt/state.json` now names an account that no longer exists.

An operator reaches the same store-level erasure through `aqt-server admin accounts
delete`, authorized by filesystem access to the data directory rather than by a
passphrase, and not through this route.

A tracked folder records the account that created it (`.aqt/state.json`), and every
command that touches its remote resource refuses to run under a different account.
The binding is on the account's owner handle, not its signing key, so
`passphrase rotate-root` — which mints a new signing key on every device — does not
strand tracked folders.

**Wrapped-root key model (implemented).** The account's *master key* is a random
root key (`RK`), minted at signup and rotated only during compromise recovery; it wraps content keys and
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
decoy** for an unknown email, so it no longer reveals which emails have accounts. `aqt passphrase rotate-root` is the compromise-recovery operation: it mints a fresh RK, rewraps every recoverable resource and snapshot content key plus incoming grant, migrates the derived signing/encryption identities, and atomically switches the account record. The server issues a fresh token only to the initiating device and removes every other device; they recover by logging in again with the passphrase. Existing convergent objects remain readable because their per-object keys are sealed in their roots; future writes derive convergence from the new RK.

### 3.7 Snapshots, checkpoints & restore

Snapshots are immutable, account-global, point-in-time copies of a resource, pinned
server-side so a later sync or delete cannot reclaim them. A checkpoint is a named,
anchored snapshot; `restore` is the top-level command that brings either back.

```
aqt snapshot create [dir] [label]   Snapshot a tracked folder's current state.
      -l, --label <s>               Label, encrypted on this machine (or positional).
          --id <id>                 Snapshot this resource id directly.
aqt snapshot list [dir]             List snapshots, newest first (alias: ls).
      --id <id> / --limit <n> / --since <dur> / --before <dur>
aqt snapshot find [query]           Fuzzy-search snapshots in fzf; prints the id.
      --id <id> / --no-fzf
aqt snapshot diff <snapshot-id>     Diff against the live tree (+ added, - removed, ~ modified).
      --against <snapshot-id>       Compare two snapshots instead of the live resource.
aqt snapshot export <snapshot-id>   Decrypt a snapshot to plaintext (leaves the boundary).
      -o, --out <dir>               Destination (required).
aqt snapshot prune [snapshot-id...] Delete by id, or by retention.
      --keep-last <n> / --before <dur> / --id <id> / --dir <dir> / --dry-run / -y
aqt snapshot anchor|unanchor <id>   Protect a snapshot from retention, or release it.
aqt snapshot auto [dir]             Show, or toggle (--on/--off, --id), scheduled snapshots.
aqt checkpoint <name> [dir]         Named, anchored snapshot retention never prunes.
      --id <id>
aqt restore <name-or-id> [dir]      Restore a checkpoint by name or a snapshot by id.
      -o, --out <dir>               Side-by-side into a new dir (default aqt-restore-<id>).
      --in-place                    Roll the live folder back and re-sync it (-y skips).
      --id <id>                     Scope the name lookup to this resource id.
```

### 3.8 Updates

```
aqt update                          Check, show the transition, confirm, then install.
      --check                       Report only; change nothing.
      --yes                         Install without asking (non-interactive).
      --prerelease                  Check the beta channel, which also carries stable.
      --json                        currentVersion / availableVersion / channel / status / releaseUrl.
aqt update policy [off|notify|auto] Show or set what ordinary commands do (default off).
```

Every tagged release publishes a canonical manifest (`aqt-update.json`) describing
its version, channel, publication time, and one exact name/size/SHA-256/URL tuple per
published platform, plus a detached Ed25519 signature over those bytes. The client
verifies the signature against public keys compiled into the binary *before* it reads
any field, then re-encodes what it parsed and requires byte equality, so only the one
canonical form of a manifest is acceptable. Multiple trusted keys are supported and a
release can carry several signatures, which is what makes key rotation survivable.

Selection is by `(GOOS, GOARCH)` and the archive name is derived per platform, so the
`aqt-server` archive published in the same release is unreachable. Unknown keys, bad
signatures, malformed or oversized metadata, duplicated platforms, a missing build for
this platform, a foreign asset URL, and a published version older than the running one
all fail closed. Stable never carries a prerelease; beta is opt-in and a superset. A
source build reports that updates do not apply to it rather than guessing its version.

Installing replaces only a standalone binary. Homebrew, WinGet, and Scoop
installations are recognized from the resolved executable path and the receipts
beside it — not from what `PATH` resolves to — and are reported with their owner's
upgrade command instead of being overwritten. The archive is downloaded to the
install directory, checked against the signed length and digest as it arrives, and
unpacked to exactly one regular `aqt`; the candidate must run and report the promised
version before the installed binary is touched. The old binary is renamed aside
rather than overwritten (the one thing Windows refuses on a running image) and
renamed back on any failure.

An opt-in policy (`off` by default, `notify`, `auto`) lets ordinary commands check at
most once a day, only after a successful command on a terminal, never for
`--json`/`--quiet`/scripts/watch agents, and never affecting that command's status.
`auto` installs stable releases only, and defers while any registered watch agent is
running. Format, key custody, rotation, compromise recovery, ownership, and rollback
files: **docs/updates.md**.

### 3.9 Encrypted Git remotes

```console
aqt git setup [--dir D] [-y]             Install the git-remote-aqt link.
aqt repo create <name> [--compact-at N]  Create a private encrypted Git remote.
aqt repo ls                              List remotes and bundle-chain state.
aqt repo info <name-or-id>               Show refs, HEAD, format and snapshots.
aqt repo gc <name-or-id>                 Compact from locally available remote refs.
aqt repo restore <snapshot-id> [-y]      Restore a pre-compaction bundle chain.
aqt repo rm <name-or-id> [-y]            Delete the remote and reclaim its packs.

git clone aqt::<name-or-id> [dir]
git remote add origin aqt::<name-or-id>
```

Git discovers a remote helper by exec'ing `git-remote-<transport>`, so `aqt` is a
multi-call binary: invoked under the name `git-remote-aqt` (matched exactly, plus
`.exe`) it runs its own hidden `git-remote-helper` subcommand. `aqt git setup` creates
that link beside the client — symlink, else hard link, else copy — and refuses a
directory a package manager owns, since the package ships its own link. One binary
means client and helper cannot disagree about protocol or crypto. A symlink resolves
by name and follows `aqt update`; the hard-link and copy fallbacks stay bound to the
file the update renamed away, so the update reports the stale link and names the
command that remakes it. `make build` installs `aqt`, the link, and `aqt-server`
under `bin/`. The URL deliberately carries no server
or credential: the helper uses the active aqt profile and cached unlocked session, and
never prompts when Git invokes it non-interactively. Fetch, push, force-push, tags,
ref deletion, SHA-1/SHA-256 repositories, optimistic concurrency retries, manual
compaction, and automatic compaction at the configured threshold are supported.
Shallow clone, sharing/grants, and the Git wire protocol are not.

---

## 3a. Project layout & status

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

Working end-to-end today: signup/device-attach (Ed25519 challenge/response),
device management (`devices ls`/`devices rm`, `logout --all-devices` to revoke
other devices), private + public push/pull (key-in-fragment), password-gated
links, `share`, `unshare` (key rotation), `ls` (decrypts names + sizes locally
from each resource's owner-wrapped key), `find` (fzf fuzzy search across files and
folder contents), and a `login`-cached session key so the passphrase is entered
once per session (`logout` clears it). Every push wraps the content key
under the owner's master key, so even public resources can later be shared/rotated.
Verified by `go test ./...` plus live multi-machine cycles. A public share link
(`/x/<id>`) opens a landing page that decrypts inline single files locally from
the `#k.` key or a password-gated `#p.` wrap; streamed files and folders keep the
`aqt pull` fallback. The pinned XChaCha20-Poly1305 and Argon2id browser runtimes
are self-hosted, and the fragment is never sent to the server.

Tracked folders (`init`/`status`/`sync`/`clone`) sync a directory by chunking its
files (FastCDC), deduplicating objects per account, packing them into raw pack
files, and storing the manifest itself as objects under a tiny sealed root — see
4.2a. Tracked folders default to **private** (your own machines); `aqt share
<folder-id>` flips a chunked folder public and mints a `#k.`/`#p.` fragment
link, and a link holder clones or subpath-pulls it read-only through the public
object endpoint (see §5, "Public whole-folder sharing").

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

**Tracked-state identity binding.** `.aqt/state.json` records, next to the
resource id and server URL, the owning profile name and the account's signing-key
fingerprint. Tracked commands default to that recorded identity (no `--profile`
needed even from a shell whose default profile differs), and an explicit
`--profile` or `--server` that contradicts it is rejected with guidance rather
than talking to the wrong account or server. A profile that was re-logged into a
different account (fingerprint change) is likewise refused. If the recorded
profile itself starts talking to a different server (a migration or a restore
under a new URL), the folder follows the profile — the account key, not the URL,
is the identity — and records the move.

**Atomic materialization.** Operations that create trees commit all-or-nothing:
`clone`, directory pulls, snapshot export and side-by-side restore download into
a staging directory beside the destination and rename it into place only on
success (an in-place restore stages and swaps with rollback), so an interrupted
transfer, a permission failure, or a destination collision leaves the
destination exactly as it was. `init` stages the local `.aqt` control state
before registering the remote resource and deletes the just-created resource if
the local commit fails, so a failed init is side-effect-free on both ends.

*Binding migration:* state written by an older
build carries no binding fields; the first tracked command adopts the active
profile only when that profile's server matches the folder's recorded server, and
writes the binding back. A legacy folder whose recorded server matches no
configured profile fails with instructions to pass the owning `--profile` (or
re-clone) — it is never silently rebound to whatever account happens to be
active.

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

**One definition of a changed tree.** `syncengine.Diff` classifies two manifests into
a `Delta`: every tracked file, symlink, and directory that differs, across additions,
removals, content, mode, and type changes, plus delete+add pairs coalesced into
renames. It is what `status` (both its local and incoming halves), the TUI's files
panel, both sync adapters' local-change gates, `snapshot diff`, and
`diff --name-status` report from, so a directory-only or mode-only edit cannot be
visible to one caller and invisible to another. `DiffTreeRoots` produces the same
`Delta` from two Merkle-DAG roots without materializing either side, and `snapshot
diff`'s materialize fallback scans both temp trees back into manifests, so all three
routes classify identically.

**One result shape for a two-sided comparison.** Every command that compares two named
states — `diff --name-status` (against the base, a snapshot, or the current remote),
`snapshot diff`, and the TUI's compare view — returns the same `comparison`: the two
labelled sides, a `complete` flag with a stable `reason` when file-level comparison was
unavailable, and the `Delta` behind the familiar added/removed/modified buckets. A new
side or a new caller extends that type rather than forking a parallel one, which is why
the TUI can render a snapshot diff and a working-tree-versus-remote comparison through
the same code.

The three-way planners (`Plan`, `PlanDirs`) stay separate — they answer "what should
this sync do", not "what differs" — but compare entries through the same
`entryDiffers` rule, so the operational plan and the reported classification cannot
disagree about what counts as a change. A symlink's own permission bits are excluded
from that rule: a scan never records them and apply never sets them, so comparing them
would manufacture a difference no side could resolve.

**One sync prologue, two adapters.** Both sync adapters — chunked and pack-and-seal —
enter through the same `syncSession`: it loads `state.json` and the last-synced base,
refuses a missing base unless `--reconcile`, and acquires the authenticated client and
unlocked master key. Each reconcile attempt then runs the session's `openRemote`, which
fetches the resource, classifies a server rollback, unwraps the content key, decodes the
sealed metadata, and checks the folder's format. Every one of those is a safety guard,
and a fix applied to one adapter's copy did not reach the other, so they are defined
once. Two details are load-bearing: a rollback is classified *before* the content key
is unwrapped and the metadata decoded, so a server whose version regressed reports that
rather than a cross-mode config typo or a keyless resource — a version regression is a
statement about the server's integrity and outranks anything read out of the record it
served; and the format guard is parameterized by the mode the caller expects,
because a pack folder carries `packed` and never the chunked path's `tree` flag, so one
shared check would reject either every pack folder or none. What stays per-adapter is
what each does with the verdict — `openRemote` reports whether the base can be trusted,
and the chunked path plans against an empty base while pack-and-seal drops into its
baseless whole-folder reconcile — along with all planning, transfer, apply, and conflict
behavior.

**Chunking + dedup.** Files at or below an inline threshold (the FastCDC minimum)
are stored inline in the manifest (which is itself sealed), so a tree of many
tiny files never spawns tiny on-disk blobs. Larger files are split with **FastCDC**
(content-defined, so an edit re-chunks locally around the change). Each chunk is
sealed with **keyed convergent encryption**:

```
convergenceKey = HKDF(masterKey, "aqt-convergence-v1")     // account-scoped, never sent
chunkKey       = HKDF(convergenceKey, sha256(plaintext))    // unique per distinct plaintext
ciphertext     = XChaCha20-Poly1305(chunkKey, nonce=0, compress(plaintext))   // deterministic
chunkID        = hex(sha256(ciphertext))                    // server storage address
```

Same account + same bytes → identical `ciphertext`/`chunkID`, so the server stores
one copy (dedup spans all of the account's folders). Different accounts derive a
different `convergenceKey`, so identical plaintext yields different ciphertext and
ID — no cross-user equality oracle. The zero nonce is safe because `chunkKey`
never repeats for distinct plaintext. The per-chunk `chunkKey` lives only in the
sealed manifest; the server holds ciphertext addressed by `chunkID` and nothing
else. Hex (not base64url) IDs avoid collisions on case-insensitive filesystems.

**Chunk granularity is a per-folder tradeoff.** By default the chunker scales with
file size: files up to 8 MiB use the fine profile (~8 KiB average, min 2K / normal 8K /
max 64K, tuned for source trees), files over 8 MiB use the "large" sizes (64K / 256K /
1M, ~256K average), and files over 1 GiB use "huge" (256K / 1M / 4M, ~1 MiB average) —
every chunk costs a manifest entry, a server-side SHA-256 verify, and an object-index
row, so a large binary is not shredded into hundreds of thousands of records while
small files keep byte-level dedup. Setting `chunkProfile` to `"large"` or `"huge"`
pins that granularity for every file in the folder, and a `chunk` block sets explicit
sizes when no preset fits. Because boundaries are derived from these sizes, a pinned
choice is sticky: changing a folder's profile re-chunks it once, with no dedup against
the old profile, so it is a deliberate per-folder decision (and `.aqtconfig` syncs
in-tree, so every clone agrees). Note the profile's `min` is also the inline cutoff,
so a coarse profile inlines larger small files into the (sealed) manifest.

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
commits). Dead objects inside a still-live pack are reclaimed separately by
`RepackOwner`, which copies the live objects into a fresh pack under a bounded byte
budget and swaps atomically (§5). No refcounts — the manifests are the source of
truth, which survives crashes; the resource→objects foreign key is the backstop that
rejects a root referencing an object the owner no longer stores.

**`.aqtignore`** uses a pragmatic gitignore subset (comments, anchored paths,
`*`/`?`/`**` globs, trailing-slash dir rules); `.aqt/` and `.git/` are always
ignored (a tracked tree syncs working files, never a live git directory), though
a later `!`-rule can re-include. **`.aqtconfig`** (JSON) sets per-folder options:

```json
{
  "version": 1,
  "pack": false,
  "chunkProfile": "default",
  "conflicts": "merge",
  "watch": {
    "interval": "5s",
    "gitGuard": true
  }
}
```

The file is plain JSON (no comments) and is parsed strictly: an unknown key or an
invalid value fails the command with the file path and field, rather than being
silently ignored. `version` is the schema version (optional; 0/absent and 1 mean
the current schema — a higher value is refused so a file written for a newer aqt
is never half-understood). `chunkProfile` is `"default"` (scales granularity with
file size) or `"large"`/`"huge"` (pin one coarse granularity); the rare tree a
named profile does not fit can pin explicit byte sizes instead with
`"chunk": { "min": ..., "normal": ..., "max": ... }`, which overrides
`chunkProfile`. `watch.interval` is the daemon's debounce floor (a Go duration;
`--interval` overrides it) and `watch.gitGuard` the git-lock guard (default true).
`conflicts` (`"block"`, the default, `"copy"`, or `"merge"`) sets the folder's
conflict handling; `--conflicts` overrides it per run. Merge is chunked-only: it
uses a self-contained Myers line diff and three-way combine for text up to 8 MiB
(no NUL in the first 8 KiB of base/local/remote), and falls back to copy without
markers whenever edits overlap or a version cannot be merged.

`pack` selects pack-and-seal instead of the chunked default: the whole tree is
tarred and sealed under the folder content key into fixed-size segments (a fresh
nonce each, so no chunk-level dedup), streamed through the same packs as file
content so the 64 MiB blob ceiling no longer caps the tree by its byte size — only
the sealed `PackRoot` (a compact segment-id list) rides in the resource blob, so the
practical bound moves to its segment count (hundreds of thousands of 4 MiB segments,
i.e. ~TB scale), the same segmented-manifest limit the chunked path has. It leaks no per-file structure —
the server sees only opaque, per-sync-unique segments — but any change re-ships the
whole folder, and `sync` reconciles it whole-folder last-writer-wins (a change on
both sides is one conflict; `--force` resolves local-wins; `--conflicts=copy` and
`--conflicts=merge` are chunked-only and are refused here, since there is no per-file conflict to resolve) rather
than merging per
file; `clone` untars it. The archive carries a header per tracked directory, not just
per file and symlink: the extract side rebuilds its manifest from the tar alone, so a
directory left out of the stream would lose its mode and — if empty — itself. An
archive written before this carries no directory headers, so the first sync after
upgrading re-ships such a folder once and then converges. The `watch` block lets a
folder pin its daemon behavior in-tree, the same way `.aqtignore` pins its exclusions.

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

### 4.2b Encrypted Git remote — implemented design

A Git remote is a private resource with sealed metadata kind `gitremote` and minimum
client capability 4. Its id-bound `RefsRoot` contains HEAD, the ref map, object format,
generation, and an ordered bundle chain. Bundle bytes are split into per-push-unique
XChaCha20-Poly1305 segments with fresh nonces and uploaded through the existing pack
API; the server observes ciphertext segment sizes/count/timing, never refs, filenames,
commits, or object structure. Git remotes cannot be public or granted in v1.

`aqt git-remote-helper`, which is what an invocation under the name `git-remote-aqt`
dispatches to, implements the standard `list`, `fetch`, `push`, and `option`
remote-helper protocol against the active profile and session. Fetch applies only missing bundles in chain order, deriving
applicability directly from locally present tips with no helper-side state file. Push
checks fast-forward policy, creates one
incremental bundle for the ref batch, uploads its segments, then flips `RefsRoot` with
`ExpectedVersion`. A 409 re-reads refs, re-checks ancestry, rebuilds, and retries up to
five times; losing uploads remain unrooted and age-GC eligible. Ref deletion changes
only the root. A standalone annotated tag always includes its tag object. The helper's
`object-format` capability and list keyword initialize fresh clones with the first
push's recorded SHA-1 or SHA-256 format; later mismatches are refused clearly.

At the per-repo threshold (64 by default), a clone containing every remote tip through
a local or matching remote-tracking ref compacts exactly those refs to one bundle,
snapshots the pre-compaction root, and CAS-swaps the new root while incrementing
`generation`; unrelated local refs are excluded. `aqt repo gc` requests the same
operation explicitly, and `aqt repo restore` version-CAS restores a saved root after
snapshotting the current chain. Full bundles carry an explicit marker, making repeated
GC a no-op; a spurious compaction CAS retry reuses the already-uploaded full bundle and
pre-compaction snapshot while the source resource version is unchanged.
Every root PUT lists all live segment ids, so old chains become ordinary mark-and-sweep
garbage. Segment-before-root ordering, the resource mutex, and CAS make a killed helper
or concurrent push leave either the old complete root or the new complete root, never
a torn remote.

### 4.3 Server HTTP API (`@aqt/server`)

Zero-knowledge REST over HTTPS. Auth is a bearer device token (`Authorization:
Bearer <token>`); the server authenticates *accounts*, never sees keys. All bodies
are opaque bytes or opaque metadata.

Every request carries `X-Aqt-Capability: <n>`, a small integer naming the highest
encrypted-resource format the client can read (`1` = v0.1.0 baseline, `2` = v0.2.0
id-binding, `3` = root rotation, `4` = encrypted Git remotes). A resource write may declare `minClient` — the lowest
capability that can read the formats it seals — which the server stores per resource
(and copies onto snapshots taken from it). On a read (`GET /v1/resources/:id`, snapshot
fetch) or an overwriting write, a requester whose capability is below the resource's
stored `min_client` gets `426 Upgrade Required` with a structured body
(`{ error, code: "upgrade_required", minClient }`) *before* any payload — an
actionable "upgrade aqt" instead of a downstream decryption failure. A request with
no (or an unparseable) capability header fails closed to `1` (baseline): a
header-less binary is indistinguishable from a pre-0.2 one, so assuming `2` could
hand it an id-bound root that only failed at AEAD open. A declared `minClient` above the
writer's own capability is rejected `400`; an omitted declaration stores the baseline.

```
POST   /v1/account                  Create account. Body: { email, kdf, publicKey, wrappedRoot,
                                     authVerifier, deviceName, inviteToken? }
                                     → { ownerHandle, deviceId, token }  (stores kdf + Ed25519 public key)
GET    /v1/account/salt?email=…      → { kdf, wrappedRoot }  (needed to re-derive on a new machine;
                                     an unknown email gets an indistinguishable decoy, see §3.6)
POST   /v1/auth/challenge            Body: { email } → { challengeId, nonce }  (one-time, short-lived)
POST   /v1/devices                   Attach device. Body: { email, challengeId, signature,
                                     authVerifier, deviceName }.
                                     Server verifies the Ed25519 signature over the nonce — no secret sent. → { deviceId, token }
DELETE /v1/devices/:id               Revoke a device.
DELETE /v1/account                   Erase the account and everything under it. Body: { authVerifier }
                                     — the passphrase proof, so a device token alone cannot destroy an
                                     account. 400 if it is absent, 403 if it does not match or the
                                     account is suspended.
                                     → { ownerHandle, resources, snapshots, devices, packs, objects,
                                         grants, bytes?, fileErrors? }  (a receipt; every token dies)
                                     bytes is the total `usage` reports, so it matches what the caller
                                     confirmed against, and is absent rather than approximated if the
                                     server could not read one. fileErrors counts stored files it could
                                     not unlink: the account is gone, but that ciphertext is not.

POST   /v1/resources                 Create (server-assigned id). Same body/echo as PUT below.
PUT    /v1/resources                 Replace in place (id set, owner-checked, version++). Also still
                                     accepts a create (id omitted) so an older client keeps working.
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
                                     Used by `share`/`unshare`; rotation just replaces the blob. Echoes the
                                     accepted policy; a private flip clears it.
DELETE /v1/resources/:id
GET    /v1/resources                 List owner's resources (ids + encrypted meta + visibility). Paginated
                                     (?limit=, ?cursor=) → { resources, nextCursor? }; see pagination note below.
PUT    /v1/resources/:id/metadata    Replace only the sealed metadata (a rename), leaving the blob
                                     and objects untouched. Owner only, `expectedVersion`-checked.
POST   /v1/public/resources/:id/objects  Unauthenticated. Body: { ids } → positional length-prefixed
                                     object slices. Serves exact objects of a PUBLIC resource, each id
                                     of which must be referenced by that resource (the share-link read
                                     path for a public/gated streamed file). ≤10,000 ids per call.
GET    /v1/public/resources/:id/preflight  Unauthenticated, uncounted. → { id, encryptedMeta, minClient,
                                     expiresAt?, maxReads?, reads? }. Lets the browser share page decide
                                     whether a counted fetch is supported and worth spending, without
                                     serving ciphertext or key material. 410 like any dead link.

# Account maintenance (owner token). None of these re-encrypt a resource:
PUT    /v1/account/passphrase        Re-wrap the root key under a new passphrase. Bumps the auth epoch
                                     (every other device's token dies) and rotates the stored verifier.
PUT    /v1/account/root-key          Compromise recovery: swap in a fresh root key with every re-wrapped
                                     key and migrated identity, atomically, keeping only this device.
GET    /v1/account/usage             → { storageBytes, quotaBytes?, packs, objects, resources, snapshots,
                                     devices, max*? }  What `aqt usage` reports, including the caps that
                                     actually apply to this account.

# Snapshots (owner token): immutable, GC-pinned copies of a resource version. The
# ciphertext is reused, not re-uploaded, and min_client is copied from the source at
# capture time so a restore is gated exactly like a resource read:
POST   /v1/snapshots                 Body: { resourceId, encryptedLabel?, anchor?, automatic? } → SnapshotInfo
GET    /v1/snapshots                 List (?resourceId=, ?limit=, ?cursor=) → { snapshots, nextCursor? }
GET    /v1/snapshots/:id             → { snapshot, blob, minClient? }; 426 like a resource read.
POST   /v1/snapshots/:id/anchor      Body: { anchored }. An anchored snapshot is exempt from every
                                     retention path; deleting one is 409 `snapshot_anchored`.
DELETE /v1/snapshots/:id
POST   /v1/resources/:id/auto-snapshot   Body: { enabled }. Per-resource opt-out from the server's
                                     scheduled snapshot job.

# Account-to-account grants (read-only). A grant is the resource's content key
# HPKE-wrapped (RFC 9180, X25519+ChaCha20-Poly1305) client-side to the grantee's
# published enc key, bound via HPKE info to (resource id, owner handle, grantee
# handle); the server stores and serves it opaquely. GET /v1/resources/:id honors
# a grant like ownership on the READ path only (returns the grant wrap + owner
# handle instead of the owner's wrapped key); every mutation stays owner-scoped:
GET    /v1/account/keys?email=...    Grant-target lookup: { handle, publicKey, encPublicKey, encKeySig }.
                                     Unknown emails (or accounts predating enc keys) get a deterministic,
                                     correctly self-signed decoy — no existence oracle.
PUT    /v1/account/enc-key           Backfill the caller's X25519 enc key; the Ed25519 self-signature is
                                     verified against the account identity key before storing.
POST   /v1/resources/:id/grants      Owner only. Body: { granteeHandle, wrappedKey }. Upsert (rotation
                                     re-wraps by re-posting). No grantee-existence check (decoy handles
                                     must be accepted indistinguishably).
GET    /v1/resources/:id/grants      Owner only: [{ granteeHandle, createdAt }]. Paginated (see below).
DELETE /v1/resources/:id/grants/:grantee  Revoke one grant. The client then rotates the content key
                                     (private resources) and re-wraps surviving grantees.
GET    /v1/shares                    Grantee-scoped incoming grants (id, ownerHandle, wrap, sealed meta). Paginated.
POST   /v1/resources/:id/objects     Authed. Same body/framing/caps as the public variant, gated on
                                     ownership OR a grant instead of visibility — a grantee reads exact
                                     membership-checked slices, never raw pack ranges (packs interleave
                                     the owner's other resources).

# Tracked folders: the folder's blob is a sealed ManifestRoot pointing at the
# manifest objects, so it uses the resource routes above; PUT additionally carries
# chunkRefs (file-object ids ∪ manifest-object ids the new root references) so the
# server can root GC. Objects ship inside raw packs; all routes require the owner token:
POST   /v1/chunks/check              Body: { ids } → { missing }   (have/want before packing). ≤10,000 ids/call.
POST   /v1/chunks/locate             Body: { ids } → { locations: [{ id, packId, off, len }] }. ≤10,000 ids/call.
PUT    /v1/packs/:id                  Body: raw pack bytes (octet-stream). id = sha256(pack);
                                     server verifies the address and every object slice. Range-able GET.
                                     → { storedObjects }
GET    /v1/packs/:id                  → raw pack bytes; supports Range (pull fetches only the needed span)
POST   /v1/gc                        Pack-level mark-and-sweep → { deletedPacks, freedBytes }
```

**Pagination.** Every list endpoint (`/v1/resources`, `/v1/shares`, `/v1/snapshots`,
`/v1/devices`, `/v1/resources/:id/grants`) pages rather than buffering the whole set:
`?limit=` (default 100, clamped to 1000) and an opaque `?cursor=`; the response keeps
its items array and adds `nextCursor` (empty on the last page). Cursors are keyset
seeks over each list's ordering key, so paging is stable under concurrent inserts. A
non-positive `limit` is `400 invalid_limit`; a corrupt `cursor` is `400 invalid_cursor`.
The Go client follows `nextCursor` transparently, so its list methods still return the
whole slice to CLI callers.

**Error codes.** Every distinct error condition carries a stable snake_case `code` in
the `{ error, code }` body — `upgrade_required`, `version_conflict`, `quota_exceeded`,
`device_limit`, `bad_pack`, `gone`, `snapshot_anchored`, `not_found`, `too_many_ids`,
`grant_limit`, `invalid_policy`, `invalid_cursor`, `invalid_limit`, `drops_roots` — so
a client branches on the code instead of matching prose, and the server never echoes a
raw Go error whose text might carry internal detail. `426` additionally carries `minClient`.

**Rate limiting.** A `429` carries a `Retry-After` header (whole seconds), computed
from the tripped limiter's own refill rate, so a client backs off exactly long enough.

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
AQT_QUOTA_BYTES      0                             # per-owner physical storage cap; 0 = unlimited
AQT_MAX_RESOURCES    0                             # per-account live resource rows; 0 = unlimited
AQT_MAX_SNAPSHOTS    0                             # per-account retained snapshot rows; 0 = unlimited
AQT_MAX_OBJECTS      0                             # per-account packed object rows; 0 = unlimited
AQT_MAX_DEVICES      0                             # per-account device cap; 0 = unlimited
AQT_AUTH_RATE        0                             # authed requests/sec per token; 0 = default (50)
AQT_AUTH_BURST       0                             # authed burst per token; 0 = default (500)
AQT_TRUSTED_PROXIES  (unset = loopback)            # X-Forwarded-* trust; "none" trusts none
```

Those are the abuse controls the protocol assumes. The full operator surface — TLS,
metrics, snapshot and GC timers, shutdown grace, per-account quota overrides — lives
in **docs/deploy.md**, which is authoritative for defaults; this list is not repeated
there and does not try to mirror it.

A client whose server runs in invite mode passes the token via `aqt signup --invite`
(or `AQT_INVITE_TOKEN`). `aqt login` attaches a device to an account that already
exists and needs no invite.

Note that open registration (the default) is enumerable by design: signing up for an
unused address must succeed, so "the signup worked" always reveals that the address
was free. A duplicate signup that cannot prove ownership gets a success-shaped decoy
response rather than a confirmation, so a prober cannot confirm a *specific* address
without also taking it — but only `AQT_REGISTRATION=invite` actually closes
enumeration.

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

## 5. Resolved behavior and open limitations

The questions the interface deliberately left open, and what became of each.
*resolved* means it ships and the behavior described is exercised by `go test ./...`,
with the remaining caveats stated inline. What is still genuinely open is collected
under [Still open](#still-open) at the end, rather than buried inside a resolution.

- **Large single files / streaming** — *resolved:* a private single file at or above ~8 MiB now streams: `push` chunks it (FastCDC), convergent-seals and packs it in a bounded-memory pass, and stores a tiny sealed `FileRoot` (the resource blob) naming the objects; `pull`/`cat` range-fetch the packs and materialize straight to disk. Memory is O(one pack), and the inline body cap no longer bounds private file size. Smaller files keep the one-shot inline path. Public and gated single files now stream the same way — a link holder reads their objects through the per-resource public object endpoint (`POST /v1/public/resources/:id/objects`), and `share`/`unshare` re-wrap only the root, so the content bytes are never re-sealed. Stdin still seals in memory under the body cap.
- **Manifest size / subtree dedup** — *resolved:* a chunked folder is now a Merkle DAG of directory nodes. Each directory node lists its name-sorted children and is sealed through the convergent pipeline under a distinct `aqt-treenode-v1` AAD, so a node's content address is its subtree Merkle hash and a moved/copied/renamed directory dedups for free (its node and file chunks are already on the server). The resource blob is a tiny sealed `TreeRoot` under `AADTreeRoot`. Directories are first-class: empty directories round-trip and directory modes propagate. The format is a clean break (`tree` metadata flag, v2); older folders are not read. The reconcile's remote read is lazy: because directory nodes are content-addressed, the last-synced base tree is sealed in memory and any node the remote shares with it is served from those bytes, so an unchanged subtree is reconstructed without a fetch and only the nodes on a spine that changed since the base hit the network — a no-op sync does zero node round-trips. The level-batched fetch shares one pack source (object locations, spans, and the byte-bounded LRU) across the whole walk, so a pack carrying nodes from several levels is range-fetched once, and a node landing inside an already-fetched span is served from memory. Directory-mode conflicts surface like file conflicts (a plain sync aborts; `--force` takes local; `--conflicts=copy` keeps the local file and preserves the remote one as a `<name>.conflict-<host>-<timestamp>` copy, but a directory-mode conflict has no copy and always resolves local-wins). Rename detection is reporting-only: a move dedups its bytes and still executes as delete+add, but `status`, `sync --dry-run`, and `snapshot diff` coalesce an unambiguous delete+add pair (same content address, one path per side) into `renamed old -> new`, with whole-directory moves collapsing to one entry via the stable subtree hash.
- **Persistent metadata cache** — *resolved:* every remote tree walk (clone, cold reconcile, `find`, snapshot diff) shares an on-disk, content-addressed cache of directory-node and chunk-list ciphertexts (default `~/.cache/aqt/nodes`, `AQT_NODE_CACHE_DIR` overrides, `AQT_NO_NODE_CACHE=1` disables). An object's id is the sha256 of its ciphertext, so entries are immutable (no invalidation, ever) and self-verifying (a corrupt file fails its hash check and is dropped); `OpenNode` re-verifies on open either way, so a disk hit is exactly as trustworthy as a server fetch. Only ciphertext is stored — the same bytes the server keeps — and the cache is LRU-pruned to a 256 MiB budget. A repeated `find` or diff over a large account therefore fetches only nodes it has never seen.
- **Subpath addressing** — *resolved:* `aqt://<id>/<path>` addresses one entry inside a chunked folder. `pull`/`cat` walk only the path's spine (one directory node per segment) and fetch just that entry's chunks; pulling a directory materializes its subtree from the subtree's own content-addressed node without touching the rest of the folder; `aqt ls <folder>[/<path>]` lists one directory by fetching the spine plus that node. Pack-and-seal folders refuse with guidance (no per-entry objects exist — the privacy trade-off working as intended).
- **Repack** — *resolved:* `RepackOwner` compacts partially-dead packs (copies live objects into a fresh pack under a bounded byte budget, swapping atomically after a re-check of age and liveness), so dead objects inside still-live packs are now reclaimed.
- **Push throughput / upload overlap** — *resolved:* the push no longer stalls the chunker on each pack's two upload round-trips (`CheckChunks` + `PutPack`). `packUploader` dispatches a full pack to a bounded pool (`uploadConcurrency`), so the CPU keeps sealing the next pack while earlier ones are in flight — hiding both the server ingest time and, over a WAN, the sequential RTTs. The pool bounds in-flight packs (backpressure via `errgroup.SetLimit`), so push memory stays O(a few packs); a snapshot error drains the pool before returning. Server-side, `PutPack` now writes the pack's object-index rows in batched multi-row INSERTs (was one `Exec` per chunk), cutting the dominant SQLite cost of ingesting a pack of many small chunks.
- **Client-side crypto parallelism** — *resolved:* chunk sealing (`SealChunk`: XChaCha20-Poly1305 + two SHA-256s) now fans across GOMAXPROCS workers (`sealStream`), lifting the CPU ceiling for large-file, high-bandwidth pushes. The split stays on the walk goroutine (`SplitStream` reuses its emit buffer, so each piece is copied — via a recycled buffer set — before crossing to a sealer), and a single collector reassembles results in stream order, so the manifest's chunk order and the sink's `Add` sequence are exactly the serial loop's. Backpressure bounds buffered plaintext at O(workers × Max) per file.
- **Public whole-folder sharing** — *resolved:* `aqt share <folder-id>` now works for chunked (tree) folders. No new object space was needed: a folder's `chunkRefs` already root every directory node, chunk-list segment, and file chunk, so the existing per-resource public object endpoint (`POST /v1/public/resources/:id/objects`, membership-checked against the referenced set) serves the whole DAG once the resource is public, and the folder content key travels in the link fragment exactly as for files (`#k.` public, `#p.` gated; expiry/`--max-reads`/`--burn` apply unchanged — only the resource fetch counts as a read, so a clone's many object requests consume one). A link holder runs `aqt clone <link>` (materializes the tree read-only, writes no tracking state — there is no token to sync with) or `aqt pull <link>/<subpath>` (spine-only walk; both the URL-path form `.../x/<id>/<path>#<frag>` and a subpath appended after the fragment are accepted). Zero-knowledge is unchanged: the server still stores and serves only ciphertext, and there is no unauthenticated write route, so links are pull-only by construction. `aqt unshare <folder-id>` rotates root-only, like a streamed file: the `TreeRoot` and metadata re-seal under a fresh content key while the convergent nodes/chunks stay (their per-object keys derive from the account convergence key, which a link never carried), and the re-PUT carries the full recomputed GC roots. Pack-and-seal folders stay unshareable (no per-entry objects — the privacy trade-off working as intended).
- **Argon2id tuning** (`time`/`memory`) per machine — *resolved:* `crypto.CalibrateKdf` benchmarks the creating machine at signup (and on `passphrase change`) and scales the iteration count to a preset's target unlock time (`interactive` ~0.5s/64 MiB, `moderate` ~1s/256 MiB default, `sensitive` ~2.5s/1 GiB), stepping memory down toward a 64 MiB floor on a machine too slow to fit one pass. Params are public and travel with the account, so every device re-derives the same key; `--kdf-preset` and manual `--kdf-time/--kdf-memory/--kdf-threads` override, and `passphrase calibrate` re-tunes an existing account in place via the cheap wrapped-root re-wrap (no resource is re-encrypted; other devices re-login).
- **Account-enumeration oracle** — *resolved:* unauthenticated auth routes are rate-limited, and `GET /account/salt` returns an indistinguishable decoy `{kdf, wrappedRoot}` for an unknown email instead of a 404. The decoy's Argon2id costs are now drawn per-email (HKDF over the server secret) from the same value set a moderate calibration produces (memory ∈ {64, 128, 256 MiB}, iterations clustered where a ~1 s unlock lands on common hardware) rather than the fixed package default, so a decoy's params no longer stand out. `POST /account` no longer answers `409` on a duplicate email in the default *open* registration mode: it returns the same success shape with a decoy token that grants nothing, so signup stops being an existence oracle (the caller's next authenticated call fails, matching the wrong-passphrase ambiguity). An *invite* mode (`AQT_REGISTRATION=invite` + `AQT_INVITE_TOKENS`) additionally gates every signup on a server-issued token, closing the email-squatting hole for hosted deployments.
- **Authenticated-route abuse / quotas** — *resolved:* the authenticated group is now rate-limited per device token (coarse token-bucket, generous burst so a large sync/clone is unaffected), with a second, far tighter limiter on the expensive `POST /gc` keyed per owner. Per-owner quotas cap physical storage — packs, resource blobs, retained snapshots, and attributable database growth (`AQT_QUOTA_BYTES`, overridable per account with `aqt-server admin accounts quota`) — plus resource, snapshot, object, and device counts (`AQT_MAX_RESOURCES`/`_SNAPSHOTS`/`_OBJECTS`/`_DEVICES`); `0` means unlimited. The byte counter is maintained incrementally inside the pack put / GC / repack transactions (a column on `accounts`, backfilled on migration), so a quota check is one indexed read and never scans the objects table. An over-quota pack put returns `507`, which the client surfaces distinctly.
- **Trusted proxies** — *resolved:* the Gin engine's trusted-proxy list is set explicitly (`AQT_TRUSTED_PROXIES`, default loopback-only, `none` to trust none), so the `X-Forwarded-*` foot-gun is no longer left at Gin's trust-all default. The rate-limit bucket key stays on the TCP peer address regardless, so a spoofed forwarded header cannot mint fresh buckets.
- **Defense-in-depth crypto** — *resolved:* AEAD additional-data domain separation across blob/wrap/gated-wrap has been in since v1; the resource id is now bound into the AAD as well (`SealBound`/`OpenBound`, tag form `aqt-<role>-v2:<id>` over the meta, inline body, and the FileRoot/TreeRoot/PackRoot resource blobs, plus snapshot labels), so a server swapping whole records (blob + meta + wrapped key are mutually consistent under the per-resource key) between ids fails the tag check. The id the check verifies against is the client's own: `GetResource` rejects a response whose echoed id differs from the requested one (and a filtered snapshot listing rejects rows claiming another resource), so the server cannot satisfy the binding by echoing the id of whatever record it chose to serve. Chunk objects, directory nodes, and pack segments stay id-free — they are content-addressed, client-verified against their address, and reachable only through an id-bound root, and binding them would kill cross-resource dedup. Bounded caveats: (1) a create seals before the server assigns the id, so a resource is unbound until its first re-seal (folder syncs upgrade the root — and once, the metadata — on the next update; a one-shot `push` stays unbound); (2) the v1 fallback that keeps old blobs readable means a server can serve a stale unbound blob (it still cannot forge or cross-open one) — full strictness would need client-generated ids and a fallback cut-off; (3) a snapshot browsed without naming a resource has no client-side expectation to pin its claimed resource id to (in-place restore checks the tracked folder's id; `--out` restores trust the claim); (4) once a folder has synced with an id-binding client, its root no longer opens on clients from before this change — upgrade every device together. Capability negotiation (`X-Aqt-Capability` request header + a per-resource `min_client` the server enforces with `426 Upgrade Required`, see §4.3 and `docs/compatibility.md`) gates every declared format boundary: a client below a resource's `min_client`, including a header-less client treated as baseline capability 1, is refused before any ciphertext is served. Key wiping: `ContentKey.Wipe` exists and every acquisition site scrubs on scope exit, including the longest-lived by-value copies in the sync/pack apply contexts; transient by-value copies on intermediate stack frames remain out of reach, the inherent Go caveat `Wipe` documents.
- **Session cache at rest** — *resolved:* the cached master key is sealed under a random per-profile key kept in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service, via pure-Go `zalando/go-keyring`); the on-disk 0600 file holds only ciphertext + `expiresAt` and is useless without the keychain entry. The device token moves into the keychain too. A host with no keychain backend (headless server), or one that sets `AQT_NO_KEYCHAIN=1`, falls back to the machine-bound key/file, so non-interactive operation is unchanged there. Remaining caveat: a process running as the same user can still reach the keychain (or re-derive the machine key); fully closing that needs a passphrase/biometric-gated agent or hardware enclave, still deferred. Exposure stays bounded by `--ttl` and cleared by `logout`.
- **Local base manifest at rest** — *resolved:* `.aqt/base.json` (the last-synced manifest) carries per-chunk decryption keys and inline small-file plaintext, so it is now sealed at rest under the **same** per-profile sealing key as the session cache (keychain, or machine-bound fallback), with a distinct `aqt-base-at-rest-v1` AAD. A backed-up / cloud-synced / stolen-disk copy is therefore useless off-machine, closing the same vectors the session-cache seal does, and it inherits the same residual caveat (a same-user process that reaches the keychain). The seal is read offline by `status` and before `unlockMaster`, so it uses the sealing key, not the master key. Old plaintext bases are read transparently and upgraded to the sealed form on the next sync (disjoint top-level keys make the two forms unambiguous). Retention note: an atomic rename replaces the file so no torn plaintext lingers, but pre-migration plaintext in freed disk blocks is not scrubbed — a forensic-only residue on the local disk.
- **Conflict copies and text merge** — *resolved:* a chunked `sync` defaults to report-and-block (exit 4), and `--conflicts=copy` preserves the remote side beside a local-wins primary. `--conflicts=merge` first materializes base/local/remote text, combines non-overlapping line edits without markers, seals the result before the root CAS, then re-hashes the planned local entry before writing after the CAS; drift preserves the newer edit and reports a conflict. Binary/oversized content, excessive edit distance, overlapping hunks, adjacent unterminated hunks that would invent a line, delete/modify pairs, and a GC'd base chunk use the collision-safe copy path. Both resolving modes are refused with `--force`, baseless reconcile/rollback, one-direction sync, and pack mode. `aqt diff` reuses the materializers, one incremental pack source/LRU per manifest side, and bounded Myers diff for unified local, incoming, and snapshot comparisons; snapshot comparison does not require `base.json`.

Resolved since the first draft: device attach is now an Ed25519 challenge/response
(no secret sent); resources support owner-checked in-place update + versioning; the
passphrase is cached per session so it is entered once, not per command. Content-
defined chunking + dedup is built for folders (FastCDC + keyed convergent
encryption, §4.2a); chunk lifecycle is mark-and-sweep GC scoped per owner.

### Still open

Everything above ships. These four do not, and each is a deliberate limit rather
than an unfinished task — they are the honest answer to "what does aqt still not
protect you from":

- **Chunk size-sequence fingerprint.** Chunked mode leaks the sequence of ciphertext
  chunk lengths, so an attacker holding a candidate file can confirm its presence
  without breaking anything (§4.2a). The mitigation that exists today is choosing
  `pack: true`. Length-bucket padding would blunt it but changes the sealed
  ciphertext length and therefore the content address, breaking dedup identity
  against every existing chunk; deferred rather than folded into the seal path.
- **Same-user process reach.** The session cache and `.aqt/base.json` are sealed
  under a keychain-held per-profile key, which stops an off-machine copy but not a
  process running as the same user on the same machine. Closing it needs a
  passphrase- or biometric-gated agent, or a hardware enclave.
- **Grant to an address that has never been pinned.** `GET /v1/account/keys` returns
  an indistinguishable decoy for an unknown email — that is what removes the
  existence oracle, but it also means a hostile server can answer a first-time
  `share --with` for an unregistered address with a key it controls. The client
  pins on first use, warns on stderr, and offers `aqt contacts verify <email>` for an
  out-of-band fingerprint comparison, so the exposure is trust-on-first-use, not a
  standing hole — but a first grant to a never-seen address is only as trustworthy
  as that verification.
- **Pre-migration plaintext residue.** Upgrading an old plaintext `.aqt/base.json`
  writes the sealed form through an atomic rename; the freed disk blocks holding the
  old plaintext are not scrubbed. Forensic-only, and local to that disk.

Nothing here changes an interface above, which is why they are recorded as limits
rather than blocking work.
