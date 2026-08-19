# Folder sync format

How a tracked folder is chunked, encrypted, stored, and reconciled. The
authoritative interfaces are the Go signatures in `internal/syncengine` and
`internal/crypto`; this document is the format and the reasoning behind it.

The wire routes these use are in [`api.md`](api.md); what the format does and does
not hide from the server is in [`../threat-model.md`](../threat-model.md).

## A folder is a resource

A tracked folder is an ordinary resource whose blob is a tiny sealed root. `init`
creates a private resource; `sync` streams changed files into packs (uploading only
the objects the server lacks) then PUTs an updated root pointer (version++); `clone`
fetches the manifest objects, reassembles the manifest, and streams in the file
objects it references. Ownership, versioning, and the master-key-wrapped content key
are inherited from the resource model unchanged.

The manifest is not the blob. It is chunked through the same pipeline as file content
and stored as objects, and the resource blob is a compact sealed root naming those
objects — so a one-file edit re-uploads a handful of manifest objects rather than the
whole manifest, and the 64 MiB blob ceiling does not cap a folder by its size.

What can cap it is `chunkRefs` — but only when shared. A public or granted
folder's PUT carries its *entire* object-id set in the 32 MiB wire header as its
readers' fetch scope, bounding a shared folder at roughly 500k chunks — about
3.8 GiB at the default ~8 KiB profile, and proportionally more on a coarser one.
Crossing the bound is `400 resource_too_large`; split the folder or pin a coarser
`chunkProfile`. A private folder's PUT omits `chunkRefs` entirely (see
[garbage collection](#garbage-collection)) and has no such ceiling.

Two root types exist: `TreeRoot` for a folder and `FileRoot` for a
[streamed single file](#streamed-single-files). (A third, `PackRoot`, belonged to
the [removed pack-and-seal format](#pack-and-seal-removed).)

## What sync preserves

The full metadata contract, stated exactly. A backup tool that is vague here cannot
be used to judge whether a restore is really a restore.

**Recorded and restored on every device**

- **Path and content.** Paths are POSIX and relative to the tracked root; content
  round-trips byte for byte, verified against its hash on the way out and its content
  address on the way back in.
- **POSIX permission bits.** A file's and a directory's `Mode().Perm()` — the low nine
  bits — ride in the manifest and are applied with `chmod` when the entry lands.
  Directory modes are applied deepest-first once the pass finishes, so a directory
  that ends up read-only does not block writing its own children. An entry carrying no
  recorded mode lands at `0600` for a file and `0700` for a directory.
- **Symlinks, as targets.** A symlink is stored as its literal target string and
  recreated with `symlink`. It is **never** followed, so a link pointing outside the
  tracked root ships as a name and not as the file it names. A symlink's own
  permission bits are neither recorded nor applied — see
  [Reconcile](#reconcile) for why comparing them would manufacture a difference no
  side could resolve.
- **Empty directories**, because a directory is a first-class manifest entry.

On **Windows** a file mode is not nine bits: Go synthesizes one from the read-only
attribute alone, so a Windows scan never records what is on disk — it carries the
last-synced mode forward untouched (see [Portability guards](#reconcile)). An
`0644`-versus-`0755` distinction authored elsewhere therefore *survives* a round
trip through a Windows device; what Windows cannot do is originate one — a
mode-only edit made there is not a change any device sees, and a path created there
records the conventional `0644`/`0755`. Content, paths, and symlink targets are
unaffected.

**Recorded, but local to each device**

- **Modification time.** A file's mtime is recorded on the *local* manifest entry to
  drive the stat fast path: an entry whose size, mode, and mtime all match the last
  sync is taken as unchanged without re-reading it. It never crosses the wire — no
  directory node carries an mtime, and change detection is content-hash based, not
  timestamp based. A pulled file carries the time *this* machine wrote it, and the
  base records exactly that so the next scan does not re-hash a tree it just
  materialized. Two devices holding identical content will show different mtimes, and
  that is not a change.

**Not preserved**

Ownership (uid/gid), extended attributes, POSIX ACLs, file flags such as immutable,
and every timestamp other than the local mtime above — atime, ctime, and birth time
are neither read nor set. Hard links are not detected: each link is scanned and
restored as an independent file, so dedup keeps one copy on the server but the
restore writes two files on disk. Sparse files are read and restored dense. Entries
that are neither regular files, symlinks, nor directories — devices, FIFOs, sockets —
are skipped by the scan entirely and never appear in a restore.

## Merkle DAG of directory nodes

A chunked folder is a Merkle DAG. Each directory node lists its name-sorted children
and is sealed through the convergent pipeline under a distinct `aqt-treenode-v1` AAD,
so a node's content address *is* its subtree Merkle hash: a moved, copied, or renamed
directory dedups for free, because its node and its files' chunks are already on the
server. The resource blob is a sealed `TreeRoot` under `AADTreeRoot`.

Directories are first-class. Empty directories round-trip and directory modes
propagate. The format is a clean break (`tree` metadata flag, v2); older folders are
not read.

**The reconcile's remote read is lazy.** Because directory nodes are
content-addressed, the last-synced base tree is sealed in memory and any node the
remote shares with it is served from those bytes. An unchanged subtree is
reconstructed without a fetch, and only the nodes on a spine that changed since the
base hit the network — a no-op sync does zero node round-trips. The level-batched
fetch shares one pack source (object locations, spans, and a byte-bounded LRU) across
the whole walk, so a pack carrying nodes from several levels is range-fetched once,
and a node landing inside an already-fetched span is served from memory.

**Rename detection is reporting-only.** A move dedups its bytes and still executes as
delete+add, but `status`, `sync --dry-run`, and `snapshot diff` coalesce an
unambiguous delete+add pair (same content address, one path per side) into
`renamed old -> new`, with whole-directory moves collapsing to one entry via the
stable subtree hash.

## Chunking and dedup

Files at or below an inline threshold (the FastCDC minimum) are stored inline in the
manifest, which is itself sealed, so a tree of many tiny files never spawns tiny
on-disk blobs. Larger files are split with **FastCDC** — content-defined, so an edit
re-chunks locally around the change. Each chunk is sealed with **keyed convergent
encryption**:

```text
convergenceKey = HKDF(masterKey, "aqt-convergence-v1")     // account-scoped, never sent
chunkKey       = HKDF(convergenceKey, sha256(plaintext))    // unique per distinct plaintext
ciphertext     = XChaCha20-Poly1305(chunkKey, nonce=0, compress(plaintext))   // deterministic
chunkID        = hex(sha256(ciphertext))                    // server storage address
```

Same account + same bytes → identical `ciphertext` and `chunkID`, so the server
stores one copy and dedup spans all of the account's folders. Different accounts
derive a different `convergenceKey`, so identical plaintext yields different
ciphertext and id — no cross-user equality oracle. The zero nonce is safe because
`chunkKey` never repeats for distinct plaintext. The per-chunk `chunkKey` lives only
in the sealed manifest; the server holds ciphertext addressed by `chunkID` and
nothing else. Hex (not base64url) ids avoid collisions on case-insensitive
filesystems.

Sealing fans across `GOMAXPROCS` workers. The split stays on the walk goroutine and a
single collector reassembles results in stream order, so the manifest's chunk order
is exactly a serial loop's; backpressure bounds buffered plaintext at
O(workers × max chunk size) per file.

### Chunk granularity is a per-folder tradeoff

By default the chunker scales with file size: files up to 8 MiB use the fine profile
(~8 KiB average — min 2K / normal 8K / max 64K, tuned for source trees), files over
8 MiB use the `large` sizes (64K / 256K / 1M, ~256K average), and files over 1 GiB
use `huge` (256K / 1M / 4M, ~1 MiB average). Every chunk costs a manifest entry, a
server-side SHA-256 verify, and an object-index row, so a large binary is not
shredded into hundreds of thousands of records while small files keep byte-level
dedup.

Setting `chunkProfile` to `"large"` or `"huge"` pins that granularity for every file
in the folder, and a `chunk` block sets explicit sizes when no preset fits. Because
boundaries are derived from these sizes, a pinned choice is sticky: changing a
folder's profile re-chunks it once with no dedup against the old profile. It is a
deliberate per-folder decision, and `.aqtconfig` syncs in-tree so every clone agrees.
Note that the profile's `min` is also the inline cutoff, so a coarse profile inlines
larger small files into the (sealed) manifest.

## Storage layout

Sealed-blob resources keep one immutable file per version, prefix-fanned like packs:
`blobs/<ab>/<cd>/<id>.<nonce>.bin`; the superseded file is unlinked once the new
version commits. Objects (chunks) are not one file each:
they are concatenated into **packs** (~16 MiB), one immutable content-addressed file
with a self-describing trailing index, fanned out per owner:
`packs/<owner>/<ab>/<cd>/<packID>.bin`. A pack ships as raw bytes (no base64), and a
pull range-fetches only the span covering the objects it needs.

The server maps `chunkID → (packID, offset, length)` in an `objects` table and
records, per resource, which object ids its current root references (opaque hashes)
so GC has roots. Object ids are `hex(sha256(ciphertext))`, so pack non-determinism
(ordering) does not affect dedup.

A push does not stall the chunker on each pack's two upload round-trips
(`CheckChunks` + `PutPack`): `packUploader` dispatches a full pack to a bounded pool,
so the CPU keeps sealing the next pack while earlier ones are in flight, hiding both
server ingest time and, over a WAN, the sequential RTTs. The pool bounds in-flight
packs, so push memory stays O(a few packs). Server-side, `PutPack` writes the pack's
object-index rows in batched multi-row INSERTs, which is the dominant SQLite cost of
ingesting a pack of many small chunks.

### What actually bounds sync memory

Ciphertext is the bounded part; metadata is not. A push holds a few packs, and a pull
holds one pack plus one batch of object locations — downloads locate and materialize
in runs of ~50k chunks and drop each run's location index once that run's files land,
rather than resolving the whole tree up front.

The manifest itself does not shrink: every chunk carries a record (id, key, length)
in memory for the whole sync, on the order of 150-200 bytes each. At the fine
profile's ~8 KiB average that is roughly 25 MB of chunk records per GB of tracked
content, so a tree in the tens of GB is where a normal machine starts to feel it. A
folder of mostly large files costs far less per byte, since the `large` and `huge`
profiles chunk at ~256 KiB and ~1 MiB — 32x and 128x fewer records for the same
bytes — which is the other reason to pin a coarse `chunkProfile` on a media folder.

### Garbage collection

**Client-decided, at chunk granularity.**
[Reachability is the client's call](api.md#client-managed-garbage-collection): only
it holds the keys, so `aqt prune` decodes every resource and snapshot of the
account (a snapshot's references keep objects alive exactly like a live
resource's), computes the reachable closure, and explicitly deletes what the
server stores beyond it. The server never chooses a victim itself.

Server-side pack maintenance only tidies after a prune: a pack whose objects were
all deleted is swept once it is older than an age guard — the guard is what keeps
an in-flight upload's packs alive until its manifest commits, since `CheckChunks`
re-arms the packs holding objects a push is about to reference — and a pack a
prune left sparse is compacted by `RepackOwner`, which copies the surviving
objects into a fresh pack under a bounded byte budget and swaps atomically after
re-checking age and the object set.

There are no refcounts. The manifests are the source of truth, which survives
crashes; the resource→objects foreign key is the backstop that rejects a shared
resource's refs naming an object the owner no longer stores.

### Node cache

Every remote tree walk — clone, cold reconcile, `find`, `snapshot diff` — shares an
on-disk, content-addressed cache of directory-node and chunk-list ciphertexts
(default `~/.cache/aqt/nodes`; `AQT_NODE_CACHE_DIR` overrides, `AQT_NO_NODE_CACHE=1`
disables). An object's id is the sha256 of its ciphertext, so entries are immutable
(no invalidation, ever) and self-verifying: a corrupt file fails its hash check and is
dropped, and `OpenNode` re-verifies on open either way, so a disk hit is exactly as
trustworthy as a server fetch. Only ciphertext is stored — the same bytes the server
keeps — and the cache is LRU-pruned to a 256 MiB budget. A repeated `find` or diff
over a large account therefore fetches only nodes it has never seen.

## Streamed single files

A regular file at or above ~8 MiB uses the same pipeline instead of sealing whole in
memory — private, public, or gated alike. `push` chunks it with FastCDC,
convergent-seals and packs it in a bounded-memory pass, and stores a tiny sealed
`FileRoot` naming the objects; `pull` and `cat` range-fetch the packs and materialize
straight to disk. Memory is O(one pack), and the inline body cap no longer bounds
file size.

Smaller files keep the one-shot inline path, and stdin — which has no size to
threshold on — always seals inline under the body cap. A public or gated streamed
file's objects are read back through
`POST /v1/public/resources/:id/objects`, so a link holder needs no account.

## Subpath addressing

`aqt://<id>/<path>` addresses one entry inside a chunked folder. `pull` and `cat`
walk only the path's spine — one directory node per segment — and fetch just that
entry's chunks. Pulling a directory materializes its subtree from the subtree's own
content-addressed node without touching the rest of the folder, and
`aqt ls <folder>[/<path>]` lists one directory by fetching the spine plus that node.

Pack-and-seal folders refuse with guidance: no per-entry objects exist, which is the
privacy trade-off working as intended.

## Public folder links

`aqt share <folder-id>` works for chunked (tree) folders and needed no new object
space. A folder's `chunkRefs` already root every directory node, chunk-list segment,
and file chunk, so the per-resource public object endpoint — membership-checked
against that referenced set — serves the whole DAG once the resource is public. The
folder content key travels in the link fragment exactly as for a file (`#k.` public,
`#p.` gated), and `--expire`/`--max-reads`/`--burn` apply unchanged: only the
resource fetch counts as a read, so a clone's many object requests consume one.

A link holder runs `aqt clone <link>`, which materializes the tree read-only and
writes no tracking state (there is no token to sync with), or
`aqt pull <link>/<subpath>` for a spine-only walk. Both the URL-path form
`.../x/<id>/<path>#<frag>` and a subpath appended after the fragment are accepted.

Zero-knowledge is unchanged: the server still stores and serves only ciphertext, and
there is no unauthenticated write route, so links are pull-only by construction.
`aqt unshare <folder-id>` rotates root-only — see
[what revocation guarantees](../threat-model.md#what-revocation-actually-guarantees).
Pack-and-seal folders stay unshareable, for the same reason subpath addressing
refuses them.

## Reconcile

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

**One result shape for a two-sided comparison.** Every command that compares two
named states — `diff --name-status` (against the base, a snapshot, or the current
remote), `snapshot diff`, and the TUI's compare view — returns the same `comparison`:
the two labelled sides, a `complete` flag with a stable `reason` when file-level
comparison was unavailable, and the `Delta` behind the familiar
added/removed/modified buckets. A new side or a new caller extends that type rather
than forking a parallel one, which is why the TUI renders a snapshot diff and a
working-tree-versus-remote comparison through the same code.

The three-way planners (`Plan`, `PlanDirs`) stay separate — they answer "what should
this sync do", not "what differs" — but compare entries through the same
`entryDiffers` rule, so the operational plan and the reported classification cannot
disagree about what counts as a change. A symlink's own permission bits are excluded
from that rule: a scan never records them and apply never sets them, so comparing
them would manufacture a difference no side could resolve.

**Portability guards.** Permission bits are a POSIX attribute. Windows synthesizes
them from the read-only flag (0666/0444 for files, 0777 for directories), so a
Windows scan carries the last-synced mode forward instead of recording the synthetic
one — a folder authored on Linux keeps its `+x` bits through a Windows device — and
a path created on Windows records the conventional 0644/0755. Symlinks need a
privilege Windows leaves off outside Developer Mode: a filesystem that cannot create
them still receives the rest of the folder, skips the links with a named warning,
and keeps their entries in the base so the next sync reads their absence as
inability rather than a deletion to push; a pack push from such a device carries
them into the archive from the base for the same reason. Case-colliding paths
(`Notes.md` and `notes.md`) are refused at push time on every platform — a
case-insensitive clone would collapse them into one file, and its next sync would
then overwrite both remote copies with the survivor's bytes — and a pull or clone
onto a case-insensitive filesystem refuses such a tree by name before writing
anything.

**One prologue.** Every sync enters through `syncSession`: it loads `state.json`
and the last-synced base, refuses a missing base unless `--reconcile`, and acquires
the authenticated client and unlocked master key. Each reconcile attempt then runs
the session's `openRemote`, which fetches the resource, classifies a server
rollback, unwraps the content key, decodes the sealed metadata, and checks the
folder's format. Every one of those is a safety guard.

One detail is load-bearing: a rollback is classified *before* the content key is
unwrapped and the metadata decoded, so a server whose version regressed reports that
rather than a config typo or a keyless resource — a version regression is a
statement about the server's integrity and outranks anything read out of the record
it served. The format check itself routes by the server's truth: a resource in the
removed pack-and-seal format, or the pre-tree legacy format, is refused with
recovery guidance rather than reconciled as an empty chunked manifest.

## Tracked state

`.aqt/state.json` records, next to the resource id and server URL, the owning profile
name, the account's owner handle, and its signing-key fingerprint. State missing the
profile, the owner handle, or the version pin is refused rather than adopted: local
state is regenerable, so re-running `aqt init`/`aqt clone` is the fix. Tracked
commands default to that recorded identity (no `--profile` needed even from a shell
whose default profile differs), and an explicit `--profile` or `--server` that
contradicts it is rejected with guidance rather than talking to the wrong account or
server. A profile that was re-logged into a different account is likewise refused.
If the recorded profile itself starts talking to a different server — a migration, or
a restore under a new URL — the folder follows the profile, because the account key
and not the URL is the identity, and records the move.

The binding is on the account's owner handle, not its signing key, so
`aqt passphrase rotate-root` — which mints a new signing key on every device — does
not strand tracked folders. Deleting the account leaves the folder's plaintext files
alone, but its `state.json` then names an account that no longer exists.

*Missing binding.* State written by a build that predates the binding fields is
refused with instructions to re-run `aqt init`/`aqt clone`; it is never adopted by
whatever account happens to be active. What the folder tracks is regenerable, and a
silent adoption is the one outcome that cannot be undone after the fact.

**Atomic materialization.** Operations that create trees commit all-or-nothing.
`clone`, directory pulls, snapshot export, and side-by-side restore download into a
staging directory beside the destination and rename it into place only on success (an
in-place restore stages and swaps with rollback), so an interrupted transfer, a
permission failure, or a destination collision leaves the destination exactly as it
was. `init` stages the local `.aqt` control state before registering the remote
resource and deletes the just-created resource if the local commit fails, so a failed
init is side-effect-free on both ends.

**Untracking.** `aqt untrack [dir]` removes `.aqt` and leaves both the working tree
and the server-side resource alone (`--delete-remote` opts into deleting the
resource too). It is the way out of a folder whose resource was deleted — by `aqt rm`
here, from another device, or by an operator — which otherwise fails every sync with
"not found on the server" while `aqt init` refuses the directory for still having
`.aqt`.

## `.aqtignore`

A pragmatic gitignore subset: comments, anchored paths, `*`/`?`/`**` globs, and
trailing-slash directory rules. `.aqt/` and `.git/` are always ignored — a tracked
tree syncs working files, never a live git directory — though a later `!`-rule can
re-include.

`aqt init` seeds common build-artifact and cache excludes (`node_modules/`, `.next/`,
`target/`, `__pycache__/`, `dist/`, …) so regenerable outputs stay out of the sync by
default; edit or `!`-re-include any line.

Back up repository history with an [encrypted Git remote](git-remote.md) rather than
by un-ignoring `.git`.

## `.aqtconfig`

Per-folder options, in JSON:

```json
{
  "version": 1,
  "chunkProfile": "default",
  "conflicts": "merge",
  "watch": {
    "interval": "5s",
    "gitGuard": true
  }
}
```

The file is plain JSON (no comments) and is parsed strictly: an unknown key or an
invalid value fails the command with the file path and field rather than being
silently ignored.

- `version` is the schema version (optional; 0/absent and 1 mean the current schema).
  A higher value is refused, so a file written for a newer aqt is never
  half-understood.
- `chunkProfile` is `"default"`, `"large"`, or `"huge"`. The rare tree a named
  profile does not fit can pin explicit byte sizes with
  `"chunk": { "min": …, "normal": …, "max": … }`, which overrides `chunkProfile`.
- `pack` named the [removed pack-and-seal format](#pack-and-seal-removed); a config
  still setting it is refused with recovery guidance.
- `conflicts` is `"block"` (the default), `"copy"`, or `"merge"`; `--conflicts`
  overrides it per run.
- `watch.interval` is the daemon's debounce floor (a Go duration; `--interval`
  overrides it) and `watch.gitGuard` the git-lock guard (default true). The block
  lets a folder pin its daemon behavior in-tree the same way `.aqtignore` pins its
  exclusions.

## Conflict handling

A conflict is a path changed on both sides since the base. The default is
report-and-block: conflicting paths are left untouched and reported, and the sync
exits `4`. `--force` resolves in favor of local.

`--conflicts=copy` keeps the local version at its path and writes the remote one
alongside as `<name>.conflict-<host>-<timestamp>`, then continues (exit 0); the copy
is ordinary content the next sync pushes. A directory-mode conflict has no copy and
always resolves local-wins.

`--conflicts=merge` first attempts a bounded three-way line merge for text files.
It materializes base, local, and remote text, combines non-overlapping line edits
without markers, seals the result before the root CAS, then re-hashes the planned
local entry before writing after the CAS; drift preserves the newer edit and reports
a conflict. Merged paths are reported as `~ merged <path>`. It uses a self-contained
Myers line diff for text up to 8 MiB with no NUL in the first 8 KiB of any of the
three sides, and **never writes conflict markers**.

The copy path is the fallback for everything merge cannot take: binary or oversized
content, excessive edit distance, overlapping hunks, adjacent unterminated hunks that
would invent a line, delete/modify pairs, and a GC'd base chunk.

Both resolving modes are refused with `--force`, with a baseless reconcile or
rollback, and with a one-direction sync.

## Pack-and-seal (removed)

`"pack": true` used to seal the whole tree — tarred, zstd-compressed, and sealed
into fixed-size segments — instead of chunking it per file. It existed primarily to
sync Git internals, which the [encrypted Git remote](git-remote.md) now handles at
the protocol level, and its remaining benefit (hiding file boundaries and directory
structure) did not justify its costs: every change re-shipped the entire folder,
there was no chunk-level dedup, conflicts were whole-folder last-writer-wins, and
the alternate format added branches across sync, clone, sharing, diff, and recovery.
The format has been removed.

A current client refuses a packed resource — and a stale `"pack": true` config —
with recovery guidance: clone the folder with an aqt release that still reads the
format (v0.5.x or earlier), remove the `pack` setting, and push the tree again as a
normal chunked folder. The `packed` metadata flag and the `aqt-pack-v1` /
`aqt-packroot-v1` AAD domains stay reserved so old ciphertext remains identifiable
and those strings are never reassigned.

An interrupted pack pull from an older build leaves `.aqt/pull-in-progress` behind;
`status` and `diff` still recognize the marker so the torn tree is not misread as
local edits.

## Watch daemon

The watcher listens for kernel file events (fsnotify, one watch per non-ignored
directory) and fingerprints the tree — path, size, mtime, mode, no content read — one
debounce interval after a burst settles; a slow safety rescan every 5 minutes catches
anything the events missed. Where the OS cannot watch the tree (over the inotify
budget, say) it falls back to polling each `--interval`, backing off toward 30s while
idle.

A push is **held back while any sub-repo is mid-operation** — either a lock file
(`index.lock`, top-level `*.lock`) or a paused state that carries no lock
(`MERGE_HEAD`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`, `rebase-merge/`,
`rebase-apply/`) — so it never captures a half-written or conflict-marked tree, and
resumes when git finishes. An edit that lands mid-sync is not lost. The git scan is
best-effort (an unreadable subtree is skipped, not treated as idle) and covers nested
repos, submodules, and worktrees.

`-d/--daemon` unlocks the session on the launching terminal first, so the detached
child — which has no tty — never needs to prompt, writes a pid and log under `.aqt/`,
and waits for the child to come up. If the cached session later expires the daemon
stops cleanly rather than looping, because it cannot prompt. `aqt agent
status|stop|logs` manages it and will not signal a recycled PID.
