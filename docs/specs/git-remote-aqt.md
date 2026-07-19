# Spec: git-remote-aqt + merge-on-conflict

Status: approved for implementation · 2026-07-18
Owner: Thomas Breindl · Consumer driving the design: the `~/Brain` vault (two-writer
git repo: macOS laptop + Linux VPS automation)

This is a self-contained implementation spec. DESIGN.md remains the product's
interface spec; a task below folds a condensed section into it once the shape is
final. Read DESIGN.md §3.4, §4.2a, and §4.3 first — this spec reuses the resource
model, pack pipeline, version CAS, and snapshot machinery defined there.

---

## 0. Motivation and constraints

A git-versioned folder cannot be safely two-way synced at the file level between
two committing machines: `.git` internals (refs, packfiles under `gc`) are not
file-mergeable, and the engine has no text merge, so high-churn files degrade
into conflict copies. For a repo where every change is already a commit, git is
the correct merge engine — what is missing is a **remote that stores everything
zero-knowledge encrypted**.

Two features ship under this spec:

- **A. `git-remote-aqt`** — a git remote helper so `git clone aqt::<repo>` /
  `push` / `fetch` work against an aqt server, with the server seeing only sealed
  blobs. Sync between machines becomes plain `git pull --rebase` / `git push`.
- **B. `--conflicts=merge` + `aqt diff`** — three-way text merge for the normal
  (non-git) folder sync path, killing conflict-copy litter for plain-text trees,
  plus a diff view over the same machinery.

Hard constraints:

- Client talks to the server **only through the public HTTPS API on the
  configured domain**. Never assume co-location, shared filesystem, or localhost.
- Zero-knowledge holds: the server must not learn filenames, per-file structure,
  or plaintext. Bundle sizes/count/timing may leak (same class as pack mode).
- Pure Go, no CGO (repo rule). The helper may shell out to the `git` binary —
  it only ever runs when git invoked it, so git is present by definition.
- Single-instance server assumption stays (per-resource mutex, DESIGN.md §5).

Non-goals (file as backlog issues, do not implement here): chunk length-bucket
padding (B2), case-fold collision detection (B3), sharing/grants for git-remote
resources, the git wire protocol / shallow clones, submodule recursion.

---

## A. git-remote-aqt

### A1. UX surface

```
aqt repo create <name>            Create an empty encrypted git remote; prints aqt::<name>
aqt repo ls                       List git-remote resources (id, name, bundles, size, version)
aqt repo info <name-or-id>        Refs, chain length, last push, snapshot state
aqt repo gc <name-or-id>          Force compaction of the bundle chain
aqt repo rm <name-or-id>          Delete (goes through normal resource deletion + GC)

git clone aqt::<name-or-id> [dir]
git remote add origin aqt::<name-or-id>
```

- The helper binary is `git-remote-aqt` (git resolves `aqt::` URLs to it by
  name). Ship it as a tiny shim in the same build that re-execs `aqt
  git-remote-helper <remote> <url>`; `make build` produces both, and `aqt repo
  create` warns if `git-remote-aqt` is not on PATH.
- Server/account resolution: the URL carries no server. The helper resolves the
  logged-in session exactly like every other command (keystore + cached
  session). A detached/headless use must have a valid cached session; the helper
  never prompts when not on a terminal (same rule as the watch daemon).
- Resource type: new `kind: "gitremote"` on the existing resource model —
  inherits ownership, version counter, quota, lifecycle, snapshots. Server gates
  the kind behind `min_client` (426 upgrade-required) so old clients cannot
  half-open one. Grants/shares on this kind are refused server-side for v1.

### A2. Data model

**RefsRoot** — the resource blob is a small sealed JSON document, the analogue of
pack mode's `PackRoot`:

```json
{
  "version": 1,
  "head": "refs/heads/main",
  "refs": { "refs/heads/main": "<sha1-or-sha256>", "refs/tags/v1": "..." },
  "bundles": [ { "id": "<segmentGroupID>", "tips": ["<sha>"], "bases": ["<sha>"] } ],
  "generation": 7
}
```

- `bundles` is the ordered chain. Each entry names the sealed segments of one
  git bundle (uploaded through the existing pack pipeline as **sealed, per-push-
  unique segments** — fresh nonce, no convergent chunking, exactly like pack
  mode; no structure leak). `tips`/`bases` let a client decide applicability
  without downloading.
- `generation` increments on every compaction and exposes the chain epoch for
  status and diagnostics.
- The root is updated with the existing optimistic CAS (`ExpectedVersion`);
  `chunkRefs` on the PUT lists all segment ids the new root references so the
  existing root-GC reaps dropped bundles (age guard protects in-flight pushes,
  unchanged).

**Client-side state** — none beyond Git's object database. Before fetching, the
helper checks each bundle's `tips` with `git cat-file -e` and downloads only
bundles whose requested objects are not already present.

### A3. Helper protocol

Implement the standard remote-helper contract on stdin/stdout:

- `capabilities` → `fetch`, `push`, `option`, `object-format` (support
  `option verbosity`, `option progress`, and `option object-format true`;
  unknown options answered `unsupported`).
- `list` / `list for-push` → decrypt RefsRoot, print `<sha> <refname>` lines and
  `@<head> HEAD` for the symref, plus `:object-format <hash>` when requested.
  Empty repo → empty list (git handles initial push).
- `fetch <sha> <refname>` batch: download every chain bundle whose `tips` are
  not all present locally, decrypt to a temp file, `git bundle unbundle` (or
  `git fetch <bundlefile> <refspecs>`) in chain order.
  Bundles are self-verifying (git checks prerequisites); a bundle whose `bases`
  are missing aborts with a clear "chain broken — run aqt repo gc on a healthy
  clone" error rather than guessing.
- `push [+]<src>:<dst>` batch:
  1. GET RefsRoot (version V). For each refspec, enforce fast-forward with
     `git merge-base --is-ancestor <remote-sha> <local-sha>` unless the refspec
     is forced (`+`); a non-ff without force reports the standard per-ref
     `error <dst> non-fast-forward` and pushes nothing.
  2. Build one bundle for the batch:
     `git bundle create <tmp> ^<each-known-remote-tip> <each-new-tip>` —
     objects only since what the remote has. Ref deletions touch only RefsRoot
     (no bundle content needed).
  3. Seal + upload segments, then PUT RefsRoot′ (refs updated, bundle appended)
     with `ExpectedVersion: V`.
  4. On `version_conflict` (409): re-GET, re-check fast-forward against the new
     tips, rebuild the bundle if still ff (or report non-ff), retry. Bound at 5
     attempts (mirror `maxSyncAttempts`), then fail with "remote busy, pull and
     retry". Segments uploaded by a losing attempt are unreferenced and age-GC'd.
  5. Report `ok <dst>` per ref before optional compaction. Force-push over a
     compaction race (generation changed) re-reads before deciding — never
     blind-writes.

Crash safety follows the folder-sync pattern: segments land before the root
flips, the root PUT is atomic under the per-resource server mutex, and a helper
killed mid-push leaves the remote at version V untouched.

### A4. Compaction

- Trigger: after a successful push, if `len(bundles) >= 64` (default; per-repo
  override `aqt repo create --compact-at N`, stored server-side in resource
  metadata) — or explicitly via `aqt repo gc`.
- Procedure: resolve every remote branch/tag tip from a matching local branch,
  tag, or `refs/remotes/<remote>/...` tracking ref, then create a full bundle
  from exactly those refs. Extra local/WIP refs are ignored. If any remote tip
  is unavailable, auto-compaction skips and warns when the chain reaches twice
  its threshold. Upload, PUT a root with `bundles: [full]`, `generation+1`,
  same refs, CAS as usual.
- **Auto-snapshot before the swap**: create a snapshot of the resource at its
  pre-compaction version (reuses the existing snapshot machinery) so a botched
  compaction is restorable with `aqt repo restore <snapshot-id>`. Retention
  treats these like any auto snapshot; restore first snapshots the current live
  chain so the rollback is itself reversible.
- Full bundles carry a sealed `full` marker. An already-full chain makes manual
  or automatic GC a no-op. A CAS retry against the same resource version reuses
  its uploaded bundle and snapshot instead of producing duplicates.
- Old segments become unreferenced → existing GC.

### A5. Edge cases

- Empty repo: `clone` of a fresh `repo create` yields an empty repo with a
  helpful stderr note. First push initializes `head` from the pushed branch.
- Tags: normal refs — a standalone annotated-tag push always includes the tag
  object even when its peeled commit is already remote.
- Branch/tag deletion: RefsRoot update only; objects linger until compaction.
- SHA-256 repos: bundles and refs are hash-agnostic strings; store
  `objectFormat` in RefsRoot on first push, negotiate it through the helper's
  object-format extension on clone, and refuse a mismatched client repo clearly.
- Large pushes: segments stream through the existing pack upload path (no size
  cliff); a bundle > quota fails with the standard quota error before the root
  flips.

### A6. Tests & acceptance criteria

New e2e file `cmd/aqt/gitremote_e2e_test.go` against the in-process test server
(same harness as the other e2e tests). Must cover:

1. init → create → push → clone in a second dir → histories identical
   (`git rev-parse` all refs match; `git fsck` clean in the clone).
2. Two clones race pushes to the same branch → exactly one wins the CAS, the
   loser reports non-ff after retrying, then succeeds after `pull --rebase`.
   No lost commits (assert both commits reachable in final history).
3. Force-push, branch delete, tag push/delete round-trip.
   Include an annotated tag pushed alone after its commit, followed by a fresh
   clone and `git fsck`.
4. Compaction at threshold: chain collapses to one bundle, `generation` bumps,
   a pre-existing clone still fetches correctly afterward, fresh clone
   downloads exactly one bundle. Pre-compaction snapshot exists.
5. Kill the helper mid-push (segment uploaded, root not flipped) → remote
   unchanged, retry succeeds, orphan segment is GC-eligible.
6. Restore drill: extend `make restore-drill` — from server data dir +
   passphrase alone, `git clone aqt::…` a repo and `git fsck` + ref-diff it
   against the source. This is the release gate.
7. Idempotent refetch: fetch an unchanged remote again → no bundle re-apply
   errors and correct convergence from local object-presence checks alone.
8. A fresh multi-branch clone compacts using remote-tracking refs without
   creating local branches; restoring its pre-compaction snapshot yields a
   cloneable old chain.
9. A SHA-256 push followed by a fresh clone initializes a SHA-256 object database,
   reproduces the ref, and passes `git fsck`.

CHANGELOG entry; `min_client` bump documented; a condensed §3.8/§4.2b lands in
DESIGN.md as the final task of the track.

---

## B. `--conflicts=merge` + `aqt diff` (normal folder sync)

### B1. Merge mode

- New conflict mode `merge` (CLI `--conflicts=merge`, `.aqtconfig`
  `"conflicts": "merge"`). Chunked mode only; pack mode refuses it exactly as it
  refuses `copy` today.
- For each two-sided-change conflict on a **text** file (binary sniff: no NUL in
  the first 8 KiB of any of the three versions, and each version ≤ 8 MiB):
  1. Materialize base content: the base manifest entry's chunks, fetched from
     the local chunk cache or the server. If any base chunk is gone (GC'd),
     fall back to `copy` behavior for that file.
  2. Three-way merge (diff3 semantics) of base/local/remote. Implement a
     self-contained Myers-diff + three-way combine in `internal/syncengine/merge`
     with a bounded edit distance and copy/binary fallback — no new dependency,
     table-driven tests. Line-based, byte-exact lines,
     preserve the file's original EOL style; no rename/copy detection.
  3. Non-overlapping hunks → merged result becomes the local content and is
     pushed as the resolution (counts as a resolved conflict in the summary:
     `~ merged path/to/file.md`). After the root CAS, re-hash the local entry
     captured during planning before writing merged bytes; drift preserves the
     newer local edit, reports a conflict, and leaves the old base for re-plan.
  4. Overlapping hunks → fall back to the folder's fallback mode: `copy`
     semantics for that file (keep local, write `.conflict-<host>-<ts>` copy).
     Never write git-style `<<<<<<<` markers into synced files.
- Non-text or oversized conflicts always fall back to copy. Delete/modify
  conflicts are not merged (no base-vs-one-side merge) — existing behavior.
- Exit code: a run where every conflict merged cleanly exits 0; any fallback
  copy follows copy-mode's exit contract.

### B2. `aqt diff`

```
aqt diff [<path>...] [dir]     Unified diff of local changes vs base (default)
      --remote                 Diff incoming remote changes vs base instead
      --against <snapshot-id>  Reuse snapshot-diff content at line level
```

Reuses the same content-materialization and diff internals as merge. Output is
standard unified diff to stdout (pager-friendly, no color codes when not a TTY).
Binary/oversized files print a one-line `Binary files differ` marker.
The snapshot form scans the working tree directly and does not require
`.aqt/base.json`.

### B3. Tests & acceptance criteria

1. Unit: merge table — non-overlap both sides, adjacent hunks, same-line
   overlap → fallback, one-side-only (not a conflict, sanity), EOL preservation,
   trailing-newline cases.
2. E2e: two devices edit different lines of the same file → next syncs converge
   both edits on both machines, zero conflict copies. Same-line edits → exactly
   one `.conflict-` copy, no data loss.
3. Base-chunk-GC'd fallback path exercised.
4. Extend the multi-device sim (`sim_multidevice_test.go`) with a
   `conflicts=merge` host mode; oracle: convergence + for merged files the final
   content contains every surviving edit (no-data-loss check extended to line
   granularity).
5. Fuzz: feed `sync_fuzz_test.go`-style random edit scripts through merge mode;
   invariant: never panics, output always equals one of {merged, local+copy},
   and every clean output line occurs in base, local, or remote.
6. Block a clean merge's PUT after planning, edit the same file, then release
   the PUT: the newer bytes survive, the sync reports a conflict, and the next
   sync reconciles.

---

## C. Rollout for the ~/Brain vault (consumer runbook — happens after A ships)

Recorded here for context; implemented in the Brain repo, not this one.

1. Server deploys at `https://sync.aquitano.me`; laptop + VPS pin the **same
   aqt version** (id-binding rule) — add an `aqt --version` equality check to
   the vault's `brain doctor`.
2. `aqt repo create brain` → `git remote add origin aqt::brain` on the laptop;
   `git clone aqt::brain ~/Brain` on the VPS. `.env` is transferred manually
   (scp), never committed; `.index/` rebuilds per machine.
3. New `.tools/schedule/sync-vault.sh`, called before/after every scheduled run
   and on a 10-minute timer on both machines: skip if no `origin`; local flock;
   auto-commit `_inbox/` additions as `inbox: capture`; require otherwise-clean
   tree (dirty → notify, abort); `git fetch` + `rebase` (conflict → abort
   rebase, `brain notify` high, exit 1); `git push` with a 3× fetch-rebase-push
   retry. One-line `.gitattributes`: `wiki/log.md merge=union`.
4. Division of labor — VPS headless runs only the capture/brief automations
   (discord poll, Todoist sweep, later email ingest, daily/weekly brief, Sunday
   maintain); scanner + Drive ingest and all interactive/query work stay on the
   Mac or an SSH'd interactive session on the VPS.
5. Backup: retire the 4-hourly pack-mode push once the remote is live (the
   remote supersedes it); second leg = replication of the server's ciphertext
   data dir to a different provider. Re-run the restore drill from that leg.
   Vault CLAUDE.md git rule changes to: "private aqt remote only — never a
   public remote, never force-push."

---

## D. Suggested implementation order

1. **A2 + A1 plumbing** — resource kind, RefsRoot seal/unseal, `aqt repo
   create/ls/info`, server kind-gating. (Foundations; testable without git.)
2. **A3 fetch/list + clone path**, then **A3 push + CAS retry**. (The core.)
3. **A4 compaction + snapshot hook**, `aqt repo gc`.
4. **A6 e2e suite + restore-drill extension.** Release gate.
5. **B1 merge engine + B2 diff command** (independent of A; can parallelize).
6. **B3 sim/fuzz extension.**
7. DESIGN.md condensation, CHANGELOG, docs/git-repositories.md update
   (point git users at `aqt::` remotes instead of `!.git/` re-includes).
