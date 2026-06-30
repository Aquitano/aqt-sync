# Phase 4 — Merkle-DAG manifests (subtree dedup + faster diffs)

Status: **implemented** in `internal/syncengine` (`tree.go`, `treediff.go`) and wired
into `init`/`sync`/`clone`/`snapshot`/`find`. The runnable prototype this spec was
validated against lives behind the `phase4spike` build tag in `cmd/treespike/`.

Decisions taken during implementation (see §9):
- **Small files: inlined** in their parent node (Q1) — preserves the no-tiny-blobs guarantee.
- **Directories: first-class** (Q4/Q5) — empty directories round-trip and directory modes propagate.
- **Node AAD: separated** (Q6) — directory nodes seal under `aqt-treenode-v1`, distinct from file chunks.
- **Migration: clean break** — a `tree` metadata flag marks v2 folders; older folders are not read (no shim).
- **Renames: path churn accepted** (Q3) — a move dedups its bytes but still surfaces as delete+add at the path level.
- **Lazy `DiffTree`: implemented + tested, not yet wired.** The live reconcile still reassembles the full
  remote tree to build the merged manifest (the data-loss-safe write path needs it), which is the same cost
  as the pre-Phase-4 reconcile — so subtree dedup ships now, and the lazy-diff CPU/I-O win is a follow-up that
  reuses the already-tested `DiffTree`. §2 (giant directories) remains deferred behind a single node per directory.

## 1. Goal

Replace the flat manifest (`syncengine.Manifest{ Version, Entries []Entry }`, one row
per path) with a git-style Merkle DAG of directory nodes. This buys two things the
flat list cannot:

- **Subtree dedup.** Moving / renaming / copying a directory must not re-upload its
  objects, and two identical directory structures must dedup across locations and
  folders. Today a directory move re-lists every entry under the new path; the file
  *chunks* dedup (their ids are stable), but the manifest churns over the whole subtree.
- **Faster diffs.** `plan`/`status` over a huge tree must skip unchanged subtrees
  instead of walking every entry. Today `Plan` builds a `map[path]Entry` for local,
  base, and remote and iterates the full union — O(tree) regardless of how little
  changed.

Both fall out of one mechanism: seal each directory node through the **existing**
convergent pipeline (`crypto.SealChunk`) so a subtree's content address (`chunkID`)
*is* its Merkle hash.

## 2. Today's shape (what we are replacing)

The authoritative types, quoted from the tree:

```go
// internal/syncengine/manifest.go
type Entry struct {
    Path   string         `json:"path"` // POSIX, relative to the tracked root
    Mode   uint32         `json:"mode"`
    Size   int64          `json:"size"`
    MTime  int64          `json:"mtime,omitempty"`
    Hash   string         `json:"hash"`           // sha256 of plaintext (or link target)
    Link   string         `json:"link,omitempty"` // symlink target
    Inline []byte         `json:"inline,omitempty"`
    Chunks []crypto.Chunk `json:"chunks,omitempty"`
}

type Manifest struct {
    Version int     `json:"version"`
    Entries []Entry `json:"entries"`
}

// ManifestRoot is the tiny resource blob; it names the manifest's own CDC objects.
type ManifestRoot struct {
    Version int            `json:"version"`
    Chunks  []crypto.Chunk `json:"chunks"`
}
```

The flat manifest is already chunked and sealed through the same pipeline as file
content (`ChunkManifest` -> `crypto.SealChunk` per CDC piece) and the resource blob is
a sealed `ManifestRoot` naming those objects (`SealManifestRoot`, `OpenManifestFromRoot`).
Phase 4 keeps that "blob is a tiny sealed root naming objects" structure — it only
changes *what* the objects are: instead of CDC slices of one big path-sorted JSON
array, they are convergently-sealed **directory nodes** forming a DAG.

The reconciliation surface we must not disturb:

```go
// internal/syncengine/plan.go
func Plan(local, base, remote Manifest) []Action            // three-way
type Action struct { Path string; Kind ActionKind }
// Upload | Download | DeleteRemote | DeleteLocal | Conflict
func changed(cur Entry, curOK bool, base Entry, baseOK bool) bool // hash or mode differs
```

`applySync` in `cmd/aqt/sync.go` consumes `[]Action` keyed by path. Phase 4 must
produce the **same** `[]Action` so everything downstream (conflict abort, the
snapshot->apply safety re-check, `partitionDeletesByDownload`, base bookkeeping) is
untouched.

## 3. Tree node format

A directory node lists its immediate children, **sorted by name**. Each child carries
its single path segment, mode, type, and a content reference. The reference's shape
depends on the type, mirroring how `Entry` already overloads `Link` / `Inline` / `Chunks`.

```go
// Proposed: internal/syncengine/tree.go

// TreeManifestVersion is the DAG manifest version. Bumped from the flat manifest's 1
// so a clean break is detectable; see §7 (migration).
const TreeManifestVersion = 2

// ChildType discriminates a directory child, the way Entry.IsSymlink()/Entry.Link do
// for the flat entry. Stored as a short string so the serialization is self-describing.
type ChildType string

const (
    ChildFile    ChildType = "file"
    ChildDir     ChildType = "dir"
    ChildSymlink ChildType = "symlink"
)

// TreeChild is one entry inside a directory node: a single path segment (Name, never a
// slash) plus its mode, type, and a content reference. Children are name-sorted so a
// node's serialization — and therefore its content address — is a pure function of the
// subtree it describes.
type TreeChild struct {
    Name string    `json:"name"` // single path segment, no slash
    Type ChildType `json:"type"`
    Mode uint32    `json:"mode"`
    Size int64     `json:"size,omitempty"`

    // Hash drives change detection and equality, exactly like Entry.Hash:
    //   dir     -> the child node's content address (Node.ID) == the subtree Merkle hash
    //   file    -> sha256 of the file's plaintext
    //   symlink -> hash of the link target
    Hash string `json:"hash"`

    Link   string         `json:"link,omitempty"`   // symlink: target
    Inline []byte         `json:"inline,omitempty"`  // file: bytes when Size <= chunker.Min (see §6)
    Chunks []crypto.Chunk `json:"chunks,omitempty"`  // file: content objects when larger
    Node   *crypto.Chunk  `json:"node,omitempty"`    // dir: object record to fetch+open the child node; Node.ID == Hash
}

// TreeNode is a directory: its children, name-sorted. One node seals to exactly one
// convergent object, whose id is the subtree Merkle hash.
type TreeNode struct {
    Version  int         `json:"version"`
    Children []TreeChild `json:"children"`
}
```

A file child reuses `Entry`'s content model verbatim (`Inline` for small files,
`Chunks` for larger ones) and the same `Hash` (plaintext sha256). A symlink reuses
`Link` + its target hash. A directory child carries `Node`, the `crypto.Chunk` record
needed to fetch and decrypt the child node — its `ID` is the subtree hash and is
mirrored into `Hash` so diff and dedup compare one field.

### New root

```go
// Proposed: replaces ManifestRoot for v2 folders.
type TreeRoot struct {
    Version int          `json:"version"` // TreeManifestVersion
    Root    crypto.Chunk `json:"root"`    // the root directory node's object; Root.ID is the whole-tree hash
}
```

Ownership, versioning, and the master-key-wrapped content key are inherited from the
resource model unchanged: the blob is still a tiny sealed root, PUT still carries
`ChunkRefs`, the resource still version-bumps. Only the root's payload changes from
"a list of manifest CDC chunks" to "one pointer at the root dir node".

## 4. Sealing: node id == subtree Merkle hash

Sealing is bottom-up and reuses `crypto.SealChunk` with no changes:

1. **Leaves.** A file is chunked/inlined exactly as today (`ChunkFile` / the inline
   cutoff at `chunker.Min`). Its child entry records `Hash` (plaintext sha256) and
   either `Inline` or `Chunks`.
2. **Directory node.** Build `TreeNode{Version, Children}` with `Children` sorted by
   `Name`. For each subdirectory child, recurse first so its `Node` (and thus `Hash`)
   is known, then `json.Marshal` the node and seal the bytes:

   ```go
   b, _ := json.Marshal(node)            // deterministic: fixed field order, name-sorted children
   ct, ch, _ := crypto.SealChunk(b, conv) // ch.ID = hex(sha256(ct)) = subtree Merkle hash
   ```

   The parent records `ch` as the child's `Node`.
3. **Root.** The top-level node's chunk becomes `TreeRoot.Root`; `SealTreeRoot` seals
   `TreeRoot` under the folder content key (see §7 for the AAD).

Why identical subtrees produce identical sealed object ids — and therefore dedup on
the server with **zero** new server logic:

- `json.Marshal(TreeNode)` is deterministic (Go fixes struct field order; we fix child
  order by sorting on `Name`). Identical subtree contents -> byte-identical node JSON.
- A child node's bytes embed its children's `Hash`es, which recursively embed *their*
  subtrees. So a node's serialization is a pure function of the entire subtree beneath
  it. Two subtrees that are structurally and byte-for-byte identical serialize to the
  same node JSON at every level.
- `crypto.SealChunk` is deterministic for a fixed account: `chunkKey = HKDF(conv,
  sha256(plaintext))`, zero nonce, so the *same account* sealing the *same bytes*
  always yields the same ciphertext and the same `ID = hex(sha256(ciphertext))`
  (`internal/crypto/convergent.go`). Identical node JSON -> identical sealed object id.
- The server already dedups by `chunk_id`: `Store.MissingChunks` returns only the
  ids the owner lacks, and `PutPack` is "an object already stored ... is left where it
  is — dedup keys on chunk_id". A directory node is just another content-addressed
  object; a moved or copied directory references the *same* node id, so the server
  stores one copy. No new tables, no new endpoints, no server change.

So dedup falls out of content addressing for free, at directory granularity, the same
way it already does at file-chunk granularity.

## 5. Diff algorithm (the perf win)

`DiffTree` is a recursive three-way walk over the local, base, and remote DAGs that
produces the **same** `[]syncengine.Action` as `Plan` does over the equivalent flat
manifests — just computed lazily and only over changed subtrees.

```
DiffTree(localNode, baseNode, remoteNode, path) -> []Action:
    # The whole-subtree short-circuit. This is the perf win.
    if local, base, remote dir-hashes are all equal:
        return nil                      # nothing changed anywhere below path; do not fetch, do not recurse
    if local-hash == remote-hash:
        return nil                      # converged on both sides; nothing to transfer

    for name in union(children of local, base, remote):
        l, b, r := child(local,name), child(base,name), child(remote,name)
        if all present-and-dir entries agree they are directories:
            if l.Hash == b.Hash == r.Hash: continue        # subtree unchanged; skip (no fetch)
            childLocal  := fetch+open l.Node if l is a changed dir else local view
            childBase   := fetch+open b.Node  (lazily, only because a hash differed)
            childRemote := fetch+open r.Node  (lazily)
            actions += DiffTree(childLocal, childBase, childRemote, path/name)
        else:
            # leaf (file/symlink), or a type change (dir<->file) at this name:
            actions += leafAction(path/name, l, b, r)      # identical logic to plan.go `changed()`
    return actions
```

Key properties:

- **Equal dir hashes skip the entire subtree.** When two directory nodes have equal
  `Hash`, every path beneath them is identical; the walk returns immediately without
  fetching or recursing. On a huge tree where one file changed, the cost is O(depth ×
  fan-out along the changed spine), not O(tree).
- **Lazy fetch of base/remote nodes.** The local DAG is built in memory from the working
  tree (the scan we already do). Base and remote node objects are fetched *only when a
  hash differs at that level* — an unchanged subtree never round-trips to the server.
  This is the I/O analogue of the CPU short-circuit.
- **Same Action set at the leaf/path level.** `leafAction` applies the exact semantics
  of `plan.go`'s `changed()` (a path changed if its hash *or* mode differs; both-sides
  change with unequal hashes is a `Conflict`, equal hashes is a no-op). The output is
  `[]Action` keyed by full path, so `applySync`, `abortOnConflicts`, the snapshot->apply
  re-check, and base bookkeeping are byte-for-byte unchanged. `PlanReconcile` (no base)
  maps the same way with `baseNode == nil` everywhere.

The flat `Plan` stays in the codebase and stays correct; `DiffTree` is an equivalent
that exploits the DAG. (For the no-DAG paths — e.g. `status` building from a flat base —
the engine can still reconstruct a flat manifest by walking the DAG once.)

## 6. Small-file handling

**Proposal: keep inlining small files (`Size <= chunker.Min`, today 2 KiB) inside their
parent directory node**, exactly as the flat manifest inlines them into `Entry.Inline`.
The node is itself sealed, so the bytes stay confidential, and this preserves today's
property that "a tree of many tiny files never spawns tiny on-disk blobs" (DESIGN §4.2a).

Trade-off vs. always chunking small files into their own convergent objects:

| | Inline in parent node (proposed) | Always chunk small files |
| --- | --- | --- |
| Object count | One node object per directory | One object per small file (the explosion the inline path exists to avoid) |
| Dedup of a *directory* of identical tiny files | Yes — the whole node dedups as one object | Yes |
| Dedup of an *individual* tiny file across differently-shaped directories | No — its bytes live in distinct parent nodes | Yes — identical tiny files share one object |
| Cost of editing one tiny file | Re-seal its parent node (already the DAG's locality cost) | Re-seal parent node *and* upload a new small object |
| Server rows | Fewer | Many (one per tiny file) |

The inline approach still dedups the common case — a copied/moved *directory* of tiny
files dedups wholesale as a single node object (§4). What it gives up is dedup of a
single tiny file that appears under two differently-shaped parents, which is rare and
low-value. Always-chunking would restore that at the cost of re-introducing the
per-tiny-file object explosion.

**Recommendation: inline (preserve current behavior).** This is the one knob most worth
the user confirming, because it trades a little small-file dedup for keeping the
no-tiny-blobs guarantee — see Open Questions Q1.

## 7. Migration (clean break + auto-rewrite)

- **Version bump.** `TreeManifestVersion = 2`; the flat manifest/root stay at 1.
- **Distinct AAD for the v2 root.** Seal `TreeRoot` under a new tag (e.g.
  `AADTreeRoot = []byte("aqt-treeroot-v1")`) rather than `AADBlob`. This is mandatory,
  not cosmetic: a v2 `TreeRoot` and a v1 `ManifestRoot` are byte-compatible JSON under
  the same content key, so without domain separation an *old* client would `Open` a v2
  root cleanly, see `Version: 2` with no `Chunks`, read it as an **empty manifest**, and
  delete the entire tree. `packseal.go`'s `SealPackRoot` already documents this exact
  footgun for `AADPackRoot`; we mirror it. With the distinct tag, an old client's `Open`
  fails the AEAD check and it errors out loudly instead. The metadata `Kind` (or a
  `meta.Tree` flag, like `meta.Packed`) routes the new client to the DAG path.
- **Auto-rewrite on next sync.** An updated client syncing a v1 folder reads the old
  flat manifest **once** via the retained `OpenManifestFromRoot`, builds the DAG from
  those entries (the file `Chunks` are carried straight across), uploads the new
  **tree-node** objects (`MissingChunks` returns only the node objects — file chunk ids
  are already on the server), and PUTs the v2 `TreeRoot`. This is a one-shot upgrade
  shim, *not* a steady-state dual-read layer: after the rewrite the folder is pure v2
  and the flat reader is never consulted for it again.
- **No content re-upload.** File chunk ids are stable (content addressing is unchanged),
  so the only new objects are dir nodes — kilobytes per directory. The superseded
  flat-manifest CDC objects become unreferenced once the v2 root roots the DAG instead,
  and a later `GCPacks` sweep reclaims them on the normal supersede path. File chunks
  stay rooted throughout.
- **In-flight old-format folders.** Until a writer on the new client syncs, a folder
  stays v1 and old clients read it normally. The first new-client sync flips it to v2;
  from then on old clients get the loud AAD failure (clean break — "old clients cannot
  read migrated folders").
- **Clone.** Cloning a not-yet-migrated v1 folder uses the same migration shim to read
  it; cloning a v2 folder walks the DAG. The cloned base is recorded as v2.
- **Age-guard.** Unchanged. The migration's node-object packs are age-guarded by
  `packs.created_at` / `gcMinAge` like any push, and `MissingChunks` re-arms the guard
  on packs holding the already-present file chunks (the dedup-hit set), so a concurrent
  GC cannot reap a file chunk the new root is about to reference before the `TreeRoot`
  PUT commits.

## 8. GC implications

The reachable set the resource roots widens from "file chunks ∪ flat-manifest objects"
to "**every object reachable from the root node in a DAG walk**": all file content
chunks ∪ all dir-node objects. The walk happens **client-side**; the server tables and
queries are unchanged in shape — they just hold and scan more `chunk_id`s.

- **Client.** `cmd/aqt/sync.go:uploadManifestObjects` currently returns
  `refs = m.ChunkIDs() ∪ manifest-object-ids`. Phase 4 replaces this with a DAG walk
  that collects every node id and every file-chunk id reachable from the root, and
  `internal/syncengine/manifest.go:ChunkManifest` is replaced by the recursive tree-seal
  of §4. This is the only place the reachable set is computed; getting the walk right is
  the whole GC-correctness story.
- **`Store.GCPacks`** (`internal/server/store.go`, the `pack_id NOT IN ( ... resource_chunks
  UNION ... snapshot_chunks )` query): unchanged. It already treats `resource_chunks` as
  opaque roots; once `ChunkRefs` includes node ids, those node objects are rooted and
  their packs survive. The `resource_chunks` table (migration step 1) and its FK to
  `objects` already back this — a root referencing an object the owner does not store is
  rejected at PUT, so a buggy DAG walk that drops a node id fails loudly rather than
  committing a dangling DAG.
- **`Store.RepackOwner` / `repackCandidates`** (the `EXISTS(... resource_chunks ...) OR
  EXISTS(... snapshot_chunks ...)` liveness test): unchanged. A live node object is
  copied forward exactly like a live file chunk.
- **Snapshots pin DAGs too.** `CreateSnapshot` copies `resource_chunks -> snapshot_chunks`
  wholesale (`INSERT INTO snapshot_chunks ... SELECT ... FROM resource_chunks`). Once
  `resource_chunks` carries the node ids, a snapshot captures the whole DAG automatically
  — no change to `snapshot_chunks` (migration step 4) or its unions in `GCPacks` /
  `repackCandidates`.

Net: GC widening is entirely "the client must list a DAG's worth of object ids in
`ChunkRefs`." The server's mark-and-sweep is already root-driven and opaque, so it needs
no Phase 4 change.

## 9. Open questions

1. **Small-file inlining (recommended: inline).** Keep inlining files `<= chunker.Min`
   into the parent node (preserves the no-tiny-blobs guarantee, dedups directories of
   tiny files wholesale), or always chunk them (better dedup of an individual tiny file
   across differently-shaped directories, at the cost of per-file object explosion)?
   See §6.
2. **Giant single directories / max children per node.** One node = one
   `crypto.SealChunk` object keeps "node id == subtree hash" exactly true, but a
   directory with millions of entries makes one large node object (and one large
   in-memory marshal). Options: cap children per node and spill into synthetic interior
   nodes (B-tree-style), or CDC-chunk the node serialization (which reintroduces a
   "hash of the chunk list" instead of a single id). Recommend deferring with a soft cap;
   needs a decision if very wide directories are expected.
3. **Rename / path-independence.** Content addressing already means a moved directory's
   *bytes* are not re-uploaded (same node id) and a moved file's chunks dedup. But
   `Plan` is path-keyed, so a rename still surfaces as `DeleteRemote(old) + Upload(new)`
   at the leaf level — the manifest churns even though no bytes move. Do we want explicit
   rename detection (a `Rename` action) so the diff records a move without re-listing,
   or is "bytes dedup, paths churn" acceptable?
4. **Empty directories.** The flat manifest tracks only files/symlinks; a DAG can
   naturally carry an empty directory node. Do we start syncing empty directories (a
   behavior change), or keep dropping them for parity?
5. **Directory mode propagation.** `TreeChild` for a dir carries `Mode`. Today directory
   permissions are not synced (only file/symlink entries exist). Do dir permission
   changes now propagate, and should a mode-only dir change count as `changed`?
6. **Tree-node AAD separation from file chunks.** Node objects and file-content chunks
   both seal via `SealChunk` under the same `aadChunk` tag, so a node and a file chunk
   with byte-identical plaintext would collide on one object id (harmless — both decrypt
   to the same bytes — and astronomically unlikely). Do we want a distinct AAD for
   tree-node objects to rule it out, accepting a `SealChunk` variant and that node
   objects no longer dedup against an identical file chunk?
