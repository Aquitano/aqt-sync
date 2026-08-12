# Encrypted Git remote format

The format behind `aqt::` remotes. The user-facing workflow — installing the helper
link, creating a remote, daily Git commands, compaction thresholds — is
[`../git-repositories.md`](../git-repositories.md). This document is what goes on the
wire and why it is safe.

## Resource shape

A Git remote is a **private** resource with sealed metadata kind `gitremote` and
minimum client capability 4. Its id-bound `RefsRoot` contains HEAD, the ref map, the
object format, a generation counter, and an ordered bundle chain.

Bundle bytes are split into per-push-unique XChaCha20-Poly1305 segments with fresh
nonces and uploaded through the existing [pack API](api.md#routes). The server
observes ciphertext segment sizes, count, and timing — never refs, filenames,
commits, or object structure.

Git remotes cannot be public or granted in v1. There is no fragment link form and no
grant wrap for a `gitremote` resource.

## Helper dispatch

Git discovers a remote helper by exec'ing `git-remote-<transport>`, so `aqt` is a
multi-call binary: invoked under the name `git-remote-aqt` — matched exactly, plus
`.exe` — it runs its own hidden `git-remote-helper` subcommand. One binary means the
client and the helper cannot disagree about protocol or crypto.

The helper implements the standard `list`, `fetch`, `push`, and `option`
remote-helper protocol against the active aqt profile and cached unlocked session.
The `aqt::` URL deliberately carries no server and no credential, and the helper
never prompts when Git invokes it non-interactively.

The `object-format` capability and list keyword initialize fresh clones with the
first push's recorded SHA-1 or SHA-256 format; a later mismatch is refused clearly.

## Fetch

Fetch applies only the missing bundles, in chain order, deriving applicability
directly from the tips present locally. There is no helper-side state file to fall
out of sync with the remote.

## Push

Push checks fast-forward policy, creates one incremental bundle for the ref batch,
uploads its segments, then flips `RefsRoot` with `ExpectedVersion`. A `409` re-reads
refs, re-checks ancestry, rebuilds, and retries up to five times; the losing uploads
remain unrooted and age-GC eligible.

Ref deletion changes only the root — no bundle is written. A standalone annotated tag
always includes its tag object.

Segment-before-root ordering, the per-resource mutex, and the version CAS together
mean a killed helper or a concurrent push leaves either the old complete root or the
new complete root, never a torn remote.

## Compaction

At the per-repo threshold (64 by default), a clone containing every remote tip
through a local or matching remote-tracking ref compacts exactly those refs to one
bundle, snapshots the pre-compaction root, and CAS-swaps the new root while
incrementing `generation`. Unrelated local refs are excluded from the full bundle.

`aqt repo gc` requests the same operation explicitly, and `aqt repo restore`
version-CAS restores a saved root after snapshotting the current chain. Full bundles
carry an explicit marker, which makes repeated GC a no-op; a spurious compaction CAS
retry reuses the already-uploaded full bundle and pre-compaction snapshot while the
source resource version is unchanged.

Every root PUT lists all live segment ids, so old chains become ordinary
[mark-and-sweep garbage](folder-sync.md#garbage-collection).

## Not in v1

Shallow clone, submodule recursion, sharing and grants, and the Git wire protocol.
