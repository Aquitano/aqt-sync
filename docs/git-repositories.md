# Encrypted Git repositories

Use an `aqt::` Git remote when the repository history itself belongs in aqt. The
`git-remote-aqt` helper stores Git bundles as zero-knowledge encrypted resource
segments, so Git—not folder sync—owns commits, refs, rebases, and merge conflicts.
The server sees ciphertext sizes, counts, and timing, but not repository paths, refs,
commits, or object structure.

## Setup

Build the CLI, helper, and server, then put `bin/` on `PATH`:

```sh
make build
export PATH="$PWD/bin:$PATH"
```

Create and attach a private remote from an existing repository:

```sh
aqt repo create notes
git remote add origin aqt::notes
git push -u origin main
```

On another logged-in machine:

```sh
git clone aqt::notes
```

The URL may use the encrypted name or resource id. It deliberately contains no
server or credential; the helper uses the active aqt profile and cached unlocked
session. Headless jobs must log in and retain a valid session first—the helper does
not prompt when Git invokes it without a terminal.

## Daily operation

Normal Git commands work:

```sh
git fetch origin
git pull --rebase origin main
git push origin main
git push origin --delete old-branch
git push origin v1
```

Pushes are optimistic and atomic. The helper rejects non-fast-forward updates unless
the refspec is forced, retries a concurrent root update up to five times, and never
publishes a root before every encrypted bundle segment is durable. A killed or losing
push leaves only unreferenced, age-GC-eligible segments.

Inspect and maintain remotes with:

```sh
aqt repo ls
aqt repo info notes
aqt repo gc notes       # compact an even local clone to one full bundle
aqt repo rm notes
```

The bundle chain compacts automatically at 64 bundles by default. Set another
threshold at creation with `aqt repo create --compact-at N notes`. Compaction first
snapshots the previous root, then swaps one full bundle under version CAS. A manual
`repo gc` must run inside a clone whose refs are even with the remote; otherwise it
leaves the chain unchanged.

SHA-1 and SHA-256 repositories are supported, but one remote cannot mix object
formats. Branches, annotated tags, forced updates, and ref deletion round-trip.
Shallow clone, submodule recursion, grants/sharing, and the Git wire protocol are not
part of the first version.

## Backups and restore

Back up the server ciphertext data directory as described in
[`docs/deploy.md`](deploy.md). `make restore-drill` proves both storage paths: it
restores a tracked folder and an encrypted Git remote on a fresh server, recovers the
account from email plus passphrase, clones the repository, runs `git fsck`, and
compares every branch and tag ref with the source.

## Why not sync `.git/` as folder files?

`.git` contains locks, loose objects, and packfiles that Git rewrites transactionally.
Capturing those files mid-commit or mid-repack can produce a torn repository, and two
machines cannot safely reconcile those internals file by file. Normal folder sync
therefore ignores `.git/`; use `aqt::` for repository history and use `aqt sync` only
for non-Git folders or working-tree data that is intentionally independent of Git.

Legacy folders may still re-include `!.git/` in `.aqtignore`, and the git-busy guard
reduces the torn-write window, but that is a compatibility escape hatch—not the
recommended repository backup design. If restoring such a legacy capture, run
`git status` and `git fsck` before trusting it.
