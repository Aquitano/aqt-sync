# Encrypted Git repositories

Use an `aqt::` Git remote when the repository history itself belongs in aqt. The
`git-remote-aqt` helper stores Git bundles as zero-knowledge encrypted resource
segments, so Git—not folder sync—owns commits, refs, rebases, and merge conflicts.
The server sees ciphertext sizes, counts, and timing, but not repository paths, refs,
commits, or object structure.

## Setup

Git resolves an `aqt::` remote by executing a program named exactly `git-remote-aqt`
on `PATH`. `aqt` answers to that name itself, so the integration is a link pointing at
the client — one binary, nothing to upgrade separately.

Install `aqt` (see the [README](../README.md#install)), then create the link:

```sh
curl -fsSL https://web.sync.aquitano.me/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
aqt git setup
```

`aqt git setup` creates the link beside the running binary, reports where it put it,
and warns if that directory is not on `PATH` or if another `git-remote-aqt` comes
first. It is safe to re-run. Pass `--dir` to put the link somewhere else on `PATH`.
It refuses to write into a directory a package manager owns, since a package that
ships `aqt` would ship the link with it.

On Windows the archive is a `.zip` carrying `aqt.exe`, and the link is
`git-remote-aqt.exe`. A symlink there needs Developer Mode or an elevated shell, so
setup falls back to a hard link (which needs neither, on one volume) and then to a
copy. Only a symlink resolves by name and so follows `aqt update`; a hard link or a
copy stays bound to the file the update replaced. The update reports a link that has
gone stale, and re-running `aqt git setup` remakes it.

From a source checkout, `make build` produces `bin/aqt`, the same link beside it, and
`bin/aqt-server`:

```sh
make build
export PATH="$PWD/bin:$PATH"
```

Releases up to and including v0.6.0 shipped a standalone `git-remote-aqt` archive.
Later releases do not: there is nothing to download but `aqt`. A copy already on disk
keeps working — it execs the `aqt` beside it, which still answers to the subcommand it
targets — but replace it with `aqt git setup`, and drop the archive from any install
script that fetches it.

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
aqt repo gc notes       # compact from locally available remote refs
aqt repo restore <snapshot-id> -y
aqt repo rm notes
```

The bundle chain compacts automatically at 64 bundles by default. Set another
threshold at creation with `aqt repo create --compact-at N notes`. Compaction first
snapshots the previous root, then swaps one full bundle under version CAS. A manual
`repo gc` must run inside a clone that has fetched every remote branch and tag. Local
branches are not required: matching remote-tracking refs are sufficient, and unrelated
local/WIP refs are excluded from the full bundle. `repo restore` rolls the remote back
to a pre-compaction snapshot after first snapshotting the current chain. Running
`repo gc` on an already-full chain is a no-op.

SHA-1 and SHA-256 repositories are supported. The helper negotiates the remote object
format during clone and retains a mismatch guard for older callers. Branches,
annotated tags, forced updates, and ref deletion round-trip.
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
