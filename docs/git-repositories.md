# Backing up git repositories

aqt ignores `.git` by default. A tracked folder syncs your working files; the
repository's internal directory — locks, loose objects, packfiles — is left out. For
most repositories that is exactly right: the canonical history lives on your git host
(GitHub, GitLab, a bare remote), and aqt covers the working tree.

Some repositories have no remote. A local-only Obsidian vault or notes repo keeps its
entire history in `.git` and nowhere else. To back that up, aqt has to capture `.git`
too — with the caveats below.

## Tracking .git

`aqt init` detects a repository and offers to track its `.git`. Accepting writes a
re-include rule into the starter `.aqtignore`:

```
# aqt ignores .git by default; ! re-includes it
!.git/
```

You can add that line to any `.aqtignore` yourself. A `!.git/` rule at the root of a
tracked folder brings the whole `.git` directory back into the sync.

## The torn-write risk

`.git` is captured as plain files. If git rewrites its index or repacks objects at
the moment a sync reads the tree, the sync can capture a half-written index or
packfile — a `.git` that git would consider corrupt on restore.

aqt narrows that window with a **git-busy guard**:

- The `watch` daemon holds a sync back while any repository under the folder is
  mid-operation — an index or ref lock (`index.lock`, `*.lock`) or a paused
  merge/rebase/cherry-pick.
- Manual `aqt sync` applies the same guard, but only when `.git` is actually tracked.
  If a repository is busy, the sync waits briefly and then defers rather than push a
  half-written repo, exiting with code 75 (the same "deferred, retry later" code as
  `watch --once`). Folders that ignore `.git` (the default) are never affected.

The guard is a mitigation, not a guarantee: a commit that *starts* just after the
check still races the read. Two things keep that from being a data-loss event:

- Content-addressed chunking means a torn `.git` only re-uploads the `.git` objects
  that changed. It never corrupts other files in the folder, and it never affects a
  different sync.
- A slightly-torn `.git` is usually recoverable with `git fsck`/`git gc`, or by
  re-cloning history from a remote if one exists.

## Recommended patterns

- **Repository with a remote (default): don't track `.git`.** Let your git host own
  the history and let aqt sync the working files. Nothing to configure.
- **Local-only repository (the notes-vault shape): track `.git`, keep the guard on.**
  Accept the small torn-write window. Prefer syncing when you are not mid-commit; the
  guard covers active locks. For a guaranteed-consistent snapshot, quiesce git first
  — commit, then sync — or write history into a tracked file with
  `git bundle create history.bundle --all` and let aqt back up the bundle instead of
  the live `.git`.
- **Disabling the guard.** Set it off per folder in `.aqtconfig` only if you
  understand the risk:
  ```json
  { "watch": { "gitGuard": false } }
  ```
  This applies to both `watch` and manual `sync`.

## Restore

A tracked `.git` restores like any other subtree: `aqt clone` (or `aqt sync`)
reproduces its files byte for byte. After restoring a local-only repository, run
`git status` (and `git fsck` if the backup may have caught a repack) to confirm the
working tree and history agree.
