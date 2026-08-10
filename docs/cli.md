# CLI output contracts

## Destructive batches

`aqt rm --json`, `aqt snapshot prune --json`, and `aqt devices rm --json`
return the same stable envelope:

```json
{
  "complete": false,
  "dryRun": false,
  "results": [
    {"id": "first-id", "status": "succeeded"},
    {"id": "second-id", "status": "failed", "error": "reason"},
    {"id": "third-id", "status": "not_attempted", "error": "an earlier operation failed"}
  ]
}
```

`status` is one of `succeeded`, `failed`, or `not_attempted`. Results follow
execution order; device batches move the current device to the end. `complete` is
true only when the requested execution completed, or when a dry run was produced
successfully. `dryRun` is true only for `snapshot prune --dry-run`; all of its
results are `not_attempted` and no delete request is sent.

Resource results may also include `snapshotsDeleted` or `snapshotsRemaining`.
On preflight or execution failure the command exits non-zero after writing the full
report, so scripts can use both the exit status and the per-item results.

## Line diffs

`aqt diff [path...] [dir]` writes standard three-context unified diffs to stdout and
no progress or color escapes, so it can be redirected or piped to a pager. Paths may
name individual files or directory prefixes. The final argument is treated as `dir`
only when it is itself a tracked root.

- Default: working tree versus `.aqt/base.json`.
- `--remote`: current remote tree versus the same base; unsynced local edits do not
  appear.
- `--against <snapshot-id>`: snapshot versus the working tree. The snapshot must
  belong to that tracked resource.

Binary files (a NUL in the first 8 KiB) and files over 8 MiB emit one
`Binary files <old> and <new> differ` line. Last-synced and incoming comparisons
require a chunked folder; pack-and-seal folders can use the snapshot form.

## Encrypted Git remotes

`aqt repo create|ls|info|gc|restore|rm` manages private `gitremote` resources. `create`
prints the Git URL (`aqt::<name>`); `--compact-at` sets the chain threshold. `ls`,
`info`, `gc`, `restore`, and `create` support `--json`; `restore` and `rm` use the
normal confirmation flow.
Git itself invokes `git-remote-aqt`, which is a link to `aqt` created by `aqt git
setup` (`--dir` places it elsewhere, `--json` reports what it did) and uses the active
aqt profile/session. See [`git-repositories.md`](git-repositories.md) for the workflow.
