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
