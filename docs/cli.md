# CLI output contracts

`aqt --help` is the authoritative list of commands and flags. This document covers
the contracts a script depends on and the behavior `--help` cannot express.

## Invocation

`aqt <command> [args] [flags]`. Bare `aqt <path>` is sugar for `aqt push <path>` when
the argument contains a path separator; a bare word that names an existing file asks
for confirmation first, and errors as an unknown command without a terminal, so a
typo'd subcommand never uploads a file.

`--server <url>` (default `http://localhost:8080`), `--profile <name>`, and
`-h/--help` apply to every command. `-v/--version` is registered on the root command
alone: `aqt --version` prints the build, `aqt ls --version` is an unknown flag — it
is deliberately not global, because promoting it would spend the `-v` short flag for
every subcommand that ever wants it. The three output flags apply only where they
mean something, and a command that does not implement one refuses it rather than
accepting it and behaving identically:

- `--json`: every command whose `--help` documents a JSON shape.
- `-q/--quiet`: `push`, `share`, `init`, `sync`, `snapshot create`, `checkpoint`,
  `restore`, `update`, and `git setup`. It reduces stdout to the single value the
  command produced — the ref, link, snapshot id, or restored directory — or, for
  `sync`, drops the per-file lines and the summary. Errors, and the conflict list a
  blocked sync exits `4` with, still print; so does `sync --dry-run`'s plan, which is
  the output that run was asked for.
- `--progress`: `pull`, `sync`, `clone`, `watch`, `agent start`, and `restore`, and
  only on a terminal. Those are the commands that transfer enough at once to draw a
  bar — `pull` for a subtree (`aqt://<id>/<dir>`), `restore` for the re-sync
  `--in-place` ends with.

Every prompt has a flag that answers it ahead of time, so a scripted run neither
blocks nor silently takes a default it did not choose: `-y/--yes` for a destructive
confirmation, `--git/--no-git` for whether `aqt init` syncs a git repository inside
the folder, and `-P/--password` with a value instead of the bare form that prompts.

Everyday resource arguments accept a unique name, an id, or a tracked path:
`info`, `pull`, `cat`, `clone`, `ls <folder>`, `rm`, `mv`, `share`, and `unshare`
all resolve the name column `aqt ls` prints. Addressing one entry *inside* a folder
still needs the ref form (`aqt://<id>/<path>`, or a share URL), since a name and a
path inside it cannot be told apart in `<folder>/<path>`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | ok |
| `1` | generic failure |
| `3` | auth required, or the session is locked |
| `4` | sync conflict |
| `5` | network, including a stalled transfer and a rate limit that outlasted the client's retry budget |
| `6` | upgrade required — the remote resource is sealed in a format this build cannot read |
| `7` | link gone — the public link expired or reached its read limit |
| `75` | deferred — `watch --once` skipped because git was busy |
| `130` | interrupted — the command was killed by ^C/SIGTERM, which also aborts any in-flight transfer |

`5` and `75` are temporary by construction, so cron retries rather than giving up;
`130` is deliberate, so cron must not.
The `6` message names the command that upgrades *this* install; see
[`compatibility.md`](compatibility.md#recovering-from-a-426).

## Push

Human default: the ref or URL, with `(copied to clipboard)` when applicable, then a
metadata line. `-q` prints only the ref or URL on stdout, so it pipes. `--json`
returns `{ id, ref, url?, name?, bytes, visibility }`.

The lifecycle flags (`--expire`, `--max-reads`, `--burn`) require an explicit
`--public` or `-P`; they never silently mint a link. They are server-enforced, and
the client fails closed against a server that does not echo the accepted policy,
deleting the just-created resource rather than handing out a link that would never
expire. An expired or exhausted link returns exit `7`.

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

## Incoming shares

`aqt shares` lists what other accounts granted this one. `--json` returns
`[{ ref, name?, kind?, from, fromEmail?, fingerprint?, since, stale? }]`.

`name` and `kind` are the *grantor's* plaintext, so both are stripped of control
bytes and bounded before they are printed or returned — a sender cannot emit escape
sequences into the recipient's terminal. `from` is the sender's opaque account handle;
`fromEmail` and `fingerprint` appear only when a local contact pin matches that
handle, and the human output says `unknown sender` when none does. Compare that
fingerprint out-of-band (`aqt contacts verify <email>`) before acting on a share.

Anyone with an account on the server can add a row here, so the recipient can remove
one:

- `aqt shares rm <ref-or-name>` drops the row. The resource is untouched and the
  owner can grant it again. `--block` also refuses that account's future grants and
  drops the shares it has already sent. `--json` returns
  `{ ref, from, removed, blocked }`.
- `aqt shares blocked` lists blocked senders (`[{ handle, email?, blocked }]`), and
  `aqt shares unblock <email-or-handle>` lifts one. An email resolves through the
  local contact pins.

`aqt contacts pin <email> --fingerprint <fp>` pins a contact's keys *before* the
first grant and fails closed unless the server presents that fingerprint. Without
`--fingerprint` it prompts (or takes `-y`) and the pin is only trust-on-first-use.

## Four questions, four commands

Comparison commands are easy to confuse, so each one names what it compares:

| command | left | right | answers |
| --- | --- | --- | --- |
| `aqt status` | last-synced base | working tree, *and* current remote | what changed here, and what is waiting there |
| `aqt sync --dry-run` | base + both sides | — | what a reconcile would do (three-way plan) |
| `aqt diff --against=remote` | current remote | working tree | how these two states differ, right now |
| `aqt snapshot diff <id>` | a snapshot | live resource, or a second snapshot | how a past state differs from another |

`status` is base-relative and reports two independent halves, so a path can appear in
both when each side moved. Neither command replaces the other.

Every `diff` mode is read-only: nothing is uploaded, nothing lands in the working
tree, and neither `.aqt/base.json` nor the recorded remote version is touched, so a
comparison can never change what a later `sync` decides to do.

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
- `--against remote`: the folder's current remote state versus the working tree.
  Neither side is the last-synced base — it is read only to reuse node ciphertexts
  and skip re-hashing unchanged files, and a folder without one still compares — so
  two sides that converged on the same content report no differences even while
  `status` still shows work pending on each. It needs the
  folder key: on a terminal it prompts, and under `--json` or a non-terminal stdin a
  locked session reports `"complete": false` with `"reason": "session-locked"`
  instead of blocking on a prompt nobody would answer.

Binary files (a NUL in the first 8 KiB) and files over 8 MiB emit one
`Binary files <old> and <new> differ` line.

`--name-status` lists classified paths instead of file content — `A` added,
`M` modified, `P` permissions, `T` type, `D` deleted, `R` renamed — and is implied by
`--json`. A remote comparison answers from directory-node metadata alone; a unified
text diff streams both sides' bytes per entry. The working tree is never written.

The same completeness fields appear in the human output as an explicit sentence, so
an incomplete comparison is never mistaken for a clean one.

## Reclaiming space

A current server never decides for itself what is garbage — it cannot see which
chunks a resource references. `aqt prune` makes that decision where the keys are:
it decodes every resource and snapshot of the account, computes the full set of
reachable chunks, and deletes what the server stores beyond it. Deleting a folder
or a large file frees quota at the next prune, not immediately.

`--dry-run` reports the diff without deleting. The command fails closed twice
over: if any resource or snapshot cannot be decoded, nothing is deleted, and the
server refuses to drop chunks whose pack was uploaded or touched within the last
hour — a concurrent push from another device may be about to reference them. Those
show up as skipped; re-run later. `--json` prints the same summary
machine-readably.

## Getting a folder unstuck

`aqt untrack [dir]` removes the folder's `.aqt` control directory after a
confirmation. The working tree is never touched, and the server-side resource is kept
unless `--delete-remote` is passed (`--keep-remote` states the default explicitly).
Use it when the remote resource was deleted — by `aqt rm` here, from another device,
or by an operator — which leaves every sync failing with "not found on the server"
while `aqt init` refuses the directory for still having `.aqt`. It is also the
step before re-tracking a directory against a different resource, account, or server.
`--delete-remote` deletes the resource first, so a failure there leaves the folder
tracked and the command retryable rather than orphaning a resource. A running watch
agent is refused (`aqt agent stop` first), since it would keep syncing a folder whose
control state had just been removed.

## Encrypted Git remotes

`aqt repo create|ls|info|gc|restore|rm` manages private `gitremote` resources. `create`
prints the Git URL (`aqt::<name>`); `--compact-at` sets the chain threshold. `ls`,
`info`, `gc`, `restore`, and `create` support `--json`; `restore` and `rm` use the
normal confirmation flow.
Git itself invokes `git-remote-aqt`, which is a link to `aqt` created by `aqt git
setup` (`--dir` places it elsewhere, `--json` reports what it did) and uses the active
aqt profile/session. See [`git-repositories.md`](git-repositories.md) for the workflow.
