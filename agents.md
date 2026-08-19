# Agent Memory & Project Context

## 1. Project Patterns & Conventions

- Pull requests into `main` are normally squash-merged. For stacked PRs, squash the base PR, then rebase the dependent PR onto the updated `main` and retarget it before merging.
- TUI mutations should re-exec the existing CLI through `tuiRequestExec` and stream into the log; chain `tuiOpenDialog` inputs/confirmations for multi-step actions instead of duplicating command business logic.

## 2. Lessons Learned & Gotchas

- Cobra/pflag renders a string flag's `NoOptDefVal` in generated help. Never use control bytes (especially NUL) as a prompt sentinel without checking the actual `--help` output.
- When a root command is annotated as supporting global `--json` for bare-path dispatch, separately handle the zero-argument path so `aqt --json` does not silently print prose.
- If a PR branch is already checked out in an auxiliary worktree, rebase an isolated temporary branch and update the PR head with an exact `--force-with-lease`; do not disturb the other worktree.

- Account deletion can race file-before-row writes from a live server. Capture resource/snapshot ids inside the delete transaction and revalidate owner/resource existence inside pack/snapshot write transactions so neither side can commit an ownerless artifact.
- Per-account quotas must cover background writers such as scheduled snapshots, not only HTTP mutation handlers. Pending auth challenges are keyed by email and must be included in account erasure.

## 3. User Preferences

- Review all open PRs, merge only when no bugs are found and checks are clean, and rebase when needed to resolve stacked-branch or merge conflicts.

- Do not GPG-sign commits unless explicitly requested.

## 4. Current Context / Scratchpad

- PR #101 was fixed and squash-merged as `d6707cc` on 2026-07-16. Stacked PR #102 was then rebased and retargeted to `main`, fixed, and squash-merged as `01027eb`.
- PR #110 passed full Go tests, vet, and changed-package race tests, then was squash-merged as `c509c1e` on 2026-07-18.
- PR #111 was rebased onto #110, fixed to document account grants on the landing page, passed Go/TypeScript/ESLint and remote checks, then was squash-merged as `13d2698` on 2026-07-18.

- On 2026-08-08, PR #139 was reviewed and updated to head `42d13fd`; PR #133 was rebased onto `main`, fixed, marked ready, and updated to head `1d9949f`. Both were mergeable with Windows, Travis, and status checks green, and neither had review threads.
- On 2026-08-09, PR #140 was fixed at `30706f9` to make the release install snippet create `~/.local/bin` and add it to `PATH`, then squash-merged as `4d4f54e`; its remote and local source branches were deleted. Full Go tests, vet, changed-package race tests, a five-platform/three-binary release simulation, and the refreshed GitHub native matrix passed, and both review threads were resolved. CodeRabbit's separate linker-symbol warning was a false positive: Go accepts the helper build's unused `-X main.version` and `-X main.buildKind` flags, and all 15 cross-builds succeeded.
