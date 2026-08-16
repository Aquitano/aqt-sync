# Contributing

aqt is a small project with one maintainer. That shapes what is useful to send: a
focused change with a clear reason lands quickly, a large one that touches several
subsystems at once may sit until there is time to review it properly.

## Build and test

Go 1.25.4 or newer (see `go.mod`), and nothing else.

```sh
go build ./...            # everything compiles
go test ./...             # the full suite
make build                # ./bin/aqt, ./bin/git-remote-aqt, ./bin/aqt-server
```

`make` wraps the rest: `make test-short` skips the slow paths, `make test-race`
runs under the race detector, `make vet` is `go vet ./...`, `make fmt` is
`gofmt -w`, and `make fuzz` gives every fuzz target a ten-second burst.
`make restore-drill` runs a full backup, restore, and byte-diff against real
binaries — worth running for anything that touches the sync or crypto paths.

The landing site is separate: `cd landing && pnpm install && pnpm run build`.

Before you open a pull request, `gofmt -l .` should print nothing and
`go vet ./...` should be silent.

## What a change should look like

- **One thing per pull request.** A bug fix, a feature, or a cleanup — not all three.
  If a fix needs a refactor first, they are two commits, and ideally two PRs.
- **Explain the reason, not the diff.** The commit message and the PR description
  should say what was wrong and why this is the fix. Reviewers can read the diff.
- **Tests that pin the behavior you changed.** A test that would have failed before
  the change and passes after it. Not a smoke test for every branch it touches.
- **Comments where something is genuinely non-obvious**, in full sentences, saying
  why rather than what. If a comment is explaining something confusing, consider
  whether the code should stop being confusing instead. A comment's length is bought
  by consequence, not by completeness:
  - If getting the code wrong breaks an invariant, a race, a crypto binding, or a
    wire contract, write as much as it takes. If it breaks nothing, write one line,
    or none.
  - Exported symbols get the conventional one-sentence doc line. A second sentence
    only for a contract or a caveat the signature cannot show. A trivial unexported
    helper needs no comment at all.
  - Never write "was": no "previously", "used to", or "older build" narration —
    unless the old behavior still arrives as input, because old on-disk state and old
    wire formats are current contracts and those comments stay. Refactor history and
    ticket ids live in git history and PR descriptions.
  - Shared contract text is stated once, at the type or function that owns it; every
    other site points to it or says nothing. The same comment in three places means
    a pointer or a helper is missing.
  - Grouped constants share one banner comment. An individual entry gets its own line
    only when its value alone would mislead.
- **Documentation is part of the change.** `docs/` states contracts the code is
  expected to keep; a change that alters one updates it in the same PR. A claim in
  `docs/` that the code does not deliver is treated as a bug.

## Commit messages

Conventional commits, in the imperative, describing the effect:

```
fix(sync): survive churn, keep pulled mtimes, and bound the download index
feat(account): let an account holder delete their own account
docs: rewrite the README in plain language
```

Common types here are `feat`, `fix`, `docs`, `test`, `perf`, `ci`, and `chore`; the
scope is the subsystem (`sync`, `server`, `landing`, `crypto`, `update`, …) and is
optional when the change is repo-wide. Keep the subject line short enough to read at
a glance and put the reasoning in the body.

## License

aqt is **AGPL-3.0-or-later**, and contributions are accepted under the same terms:
opening a pull request means you are licensing your contribution that way, and that
you have the right to. There is no CLA and no copyright assignment.

Practically, that means anyone running a modified `aqt-server` owes its users the
source — which is why the server implements a source offer (`AQT_SOURCE_URL`) and
why every first-party source file carries a header:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
```

New files need it too, in the comment form their language uses. In Go it is the
first line with a blank line under it (without the blank line it becomes the package
doc comment), and it goes *above* any `//go:build` constraint. The vendored runtimes
under `internal/server/webassets/` are third-party MIT and ISC code and keep their
own licenses — do not stamp those.
