# Agent Memory & Project Context

## 1. Project Patterns & Conventions

- The core product is a pure-Go CLI and server. Keep marketing web code isolated in `landing/`.
- `landing/` uses Next.js App Router, React Server Components by default, Tailwind CSS 4, and small client islands for GSAP and clipboard behavior.
- The landing page uses a sharp duotone system: pale yellow paper, charcoal ink, square geometry, IBM Plex Mono, Space Grotesk, halftone texture, and reduced-motion fallbacks.

## 2. Lessons Learned & Gotchas

- pnpm 11 build approvals live in `pnpm-workspace.yaml` under `allowBuilds`; the `package.json` `pnpm.onlyBuiltDependencies` field is ignored.
- Next.js Turbopack production builds may need permission to bind an internal worker port in the managed sandbox.
- Pin ESLint to 9 and TypeScript to 5.9 until the Next 16 lint stack supports ESLint 10 and TypeScript 7.
- Browser Argon2id must preserve Go's `threads`/lane parameter; libsodium's high-level password API does not expose it, so `/x/:id` uses the pinned `hash-wasm` Argon2 build alongside libsodium XChaCha20-Poly1305.
- The browser decrypt page derives and unwraps a gated key before fetching the resource, so a wrong password does not consume a limited read.
- Encrypted Git remotes use private capability-4 `gitremote` resources: an id-bound sealed `RefsRoot` CAS-points at fresh-nonce bundle segments stored through the existing pack API. Segment upload precedes root PUT; losing/crashed uploads remain unrooted and age-GC eligible.
- Git bundle chains compact when every remote tip is available through a local branch/tag or matching remote-tracking ref; extra WIP refs are ignored. Compaction snapshots the old chain, increments `generation`, marks the full bundle for no-op repeat GC, reuses work on same-version CAS retries, and is reversible with `aqt repo restore <snapshot-id>`.
- Standalone annotated-tag pushes must bundle the tag object even when its peeled commit is already remote; full compaction bundles include only the verified remote refs, and fresh-nonce segments upload without a futile existence check.
- Folder `conflicts=merge` is chunked-only. It materializes base/local/remote text (8 MiB max, NUL sniff), uses the dependency-free Myers/diff3 engine with a bounded edit distance and clean-line provenance check, writes clean merged bytes locally only after the root CAS and a source-entry drift check, and otherwise reuses collision-safe copy fallback without markers.
- `aqt diff` shares the merge materializers and unified renderer for local/base, remote/base, and snapshot/local comparisons; manifest reads share one incremental pack source/LRU per side, `--against` scans without requiring `base.json`, and pack folders require the snapshot form.
- Git object format is stored in `RefsRoot` and negotiated through the remote-helper object-format extension; SHA-1 and SHA-256 pushes and fresh clones are supported, while mismatched fetches still fail clearly.

## 3. User Preferences

- Keep the landing experience in an independent `landing/` subfolder rather than mounting it on the Go server.
- Prefer ambitious, reference-led visual design with strong UX and GSAP motion.
- For this landing page, favor large bitmap display typography, visible print grain, halftone detail, registration marks, and poster-like cream/charcoal plates.
- Avoid perpetual moving marquees or rotating capability bars.

## 4. Current Context / Scratchpad

- The reference-led pixel-art revision is complete and verified with lint, typecheck, peer checks, and a production build.
- Issue 60 browser decryption is complete for inline single files. Crypto assets are vendored and allowlisted under `/x-assets/`; streamed files and folders retain the CLI fallback.
- The git-remote-aqt and merge-on-conflict specification is implemented. Release gates include concurrent pushes, crash-after-upload orphan GC, compaction/cache-loss clones, merge sim/fuzz coverage, and a cold backup restore with Git `fsck` plus ref comparison.
