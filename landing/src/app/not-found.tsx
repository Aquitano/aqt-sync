// SPDX-License-Identifier: AGPL-3.0-or-later

import Link from "next/link";

export default function NotFound() {
  return (
    <main className="grid min-h-[100dvh] place-items-center bg-[var(--paper)] p-6 text-[var(--ink)]">
      <section className="max-w-3xl border border-dashed border-current p-8 md:p-16">
        <p className="font-mono text-xs uppercase tracking-[0.1em]">Nothing decrypted here</p>
        <h1 className="mt-8 text-6xl font-semibold tracking-[-0.08em] md:text-8xl">404.</h1>
        <p className="mt-6 max-w-md text-lg text-[var(--ink-muted)]">
          This route does not exist, or its contents are still private.
        </p>
        <Link className="button button-dark mt-8" href="/">Return home</Link>
      </section>
    </main>
  );
}
