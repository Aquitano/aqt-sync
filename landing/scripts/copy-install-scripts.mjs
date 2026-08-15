// SPDX-License-Identifier: AGPL-3.0-or-later

// The install scripts live in the repository's scripts/ directory, which is where
// they are reviewed and tested. The landing site serves them, so copy them into
// public/ at build time rather than keeping a second copy in git that can drift.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const from = join(here, "..", "..", "scripts");
const to = join(here, "..", "public");

mkdirSync(to, { recursive: true });
for (const name of ["install.sh", "install.ps1"]) {
  copyFileSync(join(from, name), join(to, name));
  console.log(`copied ${name} -> public/${name}`);
}
