// SPDX-License-Identifier: AGPL-3.0-or-later

// The link-preview card needs its faces as files next to the route: Satori takes
// raw bytes, and a bundler-traced relative asset survives outputs where
// node_modules is not deployed next to the server. The files come from the
// installed @fontsource packages the site already loads, so the card cannot
// drift from the site — copy them in at build time rather than committing a
// second copy in git or resolving node_modules on every request.
import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(here, "..", "package.json"));
const to = join(here, "..", "src", "app", "fonts");

const faces = [
  ["@fontsource/pixelify-sans", "pixelify-sans-latin-600-normal.woff"],
  ["@fontsource/ibm-plex-mono", "ibm-plex-mono-latin-400-normal.woff"],
];

mkdirSync(to, { recursive: true });
for (const [pkg, file] of faces) {
  const from = join(dirname(require.resolve(`${pkg}/package.json`)), "files", file);
  copyFileSync(from, join(to, file));
  console.log(`copied ${pkg}/files/${file} -> src/app/fonts/${file}`);
}
