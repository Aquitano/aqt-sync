// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile } from "node:fs/promises";
import path from "node:path";
import { ImageResponse } from "next/og";
import { markPixels } from "./mark";
import { ogDescription, ogTitle } from "./site";

export const alt = ogTitle;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

// The palette is the poster sections' inverted pair from globals.css: ink ground,
// paper ink. A link preview lands in someone else's timeline, so the dark side of
// the site's two is the one that holds its own there.
const ink = "#1d1c19";
const paper = "#ddc998";
const paperPale = "#e7d9b3";

// Satori has no font discovery and no CSS engine: every face has to be handed over
// as bytes, and only flexbox lays anything out — hence the mark being rows of boxes
// rather than the grid globals.css uses. The files land in the source tree at
// build time, copied from the @fontsource packages the site loads
// (scripts/copy-og-fonts.mjs), so the card cannot drift from the site. They load
// through a plain filesystem read: the bundler cannot trace computed asset URLs
// in this route (verified: require.resolve and new-URL fetch variants both fail
// the production build or render), while a source-tree path stays valid wherever
// the project itself is deployed.
async function face(file: "pixelify-sans-latin-600-normal.woff" | "ibm-plex-mono-latin-400-normal.woff") {
  return readFile(path.join(process.cwd(), "src", "app", "fonts", file));
}

function PixelMark({ cell }: { cell: number }) {
  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {[0, 1, 2, 3, 4, 5].map((row) => (
        <div key={row} style={{ display: "flex" }}>
          {markPixels.slice(row * 6, row * 6 + 6).map((pixel, column) => (
            <div
              key={column}
              style={{
                width: cell,
                height: cell,
                background: pixel ? paper : "transparent",
              }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export default async function OpengraphImage() {
  const [pixelify, plexMono] = await Promise.all([
    face("pixelify-sans-latin-600-normal.woff"),
    face("ibm-plex-mono-latin-400-normal.woff"),
  ]);
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: 80,
          background: ink,
          color: paper,
          fontFamily: "IBM Plex Mono",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: 40,
            left: 40,
            right: 40,
            bottom: 40,
            border: `1px dashed ${paper}`,
            opacity: 0.28,
          }}
        />

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            fontSize: 22,
            letterSpacing: "0.28em",
            opacity: 0.65,
          }}
        >
          <div>AQT / SYNC</div>
          <div>LOCAL FIRST</div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 52 }}>
          <PixelMark cell={26} />
          <div
            style={{
              fontFamily: "Pixelify Sans",
              fontSize: 200,
              lineHeight: 0.8,
              letterSpacing: "-0.12em",
            }}
          >
            aqt
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 26 }}>
          <div style={{ display: "flex", height: 1, background: paper, opacity: 0.35 }} />
          <div style={{ fontSize: 34, lineHeight: 1.35, color: paperPale, maxWidth: 900 }}>
            {ogDescription}
          </div>
          <div style={{ fontSize: 20, letterSpacing: "0.28em", opacity: 0.6 }}>
            XCHACHA20 / ARGON2ID / CIPHERTEXT
          </div>
        </div>
      </div>
    ),
    {
      ...size,
      fonts: [
        {
          name: "Pixelify Sans",
          data: pixelify,
          weight: 600,
          style: "normal",
        },
        {
          name: "IBM Plex Mono",
          data: plexMono,
          weight: 400,
          style: "normal",
        },
      ],
    },
  );
}
