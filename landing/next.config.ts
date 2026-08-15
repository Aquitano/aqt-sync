// SPDX-License-Identifier: AGPL-3.0-or-later

import type { NextConfig } from "next";

// The marketing site renders no untrusted data, but it is the public face of a
// security product and is served on an origin users are told to trust, so it ships
// the baseline headers itself rather than relying on the host's defaults. A
// host-level config still wins where one exists; this is the floor.
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    // Next inlines its hydration bootstrap, so script-src needs 'unsafe-inline';
    // 'self' is what actually bounds it. The site loads nothing cross-origin, so
    // everything else is pinned to the origin and there are no frame ancestors.
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  reactCompiler: true,
  turbopack: {
    root: process.cwd(),
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
