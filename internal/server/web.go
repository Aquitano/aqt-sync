// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

const htmlContentType = "text/html; charset=utf-8"

// shareCSP locks the share page down: the decryptor may only talk to this
// origin, so the fragment key cannot be exfiltrated by anything the page loads.
// blob: is needed for the Raw/Download object URLs of decrypted files. Script
// comes only from 'self' (the page script is a served asset, never inline):
// blob: documents inherit this CSP, so 'unsafe-inline' would let a hostile
// shared SVG opened via Raw run script in this origin.
// connect-src data: lets libsodium fetch its embedded WASM (a data: URL);
// without it the runtime silently falls back to asm.js. data: fetches carry
// nothing off the page.
const shareCSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; " +
	"connect-src 'self' data:; img-src blob:; media-src blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

//go:embed webassets/*
var webAssets embed.FS

var shareTmpl = template.Must(template.ParseFS(webAssets, "webassets/share.html"))

// The value marks whether the asset's filename pins its content (version-named
// vendor builds), which decides how aggressively it may be cached.
var shareScriptAssets = map[string]struct {
	path      string
	immutable bool
}{
	"libsodium-0.7.10.js":          {"webassets/libsodium-0.7.10.js", true},
	"libsodium-wrappers-0.7.10.js": {"webassets/libsodium-wrappers-0.7.10.js", true},
	"hash-wasm-argon2-4.9.0.js":    {"webassets/hash-wasm-argon2-4.9.0.js", true},
	"fzstd-0.1.1.js":               {"webassets/fzstd-0.1.1.js", true},
	"share.js":                     {"webassets/share.js", false},
}

// shareAsset serves the pinned crypto runtime and the page script used by the
// browser decryptor. Keeping the allowlist here avoids turning the embedded
// directory (which also contains license files and the HTML template) into a
// file server.
func (s *Server) shareAsset(c *gin.Context) {
	asset, ok := shareScriptAssets[c.Param("name")]
	if !ok {
		c.Status(http.StatusNotFound)
		return
	}
	body, err := webAssets.ReadFile(asset.path)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	if asset.immutable {
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		c.Header("Cache-Control", "no-cache")
	}
	c.Header("Cross-Origin-Resource-Policy", "same-origin")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "application/javascript; charset=utf-8", body)
}

// shareView serves the human landing page for a public share link (GET /x/:id).
//
// It never decrypts and never sees the content key: the key lives in the URL
// fragment, which browsers do not send to the server. The page decrypts
// client-side (or shows the `aqt pull` command); the server only confirms the
// resource is a public aqt resource. A private or unknown id 404s, so the page
// never confirms a private resource's existence (matching the JSON API).
func (s *Server) shareView(c *gin.Context) {
	id := c.Param("id")
	vis, gone, err := s.store.ResourceVisibility(id)
	switch {
	case err == nil && vis == api.Public && gone:
		// The link exists but its lifecycle has ended; say so with 410 rather than
		// offering a pull command that would itself 410.
		c.Data(http.StatusGone, htmlContentType, gonePage)
		return
	case errors.Is(err, ErrNotFound), err == nil && vis != api.Public:
		c.Data(http.StatusNotFound, htmlContentType, notFoundPage)
		return
	case err != nil:
		c.Data(http.StatusInternalServerError, htmlContentType, internalErrorPage)
		return
	}

	var buf bytes.Buffer
	page := sharePage{ID: id, PullURL: shareURL(c, id), SourceURL: s.cfg.sourceURL()}
	if err := shareTmpl.Execute(&buf, page); err != nil {
		c.Data(http.StatusInternalServerError, htmlContentType, internalErrorPage)
		return
	}
	c.Header("Content-Security-Policy", shareCSP)
	c.Header("Referrer-Policy", "no-referrer")
	c.Data(http.StatusOK, htmlContentType, buf.Bytes())
}

type sharePage struct {
	ID        string
	PullURL   string // absolute /x/<id> URL, for the no-JS fallback command
	SourceURL string // source link this deployment offers
}

// shareURL rebuilds the absolute link to this resource for the no-JS fallback.
// With JS the page uses the exact location.href instead (it alone carries the
// fragment), so this is only ever a best-effort display value.
func shareURL(c *gin.Context, id string) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + c.Request.Host + "/x/" + id
}

// Small static pages share the visual language of the share page: cream paper,
// dot grid, mono labels, a dashed frame with square corner marks.
const staticPageShell = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>aqt · %s</title>
<style>
  body { margin: 0; min-height: 100dvh; color: #1d1c19; background: #f3dea3
         radial-gradient(circle, rgb(29 28 25 / 9%%) 0 1px, transparent 1.5px); background-size: 9px 9px;
         font: 16px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 42rem; margin: 0 auto; padding: clamp(2rem, 6vw, 4rem) 1.25rem; }
  .sheet { position: relative; padding: clamp(1.5rem, 4vw, 3rem); border: 1px dashed rgb(29 28 25 / 32%%); }
  .sheet i { position: absolute; width: 9px; height: 9px; background: #1d1c19; }
  .sheet i:nth-of-type(1) { top: -5px; left: -5px; } .sheet i:nth-of-type(2) { top: -5px; right: -5px; }
  .sheet i:nth-of-type(3) { bottom: -5px; left: -5px; } .sheet i:nth-of-type(4) { bottom: -5px; right: -5px; }
  .label { margin: 0 0 1.5rem; font-family: ui-monospace, Menlo, Consolas, monospace;
           font-size: 0.65rem; letter-spacing: 0.12em; text-transform: uppercase; opacity: 0.65; }
  h1 { margin: 0 0 0.75rem; font-size: clamp(1.5rem, 4vw, 2rem); letter-spacing: -0.02em; }
  p { max-width: 34rem; color: #615b4d; }
</style>
</head>
<body><main><div class="sheet"><i></i><i></i><i></i><i></i>
<p class="label">aqt · encrypted sync</p>
<h1>%s</h1><p>%s</p>
</div></main></body>
</html>
`

func staticPage(title, heading, body string) []byte {
	return []byte(fmt.Sprintf(staticPageShell, title, heading, body))
}

var (
	notFoundPage = staticPage("not found", "Not found.",
		"No public resource lives at this link. It may be private, deleted, or the link may be incomplete.")
	gonePage = staticPage("link expired", "This link has expired.",
		"It ran out of time or reached its read limit. The encrypted content is no longer available.")
	internalErrorPage = staticPage("server error", "Something went wrong.",
		"The server could not load this link. Try again in a moment.")
)
