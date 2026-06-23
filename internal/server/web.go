package server

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

const htmlContentType = "text/html; charset=utf-8"

// shareView serves the human landing page for a public share link (GET /x/:id).
//
// It never decrypts and never sees the content key: the key lives in the URL
// fragment, which browsers do not send to the server. The page only confirms the
// resource is a public aqt resource and shows the `aqt pull` command that runs
// the decryption locally. A private or unknown id 404s, so the page never
// confirms a private resource's existence (matching the JSON API).
func (s *Server) shareView(c *gin.Context) {
	id := c.Param("id")
	vis, err := s.store.ResourceVisibility(id)
	switch {
	case errors.Is(err, ErrNotFound), err == nil && vis != api.Public:
		c.Data(http.StatusNotFound, htmlContentType, notFoundPage)
		return
	case err != nil:
		c.Data(http.StatusInternalServerError, htmlContentType, internalErrorPage)
		return
	}

	var buf bytes.Buffer
	if err := shareTmpl.Execute(&buf, sharePage{ID: id, PullURL: shareURL(c, id)}); err != nil {
		c.Data(http.StatusInternalServerError, htmlContentType, internalErrorPage)
		return
	}
	c.Data(http.StatusOK, htmlContentType, buf.Bytes())
}

type sharePage struct {
	ID      string
	PullURL string // absolute /x/<id> URL, for the no-JS fallback command
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

var shareTmpl = template.Must(template.New("share").Parse(shareHTML))

// The fragment (after '#') is injected client-side from location.href; the
// server never receives it, so the static command shows a #… placeholder that
// the inline script replaces with the exact link the visitor opened.
const shareHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>aqt · encrypted resource</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  main { max-width: 42rem; margin: 0 auto; padding: 4rem 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 1.5rem; letter-spacing: -0.01em; }
  .lead { font-size: 1.05rem; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  pre { background: rgba(127,127,127,0.12); border: 1px solid rgba(127,127,127,0.25);
        border-radius: 8px; padding: 1rem; overflow-x: auto; }
  pre code { font-size: 0.85rem; }
  button { font: inherit; font-size: 0.85rem; padding: 0.4rem 0.9rem; border-radius: 6px;
           border: 1px solid rgba(127,127,127,0.4); background: transparent; cursor: pointer; }
  .hint { color: #888; font-size: 0.9rem; }
  .meta { color: #888; font-size: 0.85rem; margin-top: 2.5rem; }
</style>
</head>
<body>
<main>
  <h1>aqt</h1>
  <p class="lead">This is an <strong>end-to-end encrypted</strong> resource. The server stores
  only ciphertext — it cannot read the file, and neither can this page.</p>
  <p>To decrypt it, use the <code>aqt</code> CLI:</p>
  <pre><code id="cmd">aqt pull '{{.PullURL}}#…'</code></pre>
  <button id="copy" type="button" hidden>Copy command</button>
  <p id="gated" class="hint" hidden>This link is password-protected — <code>aqt pull</code>
  will prompt you for the share password.</p>
  <p id="nojs" class="hint">Run the command with the full link you opened. The part after
  <code>#</code> is the decryption key; it stays in your browser and is never sent to the server.</p>
  <p class="meta">resource <code>{{.ID}}</code> · <code>go install github.com/aquitano/aqt-sync/cmd/aqt@latest</code></p>
</main>
<script>
(function () {
  // The decryption key is in location.hash and never reaches the server. Build
  // the exact "aqt pull" command from the URL the visitor opened, locally.
  var cmd = "aqt pull '" + window.location.href + "'";
  document.getElementById('cmd').textContent = cmd;
  document.getElementById('nojs').hidden = true;
  if (window.location.hash.indexOf('#p.') === 0) {
    document.getElementById('gated').hidden = false;
  }
  var btn = document.getElementById('copy');
  if (navigator.clipboard) {
    btn.hidden = false;
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(cmd).then(function () {
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = 'Copy command'; }, 1500);
      });
    });
  }
}());
</script>
</body>
</html>
`

var notFoundPage = []byte(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="robots" content="noindex"><title>aqt · not found</title>
<style>body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:42rem;margin:0 auto;padding:4rem 1.5rem}</style>
</head>
<body><h1>Not found</h1><p>No public resource lives at this link. It may be private, deleted, or the link may be incomplete.</p></body>
</html>
`)

var internalErrorPage = []byte("internal error")
