// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"compress/gzip"
	"strings"

	"github.com/gin-gonic/gin"
)

// minGzipSize is the response-body threshold below which compression is skipped:
// under roughly one MTU the gzip framing and CPU rarely pay for themselves, and a
// tiny JSON control reply (an empty missing-chunk list, a version echo) stays raw.
const minGzipSize = 1400

// gzipJSON compresses compressible JSON responses when the client offers gzip.
// Locate/check/list replies are hex-id JSON that runs to megabytes on a clone and
// compresses by an order of magnitude; the already-encrypted pack/blob bodies are
// left untouched (the writer skips any non-JSON Content-Type), so no CPU is spent
// re-compressing ciphertext. Go's http.Transport advertises gzip and decompresses
// transparently, so the client needs no matching code.
func gzipJSON() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !acceptsGzip(c.GetHeader("Accept-Encoding")) {
			c.Next()
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: c.Writer}
		c.Writer = gw
		c.Next()
		gw.finish()
	}
}

// acceptsGzip reports whether the Accept-Encoding header lists gzip. A qvalue of
// zero ("gzip;q=0") is a refusal and is honored.
func acceptsGzip(header string) bool {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(fields[0]), "gzip") {
			for _, p := range fields[1:] {
				if strings.EqualFold(strings.TrimSpace(p), "q=0") {
					return false
				}
			}
			return true
		}
	}
	return false
}

func compressible(contentType string) bool {
	return strings.HasPrefix(contentType, "application/json")
}

// gzipResponseWriter buffers the response until it can decide whether to compress:
// it commits on the first write (from the Content-Type) and, for a compressible
// body, only once the buffer crosses minGzipSize — so a small reply ships raw and a
// large one streams through gzip without ever holding the whole body twice.
type gzipResponseWriter struct {
	gin.ResponseWriter
	buf     []byte
	gz      *gzip.Writer
	decided bool // Content-Type inspected; raw or buffering chosen
	raw     bool // committed to passing bytes through uncompressed
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if w.gz != nil {
		if _, err := w.gz.Write(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	if w.raw {
		return w.ResponseWriter.Write(b)
	}
	if !w.decided {
		w.decided = true
		if !compressible(w.Header().Get("Content-Type")) {
			w.raw = true
			return w.ResponseWriter.Write(b)
		}
	}
	w.buf = append(w.buf, b...)
	if len(w.buf) < minGzipSize {
		return len(b), nil
	}
	return len(b), w.startGzip()
}

func (w *gzipResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *gzipResponseWriter) startGzip() error {
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Add("Vary", "Accept-Encoding")
	w.gz = gzip.NewWriter(w.ResponseWriter)
	_, err := w.gz.Write(w.buf)
	w.buf = nil
	return err
}

// finish flushes whatever the writer buffered: a compressed stream is closed, and
// a sub-threshold body is written raw.
func (w *gzipResponseWriter) finish() {
	if w.gz != nil {
		_ = w.gz.Close()
		return
	}
	if len(w.buf) > 0 {
		_, _ = w.ResponseWriter.Write(w.buf)
		w.buf = nil
	}
}
