// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
)

// Every list endpoint pages its result rather than buffering the whole set: a
// request without ?limit= gets defaultPageLimit rows, ?limit= is clamped to
// maxPageLimit, and each response carries an opaque nextCursor the caller passes
// back as ?cursor= for the following page (empty on the last page).
const (
	defaultPageLimit = 100
	maxPageLimit     = 1000
)

// cursorSep joins the ordering-key parts inside a cursor. It is the ASCII unit
// separator, chosen because it does not occur in the ids and timestamps a cursor
// carries. It is not assumed absent: grantee handles are deliberately unvalidated
// (so a decoy handle is indistinguishable from a real one) and so can contain
// anything, hence the escaping below.
const cursorSep = "\x1f"

// cursorEsc escapes an occurrence of cursorSep inside a part, so a part carrying the
// separator cannot forge an extra field and be mis-parsed as another endpoint's key
// shape.
const cursorEsc = "\x1e"

// errBadCursor is returned by a store list query when its ?cursor= does not decode
// (wrong shape or corrupt). Handlers map it to a 400 with ErrCodeInvalidCursor.
var errBadCursor = errors.New("invalid pagination cursor")

// pageParams is the parsed pagination request shared by the list handlers and the
// store queries they call. The zero value (limit 0, empty cursor) asks a store for
// the first page at the default limit, which keeps direct callers (tests) simple.
type pageParams struct {
	limit  int
	cursor string
}

// parsePage reads ?limit= and ?cursor=, rejecting a non-positive or non-numeric
// limit; an over-max limit is clamped rather than rejected. The cursor is kept
// opaque here and validated where it is decoded against a specific ordering key.
func parsePage(c *gin.Context) (pageParams, bool) {
	p := pageParams{limit: defaultPageLimit, cursor: c.Query("cursor")}
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			abortCode(c, http.StatusBadRequest, "limit must be a positive integer", api.ErrCodeInvalidLimit)
			return pageParams{}, false
		}
		if n > maxPageLimit {
			n = maxPageLimit
		}
		p.limit = n
	}
	return p, true
}

// effectiveLimit floors a page limit at the default so a direct store caller passing
// the zero value still gets a bounded query.
func (p pageParams) effectiveLimit() int {
	if p.limit <= 0 {
		return defaultPageLimit
	}
	if p.limit > maxPageLimit {
		return maxPageLimit
	}
	return p.limit
}

// encodeCursor builds the opaque cursor for a page's last row from its ordering-key
// parts (the same columns the query's ORDER BY uses).
func encodeCursor(parts ...string) string {
	escaped := make([]string, len(parts))
	for i, p := range parts {
		escaped[i] = strings.NewReplacer(cursorEsc, cursorEsc+cursorEsc, cursorSep, cursorEsc+"s").Replace(p)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(escaped, cursorSep)))
}

// decodeCursor reverses encodeCursor, returning errBadCursor unless it decodes into
// exactly want parts. want pins the cursor to one endpoint's key shape, so a cursor
// minted for another list (or a corrupt one) is rejected rather than mis-parsed.
func decodeCursor(cursor string, want int) ([]string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, errBadCursor
	}
	parts := strings.Split(string(raw), cursorSep)
	if len(parts) != want {
		return nil, errBadCursor
	}
	for i, p := range parts {
		unescaped, err := unescapeCursorPart(p)
		if err != nil {
			return nil, err
		}
		parts[i] = unescaped
	}
	return parts, nil
}

func unescapeCursorPart(p string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != cursorEsc[0] {
			b.WriteByte(p[i])
			continue
		}
		i++
		if i >= len(p) {
			return "", errBadCursor
		}
		switch p[i] {
		case cursorEsc[0]:
			b.WriteByte(cursorEsc[0])
		case 's':
			b.WriteByte(cursorSep[0])
		default:
			return "", errBadCursor
		}
	}
	return b.String(), nil
}
