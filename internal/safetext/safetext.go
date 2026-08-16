// SPDX-License-Identifier: AGPL-3.0-or-later

// Package safetext makes text this client did not author safe to print. Server
// prose, another account's resource names, and anything else that arrives over the
// wire all reach a terminal, a TUI pane, and JSON output; a control byte in any of
// them can erase the line and forge output that looks like aqt's own, and a bidi
// control can make what is left render as a different string than it is.
package safetext

import (
	"strings"
	"unicode"
)

// DisplayMax is the default bound for one field of remote-controlled text. Long
// enough for a real file name or a server's one-line explanation, short enough that
// no single field can push the rest of a row off the screen.
const DisplayMax = 200

// zwnj and zwj join and separate the letters they sit between rather than reordering
// them, and Persian, Hindi, and emoji sequences need them to render at all. They are
// the two format controls Clean keeps.
const (
	zwnj = '\u200c'
	zwj  = '\u200d'
)

// Clean drops the characters that let remote text rewrite the terminal and bounds
// the result at maxLen bytes, plus the appended ellipsis when it truncates (cut on
// a rune boundary). Tabs and spaces survive as spaces so
// wording stays readable; everything else in C0, DEL, and C1 goes, including the
// newline that would otherwise forge a second line of our output. So do the Unicode
// format controls (except zwnj and zwj) and the line and paragraph separators: they
// print as nothing but are not inert, since a bidi override or isolate reorders the
// runes around it and can make a name render as a different string than it is.
func Clean(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == ' ':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// C0 and DEL.
		case r >= 0x80 && r <= 0x9f:
			// C1 controls, reachable as real runes once decoded.
		case r == zwnj || r == zwj:
			b.WriteRune(r)
		case unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			// Bidi controls, the other invisible formats, and the two separators that
			// break a line without being control bytes.
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > maxLen {
		out = strings.TrimSpace(truncateRunes(out, maxLen)) + "…"
	}
	return out
}

// truncateRunes cuts at most maxLen bytes off the front of s without splitting a
// rune, so the bound can never turn valid UTF-8 into a replacement character.
func truncateRunes(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

// utf8Start reports whether b begins a UTF-8 encoded rune (ASCII, or a leading byte).
func utf8Start(b byte) bool { return b&0xc0 != 0x80 }
