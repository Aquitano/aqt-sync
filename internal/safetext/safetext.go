// Package safetext makes text this client did not author safe to print. Server
// prose, another account's resource names, and anything else that arrives over the
// wire all reach a terminal, a TUI pane, and JSON output; a control byte in any of
// them can erase the line and forge output that looks like aqt's own.
package safetext

import "strings"

// DisplayMax is the default bound for one field of remote-controlled text. Long
// enough for a real file name or a server's one-line explanation, short enough that
// no single field can push the rest of a row off the screen.
const DisplayMax = 200

// Clean drops the control bytes that let remote text rewrite the terminal and
// bounds the result at maxLen runes' worth of bytes. Tabs and spaces survive as
// spaces so wording stays readable; everything else in C0, DEL, and C1 goes,
// including the newline that would otherwise forge a second line of our output.
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
