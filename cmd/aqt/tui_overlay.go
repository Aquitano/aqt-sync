// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// tuiOverlay composites top centered onto base, both treated as line blocks of
// the given width and height. Each top line is spliced into the matching base
// line at the centered column. Slicing a styled base line at a column boundary
// is done with ANSI-aware cuts so a background color or style on the base cannot
// bleed into or out of the overlay region.
func tuiOverlay(base, top string, w, h int) string {
	baseLines := strings.Split(base, "\n")
	topLines := strings.Split(top, "\n")

	topH := len(topLines)
	topW := 0
	for _, l := range topLines {
		if lw := ansi.StringWidth(l); lw > topW {
			topW = lw
		}
	}

	y0 := (h - topH) / 2
	if y0 < 0 {
		y0 = 0
	}
	x0 := (w - topW) / 2
	if x0 < 0 {
		x0 = 0
	}

	out := make([]string, len(baseLines))
	for i, bl := range baseLines {
		ti := i - y0
		if ti < 0 || ti >= topH {
			out[i] = bl
			continue
		}
		left := ansi.Truncate(bl, x0, "")
		if lw := ansi.StringWidth(left); lw < x0 {
			// A base line shorter than the overlay column: pad so the box lands
			// at the same column on every row.
			left += strings.Repeat(" ", x0-lw)
		}
		tl := topLines[ti]
		if tw := ansi.StringWidth(tl); tw < topW {
			tl += strings.Repeat(" ", topW-tw)
		}
		right := ansi.TruncateLeft(bl, x0+topW, "")
		out[i] = left + tl + right
	}
	return strings.Join(out, "\n")
}

// tuiDimBackground flattens screen to a single dim style. Stripping the existing
// styles first and re-rendering avoids any interaction with the overlay's column
// cuts (losing background detail while dimmed is the intended lazygit look).
func tuiDimBackground(screen string) string {
	return tuiStyleDim.Render(ansi.Strip(screen))
}
