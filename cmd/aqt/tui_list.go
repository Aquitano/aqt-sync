package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// tuiRow is one line in a side panel. Selectable rows carry a payload the detail
// view and the action keys act on; header rows only structure the list.
type tuiRow struct {
	text   string // plain text, used for filtering and the selected-row bar
	styled string // colored variant shown when not selected ("" = use text)
	header bool
	tag    any
}

func (r tuiRow) display() string {
	if r.styled != "" {
		return r.styled
	}
	return r.text
}

// tuiList is a cursor over rows with a scroll window and an optional substring
// filter. It renders only the visible slice, so panel cost is bounded by panel
// height, not item count.
type tuiList struct {
	rows   []tuiRow
	cursor int
	offset int
	filter string
}

// setRows replaces the list contents, keeping the cursor on the same tag when it
// still exists so a background refresh does not yank the selection away.
func (l *tuiList) setRows(rows []tuiRow) {
	var keep any
	if cur := l.current(); cur != nil {
		keep = cur.tag
	}
	l.rows = rows
	if keep != nil {
		for i, r := range l.visibleRows() {
			if !r.header && r.tag == keep {
				l.cursor = i
				l.clamp()
				return
			}
		}
	}
	l.clamp()
	l.snapToSelectable(1)
}

// visibleRows applies the filter. Headers disappear while filtering: a filtered
// view is a flat match list.
func (l *tuiList) visibleRows() []tuiRow {
	if l.filter == "" {
		return l.rows
	}
	q := strings.ToLower(l.filter)
	out := make([]tuiRow, 0, len(l.rows))
	for _, r := range l.rows {
		if !r.header && strings.Contains(strings.ToLower(r.text), q) {
			out = append(out, r)
		}
	}
	return out
}

func (l *tuiList) setFilter(f string) {
	l.filter = f
	l.cursor, l.offset = 0, 0
	l.snapToSelectable(1)
}

func (l *tuiList) clamp() {
	if n := len(l.visibleRows()); l.cursor >= n {
		l.cursor = n - 1
	}
	if l.cursor < 0 {
		l.cursor = 0
	}
}

// snapToSelectable moves the cursor in direction dir (+1/-1) until it rests on a
// selectable row, so headers are skipped transparently. In a list with no
// selectable rows at all the cursor parks on a header and current() reports nil.
func (l *tuiList) snapToSelectable(dir int) {
	rows := l.visibleRows()
	inBounds := func() bool { return l.cursor >= 0 && l.cursor < len(rows) }
	for inBounds() && rows[l.cursor].header {
		l.cursor += dir
	}
	l.clamp()
	if len(rows) > 0 && rows[l.cursor].header {
		// Ran off the end (e.g. trailing headers): search the other way.
		for inBounds() && rows[l.cursor].header {
			l.cursor -= dir
		}
		l.clamp()
	}
}

func (l *tuiList) move(delta int) {
	rows := l.visibleRows()
	if len(rows) == 0 {
		return
	}
	dir := 1
	if delta < 0 {
		dir = -1
	}
	l.cursor += delta
	l.clamp()
	l.snapToSelectable(dir)
}

func (l *tuiList) home() { l.cursor = 0; l.snapToSelectable(1) }
func (l *tuiList) end()  { l.cursor = len(l.visibleRows()) - 1; l.snapToSelectable(-1) }

// current returns the selected row, or nil when the list is empty or the cursor
// sits on a header (possible only in a headers-only list).
func (l *tuiList) current() *tuiRow {
	rows := l.visibleRows()
	if l.cursor < 0 || l.cursor >= len(rows) || rows[l.cursor].header {
		return nil
	}
	r := rows[l.cursor]
	return &r
}

// render draws height lines of the list at the given inner width, scrolling the
// window to keep the cursor visible and marking the selection when focused.
func (l *tuiList) render(width, height int, focused bool) string {
	rows := l.visibleRows()
	if height < 1 {
		return ""
	}
	if l.cursor < l.offset {
		l.offset = l.cursor
	}
	if l.cursor >= l.offset+height {
		l.offset = l.cursor - height + 1
	}
	if l.offset > len(rows)-height {
		l.offset = len(rows) - height
	}
	if l.offset < 0 {
		l.offset = 0
	}
	var b strings.Builder
	for i := l.offset; i < len(rows) && i < l.offset+height; i++ {
		if i > l.offset {
			b.WriteByte('\n')
		}
		r := rows[i]
		switch {
		case i == l.cursor && focused && !r.header:
			b.WriteString(tuiStyleSelected.Render(tuiPadTrunc(" "+r.text, width)))
		case i == l.cursor && !r.header:
			// Unfocused panels keep a quiet cursor so returning to the panel
			// lands where you left it.
			b.WriteString(tuiStyleDim.Render("›") + tuiTrunc(r.display(), width-1))
		default:
			b.WriteString(" " + tuiTrunc(r.display(), width-1))
		}
	}
	return b.String()
}

// tuiTrunc truncates a possibly-styled string to width terminal cells.
func tuiTrunc(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(s)
}

// tuiPadTrunc fits s to exactly width cells (truncate or pad with spaces), so a
// background style covers the full line.
func tuiPadTrunc(s string, width int) string {
	s = tuiTrunc(s, width)
	if pad := width - lipgloss.Width(s); pad > 0 {
		s += strings.Repeat(" ", pad)
	}
	return s
}

// tuiBox frames body in a rounded border with the title embedded in the top edge,
// lazygit-style: "╭─ Title ──────╮". width and height are outer dimensions.
func tuiBox(title, body string, width, height int, focused bool) string {
	if width < 4 || height < 2 {
		return ""
	}
	inner := width - 2
	border := lipgloss.NewStyle().Foreground(tuiColBorder)
	titleStyle := tuiStyleTitle
	if focused {
		border = border.Foreground(tuiColAccent)
		titleStyle = tuiStyleTitleHot
	}

	t := " " + title + " "
	fill := inner - lipgloss.Width(t) - 1
	if fill < 0 {
		t = tuiTrunc(t, inner-1)
		fill = inner - lipgloss.Width(t) - 1
	}
	var b strings.Builder
	b.WriteString(border.Render("╭─") + titleStyle.Render(t) + border.Render(strings.Repeat("─", fill)+"╮"))

	lines := strings.Split(body, "\n")
	for i := 0; i < height-2; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteByte('\n')
		b.WriteString(border.Render("│") + tuiPadTrunc(line, inner) + border.Render("│"))
	}
	b.WriteByte('\n')
	b.WriteString(border.Render("╰" + strings.Repeat("─", inner) + "╯"))
	return b.String()
}
