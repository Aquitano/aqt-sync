// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "github.com/charmbracelet/lipgloss"

// The TUI palette sticks to the 256-color cube with adaptive light/dark picks so
// it reads on both default terminal themes without configuration. Semantic names
// (add/mod/del) match the status letters they color.
var (
	tuiColAccent   = lipgloss.AdaptiveColor{Light: "29", Dark: "43"}   // active border, selection
	tuiColBorder   = lipgloss.AdaptiveColor{Light: "250", Dark: "238"} // inactive border
	tuiColDim      = lipgloss.AdaptiveColor{Light: "240", Dark: "244"}
	tuiColAdd      = lipgloss.AdaptiveColor{Light: "28", Dark: "78"}
	tuiColMod      = lipgloss.AdaptiveColor{Light: "130", Dark: "179"}
	tuiColDel      = lipgloss.AdaptiveColor{Light: "124", Dark: "167"}
	tuiColConflict = lipgloss.AdaptiveColor{Light: "160", Dark: "203"}
	tuiColPublic   = lipgloss.AdaptiveColor{Light: "166", Dark: "215"}
	tuiColSelBg    = lipgloss.AdaptiveColor{Light: "254", Dark: "236"}

	tuiStyleTitle    = lipgloss.NewStyle().Bold(true)
	tuiStyleTitleHot = lipgloss.NewStyle().Bold(true).Foreground(tuiColAccent)
	tuiStyleDim      = lipgloss.NewStyle().Foreground(tuiColDim)
	tuiStyleAdd      = lipgloss.NewStyle().Foreground(tuiColAdd)
	tuiStyleMod      = lipgloss.NewStyle().Foreground(tuiColMod)
	tuiStyleDel      = lipgloss.NewStyle().Foreground(tuiColDel)
	tuiStyleConflict = lipgloss.NewStyle().Foreground(tuiColConflict).Bold(true)
	tuiStylePublic   = lipgloss.NewStyle().Foreground(tuiColPublic)
	tuiStyleAccent   = lipgloss.NewStyle().Foreground(tuiColAccent)
	tuiStyleErr      = lipgloss.NewStyle().Foreground(tuiColDel).Bold(true)

	// Selected row: background bar across the panel width, like lazygit's line
	// cursor. Background only; the selected row keeps each segment's own
	// foreground (see tuiRow.selected) so the semantic colors survive the bar.
	tuiStyleSelected = lipgloss.NewStyle().Background(tuiColSelBg)

	// Bottom bar: "key" bright, "label" dim, joined with dim separators.
	tuiStyleKey      = lipgloss.NewStyle().Foreground(tuiColAccent)
	tuiStyleKeyLabel = lipgloss.NewStyle().Foreground(tuiColDim)
)

// tuiKeyHint renders one "key label" pair for the bottom bar.
func tuiKeyHint(key, label string) string {
	return tuiStyleKey.Render(key) + tuiStyleKeyLabel.Render(" "+label)
}
