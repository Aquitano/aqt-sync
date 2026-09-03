// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// A dialog captures all input while open. Update returns the command to run when
// the dialog resolves (nil to stay open); done reports whether it closed.
type tuiDialog interface {
	Update(msg tea.KeyMsg) (cmd tea.Cmd, done bool)
	View(width int) string
}

// --- confirm ---

type tuiConfirm struct {
	title   string
	body    string
	confirm tea.Cmd
}

func (d *tuiConfirm) Update(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "y", "Y", "enter":
		return d.confirm, true
	case "n", "N", "esc", "q":
		return nil, true
	}
	return nil, false
}

func (d *tuiConfirm) View(width int) string {
	body := d.body + "\n\n" + tuiKeyHint("y", "confirm") + "  " + tuiKeyHint("n/esc", "cancel")
	return tuiDialogBox(d.title, body, width)
}

// --- text input ---

type tuiInput struct {
	title  string
	input  textinput.Model
	submit func(value string) tea.Cmd
	// allowEmpty lets a prompt treat an empty submit as valid (e.g. an optional
	// snapshot label); otherwise enter on an empty field does nothing.
	allowEmpty bool
	trimSpace  bool
}

func tuiNewInput(title, placeholder string, submit func(string) tea.Cmd) *tuiInput {
	in := textinput.New()
	in.Placeholder = placeholder
	in.Focus()
	in.CharLimit = 256
	return &tuiInput{title: title, input: in, submit: submit, trimSpace: true}
}

func (d *tuiInput) Update(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "enter":
		v := d.input.Value()
		if d.trimSpace {
			v = strings.TrimSpace(v)
		}
		if v == "" && !d.allowEmpty {
			return nil, false
		}
		return d.submit(v), true
	case "esc":
		return nil, true
	}
	var cmd tea.Cmd
	d.input, cmd = d.input.Update(msg)
	return cmd, false
}

func (d *tuiInput) View(width int) string {
	body := d.input.View() + "\n\n" + tuiKeyHint("enter", "submit") + "  " + tuiKeyHint("esc", "cancel")
	return tuiDialogBox(d.title, body, width)
}

func tuiNewSecretInput(title, placeholder string, submit func(string) tea.Cmd) *tuiInput {
	in := tuiNewInput(title, placeholder, submit)
	in.trimSpace = false
	in.input.EchoMode = textinput.EchoPassword
	return in
}

// --- persistent result ---

type tuiResultDialog struct {
	title string
	body  string
	retry tea.Cmd
}

func (d *tuiResultDialog) Update(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "r":
		return d.retry, false
	case "esc", "q", "enter":
		return nil, true
	}
	return nil, false
}

func (d *tuiResultDialog) View(width int) string {
	body := d.body
	if d.retry != nil {
		body += "\n\n" + tuiKeyHint("r", "retry copy")
	}
	body += "  " + tuiKeyHint("esc", "close")
	return tuiDialogBox(d.title, body, width)
}

// --- menu ---

// tuiMenuOption is one entry of a menu. For the panel action menus it is also
// the only definition of what a panel shortcut does: handleActionKey looks the
// pressed key up here instead of repeating the mapping.
//
// An option resolves to a dialog or to a command, never both. Holding the dialog
// unwrapped is what lets a key press open it synchronously while the menu path
// defers it through tuiOpenDialog.
type tuiMenuOption struct {
	key    string // single-key shortcut, "" for none
	label  string
	dialog tuiDialog
	cmd    tea.Cmd
}

func (o tuiMenuOption) command() tea.Cmd {
	if o.dialog != nil {
		return tuiOpenDialog(o.dialog)
	}
	return o.cmd
}

type tuiMenu struct {
	title   string
	options []tuiMenuOption
	cursor  int
}

func (d *tuiMenu) Update(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "esc", "q":
		return nil, true
	case "up", "k":
		if d.cursor > 0 {
			d.cursor--
		}
		return nil, false
	case "down", "j":
		if d.cursor < len(d.options)-1 {
			d.cursor++
		}
		return nil, false
	case "enter":
		return d.options[d.cursor].command(), true
	}
	for _, o := range d.options {
		if o.key != "" && msg.String() == o.key {
			return o.command(), true
		}
	}
	return nil, false
}

func (d *tuiMenu) View(width int) string {
	var b strings.Builder
	for i, o := range d.options {
		if i > 0 {
			b.WriteByte('\n')
		}
		plain := o.label
		if o.key != "" {
			plain = o.key + "  " + o.label
		}
		if i == d.cursor {
			b.WriteString(tuiStyleSelected.Foreground(tuiColAccent).Bold(true).Render(" " + plain))
		} else if o.key != "" {
			b.WriteString(" " + tuiStyleKey.Render(o.key) + "  " + o.label)
		} else {
			b.WriteString(" " + plain)
		}
	}
	b.WriteString("\n\n" + tuiKeyHint("enter", "select") + "  " + tuiKeyHint("esc", "cancel"))
	return tuiDialogBox(d.title, b.String(), width)
}

// --- help overlay ---

// tuiHelp lists the keybindings. tracked gates the keys that only work inside a
// tracked folder (sync, checkpoint, new snapshot, restore in place), so the overlay
// never advertises an action the panel would refuse.
type tuiHelp struct{ tracked bool }

func (d *tuiHelp) Update(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "esc", "q", "?", "enter":
		return nil, true
	}
	return nil, false
}

func (d *tuiHelp) View(width int) string {
	type helpSection struct {
		title string
		keys  [][2]string
	}
	snapshotKeys := [][2]string{
		{"d", "diff against live tree"}, {"a", "anchor / unanchor"}, {"x", "delete"},
	}
	if d.tracked {
		snapshotKeys = [][2]string{
			{"d", "diff against live tree"}, {"n", "new snapshot (optional label)"},
			{"a", "anchor / unanchor"}, {"R", "restore in place"}, {"x", "delete"},
		}
	}
	sections := []helpSection{
		{"Navigate", [][2]string{
			{"1-4", "jump to panel"}, {"tab / shift+tab", "next / previous panel"},
			{"j/k, ↓/↑", "move selection"}, {"g / G", "top / bottom"},
			{"enter", "inspect in main pane"}, {"esc", "back / close"},
			{"/", "filter panel"}, {"@", "toggle command log"},
			{"space", "actions menu for the panel"},
			{"r", "refresh"}, {"q", "quit"},
		}},
	}
	if d.tracked {
		sections = append(sections, helpSection{"Files", [][2]string{
			{"s", "sync now"}, {"S", "sync options (dry-run, push/pull-only, …)"},
			{"c", "checkpoint (named, never pruned)"},
		}})
	}
	sections = append(sections,
		helpSection{"Snapshots", snapshotKeys},
		helpSection{"Resources", [][2]string{
			{"y", "copy ref / share link"}, {"s", "share (public link, lifecycle options)"},
			{"p", "make private (rotates key, old links die)"}, {"x", "delete"},
		}},
	)
	var b strings.Builder
	for i, s := range sections {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(tuiStyleTitleHot.Render(s.title))
		for _, k := range s.keys {
			b.WriteString("\n  " + tuiStyleKey.Render(tuiPadTrunc(k[0], 16)) + tuiStyleKeyLabel.Render(k[1]))
		}
	}
	return tuiDialogBox("Keybindings", b.String(), width)
}

// tuiDialogBox renders a floating box; the model centers it over the layout.
func tuiDialogBox(title, body string, width int) string {
	w := min(width-8, 64)
	if w < 24 {
		w = width - 2
	}
	inner := lipgloss.NewStyle().Width(w - 4).Render(body)
	h := strings.Count(inner, "\n") + 3
	return tuiBox(title, " "+strings.ReplaceAll(inner, "\n", "\n "), w, h+1, true)
}
