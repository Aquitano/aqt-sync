package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// Account actions are always available from the Status panel, including when
// the TUI was opened outside a tracked folder.
func (m *tuiModel) statusAction(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "u":
		m.dialog = m.pushDialog()
	case "i":
		m.dialog = m.initDialog()
	case "c":
		m.dialog = m.cloneDialog()
	case "d":
		m.dialog = m.devicesDialog()
	}
	return m, nil
}

func (m *tuiModel) statusActions() []tuiMenuOption {
	return []tuiMenuOption{
		{key: "u", label: "push a file…", cmd: tuiOpenDialog(m.pushDialog())},
		{key: "i", label: "init a folder…", cmd: tuiOpenDialog(m.initDialog())},
		{key: "c", label: "clone a folder ref…", cmd: tuiOpenDialog(m.cloneDialog())},
		{key: "h", label: "incoming shares", cmd: tuiRequestExec("shares")},
		{key: "o", label: "contacts", cmd: tuiRequestExec("contacts")},
		{key: "U", label: "account usage", cmd: tuiRequestExec("usage")},
		{key: "d", label: "revoke a device…", cmd: tuiOpenDialog(m.devicesDialog())},
	}
}

func (m *tuiModel) pushDialog() tuiDialog {
	return tuiNewInput("Push file", "path to upload", func(path string) tea.Cmd {
		return tuiRequestExec("push", path)
	})
}

func (m *tuiModel) initDialog() tuiDialog {
	return tuiNewInput("Init folder", "path to track", func(path string) tea.Cmd {
		// If the folder contains a git repository, init asks whether .git should
		// be included. The child cannot own the TUI's terminal, so choose the
		// safe default (no); users can edit .aqtignore afterwards.
		return tuiRequestExecStdin("n\n", "init", path)
	})
}

func (m *tuiModel) cloneDialog() tuiDialog {
	return tuiNewInput("Clone folder", "id, aqt:// ref, or share URL", func(ref string) tea.Cmd {
		return tuiOpenDialog(tuiCloneDestinationDialog(ref, false))
	})
}

func tuiCloneDestinationDialog(ref string, adopt bool) tuiDialog {
	title := "Clone destination"
	if adopt {
		title = "Adopt destination"
	}
	return tuiNewInput(title, "new directory path", func(dest string) tea.Cmd {
		args := []string{"clone", ref, dest}
		if adopt {
			args = append(args, "--adopt")
		}
		return tuiRequestExec(args...)
	})
}

func (m *tuiModel) devicesDialog() tuiDialog {
	options := make([]tuiMenuOption, 0, len(m.devices))
	for i, device := range m.devices {
		device := device
		label := device.Name + "  " + device.ID
		if device.Current {
			label += "  (this device)"
		}
		options = append(options, tuiMenuOption{key: tuiMenuDigit(i), label: label, cmd: func() tea.Msg {
			body := fmt.Sprintf("Revoke %q (%s)?\nIt must log in again before it can sync.", device.Name, device.ID)
			if device.Current {
				body += "\nThis is the current device; the TUI session will stop working."
			}
			return tuiOpenDialogMsg{dialog: &tuiConfirm{
				title: "Revoke device", body: body,
				confirm: tuiRequestExec("devices", "rm", device.ID, "--yes"),
			}}
		}})
	}
	if len(options) == 0 {
		options = append(options, tuiMenuOption{label: "No devices available"})
	}
	return &tuiMenu{title: "Revoke device", options: options}
}

func tuiMenuDigit(i int) string {
	if i >= 0 && i < 9 {
		return string(rune('1' + i))
	}
	return ""
}

func (m *tuiModel) agentToggleLabel() string {
	if m.agent.running {
		return "stop watch agent"
	}
	return "start watch agent"
}

func (m *tuiModel) agentToggleCmd() tea.Cmd {
	if m.agent.running {
		return tuiRequestExec("agent", "stop", m.ctx.root)
	}
	return tuiRequestExec("agent", "start", m.ctx.root)
}
