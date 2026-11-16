// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"slices"

	tea "github.com/charmbracelet/bubbletea"
)

// Account actions are always available from the Status panel, including when
// the TUI was opened outside a tracked folder.
func (m *tuiModel) statusActions() []tuiMenuOption {
	return []tuiMenuOption{
		{key: "u", label: "push a file…", dialog: m.pushDialog()},
		{key: "i", label: "init a folder…", dialog: m.initDialog()},
		{key: "c", label: "clone a folder ref…", dialog: m.cloneDialog()},
		{key: "h", label: "incoming shares", cmd: tuiRequestExec("shares")},
		{key: "o", label: "contacts", cmd: tuiRequestExec("contacts")},
		{key: "U", label: "account usage", cmd: tuiRequestExec("usage")},
		{key: "d", label: "revoke a device…", dialog: m.devicesDialog()},
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
		// be included. The child cannot own the TUI's terminal, so it answers with
		// the flag instead: the safe default (no); users can edit .aqtignore afterwards.
		return tuiRequestExec("init", path, "--no-git")
	})
}

func (m *tuiModel) cloneDialog() tuiDialog {
	return tuiNewInput("Clone folder", "id, aqt:// ref, or share URL", func(ref string) tea.Cmd {
		return tuiOpenDialog(tuiCloneDestinationDialog(ref, false, m.ctx.execPinningOwner(ref)))
	})
}

func tuiCloneDestinationDialog(ref string, adopt bool, run func(sub ...string) tea.Cmd) tuiDialog {
	title := "Clone destination"
	if adopt {
		title = "Adopt destination"
	}
	return tuiNewInput(title, "new directory path", func(dest string) tea.Cmd {
		args := []string{"clone", ref, dest}
		if adopt {
			args = append(args, "--adopt")
		}
		return run(args...)
	})
}

// execPinningOwner runs an action that reads ref and, when it fails, offers to pin the
// owner of the share it read if that is why: the child has no terminal to ask on.
func (c *tuiCtx) execPinningOwner(ref string) func(sub ...string) tea.Cmd {
	return func(sub ...string) tea.Cmd {
		return tuiRequestExecThen(func(exit int, _ []string) tea.Cmd {
			if exit == 0 {
				return nil
			}
			return c.pinOwnerDialogCmd(ref, sub)
		}, sub...)
	}
}

// pinOwnerDialogCmd checks in process whether ref is a share signed by the key the
// server reports for an owner this account has not pinned. If so it shows that claim
// and, on confirm, runs sub again with --accept-owner naming the fingerprint it showed, so
// the child pins only the key the user saw.
func (c *tuiCtx) pinOwnerDialogCmd(ref string, sub []string) tea.Cmd {
	ctx := *c
	return func() tea.Msg {
		// A link read can count against the link's read limit, and never goes
		// through a grant.
		id, fragment, _ := parseRef(ref)
		if fragment != "" {
			return nil
		}
		res, err := ctx.cl.GetResource(id)
		if err != nil || res.GrantKey == nil {
			return nil
		}
		ck, a, row, err := grantSender(res, ctx.mk, ctx.prof)
		ck.Wipe()
		if err != nil || !a.signed || a.pin != nil || row.Attribution != attributionClaimed {
			return nil
		}
		return tuiOpenDialogMsg{dialog: &tuiConfirm{
			title:   "Pin the owner of this share?",
			body:    unpinnedOwnerNotice(row) + "Pin them and run it again?",
			confirm: tuiRequestExec(append(slices.Clone(sub), "--accept-owner", row.ClaimedFingerprint)...),
		}}
	}
}

func (m *tuiModel) devicesDialog() tuiDialog {
	options := make([]tuiMenuOption, 0, len(m.devices))
	for i, device := range m.devices {
		label := device.Name + "  " + device.ID
		body := fmt.Sprintf("Revoke %q (%s)?\nIt must log in again before it can sync.", device.Name, device.ID)
		if device.Current {
			label += "  (this device)"
			body += "\nThis is the current device; the TUI session will stop working."
		}
		options = append(options, tuiMenuOption{key: tuiMenuDigit(i), label: label, dialog: &tuiConfirm{
			title: "Revoke device", body: body,
			confirm: tuiRequestExec("devices", "rm", device.ID, "--yes"),
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
