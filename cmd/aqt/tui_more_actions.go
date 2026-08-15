// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *tuiModel) pullDialog(res lsRow) tuiDialog {
	in := tuiNewInput("Pull "+res.Name, "output path (empty = resource name)", func(out string) tea.Cmd {
		args := []string{"pull", "aqt://" + res.ID}
		if out != "" {
			args = append(args, "--out", out)
		}
		return tuiRequestExec(args...)
	})
	in.allowEmpty = true
	return in
}

func resourceCloneDialog(res lsRow, adopt bool) tuiDialog {
	return tuiCloneDestinationDialog("aqt://"+res.ID, adopt)
}

func shareExpiryDialog(res lsRow) tuiDialog {
	return tuiNewInput("Custom expiry", "duration, e.g. 30m or 72h", func(expire string) tea.Cmd {
		return tuiRequestExec("share", res.ID, "--expire", expire)
	})
}

func shareMaxReadsDialog(res lsRow) tuiDialog {
	return tuiNewInput("Read limit", "maximum downloads, e.g. 5", func(reads string) tea.Cmd {
		return tuiRequestExec("share", res.ID, "--max-reads", reads)
	})
}

func grantDialog(res lsRow) tuiDialog {
	return tuiNewInput("Grant "+res.Name, "recipient email", func(email string) tea.Cmd {
		return tuiRequestExec("share", res.ID, "--with", email)
	})
}

func revokeGrantDialog(res lsRow) tuiDialog {
	return tuiNewInput("Revoke grant", "recipient email", func(email string) tea.Cmd {
		return func() tea.Msg {
			return tuiOpenDialogMsg{dialog: &tuiConfirm{
				title:   "Revoke grant",
				body:    fmt.Sprintf("Revoke %s's access to %q?\nThe resource key is rotated for private resources.", email, res.Name),
				confirm: tuiRequestExec("unshare", res.ID, "--with", email, "--yes"),
			}}
		}
	})
}

func autoSnapshotCmd(res lsRow) tea.Cmd {
	flag := "--on"
	if res.AutoSnapshot {
		flag = "--off"
	}
	return tuiRequestExec("snapshot", "auto", "--id", res.ID, flag)
}

func autoSnapshotLabel(res lsRow) string {
	if res.AutoSnapshot {
		return "disable scheduled snapshots"
	}
	return "enable scheduled snapshots"
}

func deleteResourceWithSnapshotsDialog(res lsRow) tuiDialog {
	return &tuiConfirm{
		title:   "Delete resource and snapshots",
		body:    fmt.Sprintf("Delete %q and every snapshot retaining its data?\nThis cannot be undone.", res.Name),
		confirm: tuiRequestExec("rm", res.ID, "--with-snapshots", "--yes"),
	}
}

func snapshotRestoreOutDialog(snap snapshotRow) tuiDialog {
	return tuiNewInput("Restore side-by-side", "new output directory", func(out string) tea.Cmd {
		return tuiRequestExec("restore", snap.ID, "--out", out)
	})
}

func snapshotExportDialog(snap snapshotRow) tuiDialog {
	return tuiNewInput("Export plaintext snapshot", "trusted output directory", func(out string) tea.Cmd {
		return func() tea.Msg {
			return tuiOpenDialogMsg{dialog: &tuiConfirm{
				title:   "Export plaintext",
				body:    fmt.Sprintf("Decrypt %q into %s?\nThe exported files are outside aqt's encryption boundary.", snap.displayName(), out),
				confirm: tuiRequestExec("snapshot", "export", snap.ID, "--out", out),
			}}
		}
	})
}

func snapshotRetentionDialog(snap snapshotRow) tuiDialog {
	return &tuiMenu{title: "Snapshot retention", options: []tuiMenuOption{
		{key: "k", label: "keep newest N for this resource…", cmd: tuiOpenDialog(tuiNewInput(
			"Keep newest snapshots", "number to keep", func(n string) tea.Cmd {
				return tuiOpenDialog(&tuiConfirm{
					title:   "Prune by retention",
					body:    fmt.Sprintf("Keep the newest %s unanchored snapshot(s) of %q and delete older ones?", n, snap.Name),
					confirm: tuiRequestExec("snapshot", "prune", "--id", snap.ResourceID, "--keep-last", n, "--yes"),
				})
			}))},
		{key: "o", label: "delete snapshots older than…", cmd: tuiOpenDialog(tuiNewInput(
			"Prune old snapshots", "age, e.g. 720h", func(age string) tea.Cmd {
				return tuiOpenDialog(&tuiConfirm{
					title:   "Prune by age",
					body:    fmt.Sprintf("Delete unanchored snapshots of %q older than %s?", snap.Name, age),
					confirm: tuiRequestExec("snapshot", "prune", "--id", snap.ResourceID, "--before", age, "--yes"),
				})
			}))},
	}}
}

func snapshotListFiltersDialog(snap snapshotRow) tuiDialog {
	return &tuiMenu{title: "Snapshot list filters", options: []tuiMenuOption{
		{key: "l", label: "limit results…", cmd: tuiOpenDialog(tuiNewInput(
			"Snapshot limit", "maximum rows", func(limit string) tea.Cmd {
				return tuiRequestExec("snapshot", "list", "--id", snap.ResourceID, "--limit", limit)
			}))},
		{key: "s", label: "created within…", cmd: tuiOpenDialog(tuiNewInput(
			"Recent snapshots", "window, e.g. 168h", func(window string) tea.Cmd {
				return tuiRequestExec("snapshot", "list", "--id", snap.ResourceID, "--since", window)
			}))},
		{key: "b", label: "older than…", cmd: tuiOpenDialog(tuiNewInput(
			"Older snapshots", "age, e.g. 720h", func(age string) tea.Cmd {
				return tuiRequestExec("snapshot", "list", "--id", snap.ResourceID, "--before", age)
			}))},
	}}
}
