package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/api"
)

// Detail builders for the main pane. Each returns plain multi-line text (with
// inline styles); the viewport handles scrolling.

// tuiFileItem is a files-panel row payload.
type tuiFileItem struct {
	kind string // new | modified | mode | type | deleted | renamed | incoming | conflict
	path string
	dir  bool   // the path is a tracked directory, which has no size to report
	desc string // one-line explanation shown in the detail view
}

func tuiFileDetail(it tuiFileItem, root string) string {
	var b strings.Builder
	b.WriteString(tuiStyleTitle.Render(it.path) + "\n\n")
	b.WriteString(tuiField("state", it.kind))

	switch it.kind {
	case "conflict":
		b.WriteString(tuiField("direction", "kept alongside your version"))
		b.WriteString(tuiField("yours", tuiConflictOriginal(it.path)))
		b.WriteString(tuiField("copy", it.path))
	case "incoming":
		b.WriteString(tuiField("direction", "server → local (on next sync)"))
	default:
		b.WriteString(tuiField("direction", "local → server (on next sync)"))
		// A single real path can be stat'd on demand; a deletion has nothing to
		// stat and a rename's body is an arrow, not a path.
		if !it.dir && (it.kind == "new" || it.kind == "modified") {
			if fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(it.path))); err == nil {
				b.WriteString(tuiField("size", humanBytes(fi.Size())))
				b.WriteString(tuiField("modified", fi.ModTime().Format("2006-01-02 15:04:05")))
			}
		}
	}
	if it.desc != "" {
		b.WriteString("\n" + it.desc + "\n")
	}
	switch it.kind {
	case "conflict":
		b.WriteString("\n" + tuiStyleDim.Render(
			"A previous sync kept your local version and wrote the remote one here.\n"+
				"Compare the two, keep what you want, delete this copy; the next sync\n"+
				"pushes the result."))
	case "incoming":
		b.WriteString("\n" + tuiStyleDim.Render("On the server, not yet pulled — press s to sync."))
	default:
		b.WriteString("\n" + tuiStyleDim.Render("Local change since the last sync — press s to sync."))
	}
	return b.String()
}

// tuiConflictOriginal recovers the path a conflict copy stands beside by dropping
// the ".conflict-<host>-<ts>" suffix conflictCopyPath appends.
func tuiConflictOriginal(copyPath string) string {
	if i := strings.Index(copyPath, ".conflict-"); i >= 0 {
		return copyPath[:i]
	}
	return copyPath
}

func tuiSnapshotDetail(r snapshotRow, diff *snapshotDiffResult, diffErr error, diffing bool) string {
	var b strings.Builder
	title := r.Name
	if r.Label != "" {
		title += "  —  " + r.Label
	}
	b.WriteString(tuiStyleTitle.Render(title) + "\n\n")
	b.WriteString(tuiField("created", r.Created))
	b.WriteString(tuiField("version", fmt.Sprintf("%d", r.Version)))
	b.WriteString(tuiField("snapshot", r.ID))
	b.WriteString(tuiField("resource", r.ResourceID))
	anchored := "no — retention may prune it"
	if r.Anchored {
		anchored = tuiStyleAccent.Render("yes — never pruned")
	}
	b.WriteString(tuiField("anchored", anchored))
	b.WriteString("\n")
	switch {
	case diffing:
		b.WriteString(tuiStyleDim.Render("computing diff against the live tree…"))
	case diffErr != nil:
		b.WriteString(tuiStyleErr.Render("diff failed: ") + diffErr.Error())
	case diff != nil:
		b.WriteString(tuiDiffBody(*diff))
	default:
		b.WriteString(tuiStyleDim.Render("press d to diff this snapshot against the live tree"))
	}
	return b.String()
}

func tuiDiffBody(d snapshotDiffResult) string {
	var b strings.Builder
	b.WriteString(tuiStyleTitle.Render(fmt.Sprintf("%s (v%d) → %s (v%d)", d.Left.Label, d.Left.Version, d.Right.Label, d.Right.Version)) + "\n")
	if len(d.Added)+len(d.Removed)+len(d.Modified)+len(d.Renamed) == 0 {
		b.WriteString("\n" + tuiStyleDim.Render("no differences"))
		return b.String()
	}
	for _, p := range d.Added {
		b.WriteString("\n" + tuiStyleAdd.Render("+ "+p))
	}
	for _, p := range d.Removed {
		b.WriteString("\n" + tuiStyleDel.Render("- "+p))
	}
	for _, p := range d.Modified {
		b.WriteString("\n" + tuiStyleMod.Render("~ "+p))
	}
	for _, r := range d.Renamed {
		b.WriteString("\n" + tuiStyleMod.Render("→ "+renameArrow(r)))
	}
	return b.String()
}

func tuiResourceDetail(r lsRow) string {
	var b strings.Builder
	b.WriteString(tuiStyleTitle.Render(r.Name) + "\n\n")
	b.WriteString(tuiField("kind", r.Kind))
	if r.Kind != api.KindFolder {
		b.WriteString(tuiField("size", humanBytes(r.Size)))
	}
	vis := r.Visibility
	if vis == string(api.Public) {
		vis = tuiStylePublic.Render("public — anyone with the link can decrypt")
	} else {
		vis = "private — only this account's devices"
	}
	b.WriteString(tuiField("visibility", vis))
	b.WriteString(tuiField("version", fmt.Sprintf("%d", r.Version)))
	b.WriteString(tuiField("ref", "aqt://"+r.ID))
	if r.Visibility == string(api.Public) {
		b.WriteString("\n" + tuiStyleDim.Render("y copies the public share link (fragment key included)"))
	} else {
		b.WriteString("\n" + tuiStyleDim.Render("y copies the private aqt:// owner reference"))
	}
	return b.String()
}

// tuiAccountDetail is the status panel's main-pane view: identity plus devices.
func tuiAccountDetail(ctx *tuiCtx, devices []api.Device, devErr error) string {
	var b strings.Builder
	b.WriteString(tuiStyleTitle.Render("Account") + "\n\n")
	b.WriteString(tuiField("email", ctx.prof.Email))
	b.WriteString(tuiField("server", ctx.prof.Server))
	b.WriteString(tuiField("device", ctx.prof.DeviceID))
	b.WriteString(tuiField("fingerprint", ctx.prof.Fingerprint))
	b.WriteString("\n" + tuiStyleTitle.Render("Devices") + "\n")
	switch {
	case devErr != nil:
		b.WriteString("\n" + tuiStyleErr.Render("could not list devices: ") + devErr.Error())
	case devices == nil:
		b.WriteString("\n" + tuiStyleDim.Render("loading…"))
	default:
		for _, d := range devices {
			marker := "  "
			name := d.Name
			if d.Current {
				marker = tuiStyleAccent.Render("● ")
				name += tuiStyleDim.Render("  (this device)")
			}
			b.WriteString("\n" + marker + name + "  " + tuiStyleDim.Render(d.ID))
		}
	}
	return b.String()
}

func tuiField(name, value string) string {
	return tuiStyleDim.Render(fmt.Sprintf("%-12s", name)) + value + "\n"
}

// tuiLogView renders the command log tail; lines already carry their styling.
func tuiLogView(lines []string) string {
	if len(lines) == 0 {
		return tuiStyleDim.Render("No commands run yet. Actions (sync, share, restore…) appear here\nwith their full output, exactly as the CLI prints it.")
	}
	return strings.Join(lines, "\n")
}
