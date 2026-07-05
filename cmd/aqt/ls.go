package main

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// lsRow is one resource as shown by `aqt ls`, with its name and size decrypted
// locally from the sealed metadata.
type lsRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size"`
	Visibility string `json:"visibility"`
	Version    int    `json:"version"`
}

// lsEntry is one member file of a folder, as shown by `aqt ls <folder>`. It is
// read from the folder's sealed manifest, so listing needs only the manifest
// blob — no member file content is downloaded.
type lsEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls [folder]",
		Short: "List your resources, or the files inside one folder",
		Long: "With no argument, list your top-level resources with decrypted names and\n" +
			"sizes. Given a folder (by name, id, or aqt:// ref), list the files inside it,\n" +
			"read from the folder's manifest without downloading any file content.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()

			if len(args) == 1 {
				return listFolder(cl, mk, args[0])
			}
			return listResources(cl, mk)
		},
	}
}

func listResources(cl *client.Client, mk crypto.MasterKey) error {
	rows, err := collectResources(cl, mk)
	if err != nil {
		return err
	}
	if flagJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no resources yet")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tKIND\tSIZE\tVISIBILITY\tID")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Kind, sizeCell(r.Kind, r.Size), r.Visibility, r.ID)
	}
	return w.Flush()
}

// listFolder resolves arg to one of the owner's folders and prints its member
// files from the sealed manifest. Only the manifest blob is fetched, so this
// stays cheap regardless of how much data the folder holds.
func listFolder(cl *client.Client, mk crypto.MasterKey, arg string) error {
	id, name, err := resolveOwnedFolder(cl, mk, arg)
	if err != nil {
		return err
	}
	members, err := folderMembers(cl, id, mk)
	if err != nil {
		return fmt.Errorf("read folder %q: %w", name, err)
	}
	rows := make([]lsEntry, 0, len(members))
	for _, e := range members {
		rows = append(rows, lsEntry{Path: e.Path, Size: e.Size})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })

	if flagJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "folder %q is empty\n", name)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PATH\tSIZE")
	var total int64
	for _, r := range rows {
		total += r.Size
		fmt.Fprintf(w, "%s\t%s\n", r.Path, humanBytes(r.Size))
	}
	fmt.Fprintf(w, "\t\n%d files\t%s\n", len(rows), humanBytes(total))
	return w.Flush()
}

// resolveOwnedFolder maps arg (a name, id, or aqt:// ref) to one of the owner's
// folders, returning its id and decrypted name. Matching prefers an exact id
// (from the ref), then falls back to a unique decrypted name so `aqt ls chill-flow`
// works the same way the resource is shown by `aqt ls`.
func resolveOwnedFolder(cl *client.Client, mk crypto.MasterKey, arg string) (id, name string, err error) {
	items, err := cl.ListResources()
	if err != nil {
		return "", "", err
	}
	wantID, _, _ := parseRef(arg)

	for _, it := range items {
		if it.ID == wantID {
			meta, ok := openMetadata(it, mk)
			return checkFolder(it.ID, meta, ok)
		}
	}

	var matches []api.ResourceListItem
	var metas []api.Metadata
	for _, it := range items {
		if meta, ok := openMetadata(it, mk); ok && meta.Name == arg {
			matches = append(matches, it)
			metas = append(metas, meta)
		}
	}
	switch len(matches) {
	case 0:
		return "", "", fmt.Errorf("no resource named %q (try `aqt ls` to see names, or pass an id)", arg)
	case 1:
		return checkFolder(matches[0].ID, metas[0], true)
	default:
		return "", "", fmt.Errorf("%q is ambiguous (%d resources share that name); pass an id instead", arg, len(matches))
	}
}

// checkFolder rejects a resolved resource that is not a listable folder: a file
// has no member listing, and a pack-and-seal folder's contents live in an opaque
// tarball that can't be read without downloading the whole thing.
func checkFolder(id string, meta api.Metadata, ok bool) (string, string, error) {
	name := meta.Name
	if name == "" {
		name = id
	}
	switch {
	case !ok:
		return "", "", fmt.Errorf("cannot decrypt metadata for %q", id)
	case meta.Kind != api.KindFolder:
		return "", "", fmt.Errorf("%q is a file, not a folder; use `aqt cat` or `aqt pull`", name)
	case meta.Packed:
		return "", "", fmt.Errorf("folder %q is pack-and-sealed; its contents can't be listed without downloading it (use `aqt clone`)", name)
	}
	return id, name, nil
}

// collectResources lists the owner's resources and decrypts each one's metadata
// with the master key, sorted by name. A resource whose metadata cannot be
// decrypted is still listed, with a placeholder name.
func collectResources(cl *client.Client, mk crypto.MasterKey) ([]lsRow, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, err
	}
	rows := make([]lsRow, 0, len(items))
	for _, it := range items {
		meta, ok := openMetadata(it, mk)
		name, kind := meta.Name, meta.Kind
		switch {
		case !ok:
			name, kind = "(unreadable)", "?"
		case name == "":
			name = "(unnamed)"
		}
		if ok && kind == "" {
			kind = api.KindFile
		}
		rows = append(rows, lsRow{
			ID: it.ID, Name: name, Kind: kind, Size: meta.Size,
			Visibility: string(it.Visibility), Version: it.Version,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name != rows[j].Name {
			return rows[i].Name < rows[j].Name
		}
		return rows[i].ID < rows[j].ID
	})
	return rows, nil
}

// sizeCell renders a resource's size, leaving folders (whose size is not tracked)
// as a dash.
func sizeCell(kind string, size int64) string {
	if kind == api.KindFolder {
		return "-"
	}
	return humanBytes(size)
}
