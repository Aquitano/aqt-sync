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

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List your resources with decrypted names and sizes",
		Args:  cobra.NoArgs,
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
		},
	}
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
