// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// lsRow is one resource as shown by `aqt ls`, with metadata decrypted locally.
type lsRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size"`
	Visibility string `json:"visibility"`
	// MinClient is set only when the row needs a newer release than this build, so a
	// script can tell "too old to read" from a name that genuinely failed to decrypt.
	MinClient    int   `json:"minClient,omitempty"`
	AutoSnapshot bool  `json:"-"`
	Version      int   `json:"version"`
	CreatedAt    int64 `json:"createdAt,omitempty"`
	UpdatedAt    int64 `json:"updatedAt,omitempty"`
}

type lsOptions struct {
	long       bool
	filter     string
	kind       string
	visibility string
	sortBy     string
	reverse    bool
}

func lsCmd() *cobra.Command {
	opts := lsOptions{sortBy: "name"}
	cmd := &cobra.Command{
		Use:   "ls [folder-name-or-ref[/path]]",
		Short: "List resources, with filtering and sorting, or entries inside a folder",
		Long: "Without arguments, lists every resource with its decrypted name and size.\n" +
			"Use --filter, --kind, or --visibility to narrow the list; --sort accepts\n" +
			"name, size, or date. Size/date sorts are newest/largest first by default.\n" +
			"With a folder's name, id, or tracked path, lists its entries; a path inside\n" +
			"it (aqt://<id>/<path>) lists that subtree, without downloading the tree.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts != (lsOptions{sortBy: "name"}) {
				return errors.New("resource list flags cannot be used when listing inside a folder")
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()

			if len(args) > 0 {
				return runLsFolder(cl, mk, args[0])
			}
			return listResources(cl, mk, opts)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&opts.long, "long", "l", false, "show update time and version")
	f.StringVarP(&opts.filter, "filter", "f", "", "show names containing this text (case-insensitive)")
	f.StringVar(&opts.kind, "kind", "", "show only file or folder resources")
	f.StringVar(&opts.visibility, "visibility", "", "show only private or public resources")
	f.StringVar(&opts.sortBy, "sort", "name", "sort by name, size, or date")
	f.BoolVarP(&opts.reverse, "reverse", "r", false, "reverse the selected sort order")
	markJSONSupported(cmd)
	return cmd
}

func listResources(cl *client.Client, mk crypto.MasterKey, opts lsOptions) error {
	rows, err := collectResources(cl, mk)
	if err != nil {
		return err
	}
	rows, err = selectResourceRows(rows, opts)
	if err != nil {
		return err
	}
	if flagJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		emptyMessage := "no resources yet"
		if opts.filter != "" || opts.kind != "" || opts.visibility != "" {
			emptyMessage = "no matching resources"
		}
		fmt.Fprintln(os.Stderr, emptyMessage)
		return nil
	}
	header := []string{"NAME", "KIND", "SIZE", "VISIBILITY", "ID"}
	if opts.long {
		header = []string{"NAME", "KIND", "SIZE", "VISIBILITY", "UPDATED", "VERSION", "ID"}
	}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		cell := []string{r.Name, r.Kind, sizeCell(r.Kind, r.Size), r.Visibility}
		if opts.long {
			cell = append(cell, cliutil.FormatUnix(r.UpdatedAt), fmt.Sprintf("v%d", r.Version))
		}
		cell = append(cell, r.ID)
		cells = append(cells, cell)
	}
	return printTable(os.Stdout, header, cells)
}

// collectResources decrypts owner-only metadata and returns a stable name sort.
func collectResources(cl *client.Client, mk crypto.MasterKey) ([]lsRow, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, err
	}
	rows := make([]lsRow, 0, len(items))
	for _, it := range items {
		meta, ok := openMetadata(it, mk)
		name, kind := meta.Name, meta.Kind
		minClient := 0
		switch {
		// A reclaimed tombstone's ciphertext (and its wrapped key) is gone, so its
		// name is unknowable and every read 410s; without this label it rendered as
		// "(unreadable)", indistinguishable from corruption. `aqt rm` clears it.
		case it.Reclaimed:
			name, kind = "(reclaimed link; `aqt rm` to clear)", "?"
		// A resource another device wrote in a format this build cannot read fails to
		// decrypt for a reason the user can act on. Saying so is the whole point of
		// capability negotiation; "(unreadable)" here is indistinguishable from real
		// corruption or a wrong passphrase.
		case it.MinClient > api.ClientCapability:
			minClient = it.MinClient
			name, kind = fmt.Sprintf("(needs aqt supporting capability %d)", it.MinClient), "?"
		case !ok:
			name, kind = "(unreadable)", "?"
		case name == "":
			name = "(unnamed)"
		}
		if ok && kind == "" {
			kind = api.KindFile
		}
		rows = append(rows, lsRow{
			// Name and Kind are this account's own plaintext, but Visibility is the
			// server's string: sanitize it like any other foreign text.
			ID: it.ID, Name: name, Kind: kind, Size: meta.Size, MinClient: minClient,
			Visibility: foreignText(string(it.Visibility)), AutoSnapshot: it.AutoSnapshot, Version: it.Version,
			CreatedAt: it.CreatedAt, UpdatedAt: it.UpdatedAt,
		})
	}
	sortResourceRows(rows, "name", false)
	return rows, nil
}

func selectResourceRows(rows []lsRow, opts lsOptions) ([]lsRow, error) {
	switch opts.sortBy {
	case "name", "size", "date":
	default:
		return nil, fmt.Errorf("invalid --sort %q (want name, size, or date)", opts.sortBy)
	}
	if opts.kind != "" && opts.kind != api.KindFile && opts.kind != api.KindFolder {
		return nil, fmt.Errorf("invalid --kind %q (want file or folder)", opts.kind)
	}
	if opts.visibility != "" && opts.visibility != string(api.Private) && opts.visibility != string(api.Public) {
		return nil, fmt.Errorf("invalid --visibility %q (want private or public)", opts.visibility)
	}
	needle := strings.ToLower(opts.filter)
	filtered := make([]lsRow, 0, len(rows))
	for _, row := range rows {
		if needle != "" && !strings.Contains(strings.ToLower(row.Name), needle) {
			continue
		}
		if opts.kind != "" && row.Kind != opts.kind {
			continue
		}
		if opts.visibility != "" && row.Visibility != opts.visibility {
			continue
		}
		filtered = append(filtered, row)
	}
	sortResourceRows(filtered, opts.sortBy, opts.reverse)
	return filtered, nil
}

func sortResourceRows(rows []lsRow, by string, reverse bool) {
	descending := by == "size" || by == "date"
	if reverse {
		descending = !descending
	}
	sort.SliceStable(rows, func(i, j int) bool {
		comparison := 0
		switch by {
		case "size":
			comparison = cmp.Compare(rows[i].Size, rows[j].Size)
		case "date":
			comparison = cmp.Compare(rows[i].UpdatedAt, rows[j].UpdatedAt)
		default:
			comparison = strings.Compare(rows[i].Name, rows[j].Name)
		}
		if comparison == 0 {
			comparison = strings.Compare(rows[i].Name, rows[j].Name)
		}
		if comparison == 0 {
			comparison = strings.Compare(rows[i].ID, rows[j].ID)
		}
		if descending {
			return comparison > 0
		}
		return comparison < 0
	})
}

func sizeCell(kind string, size int64) string {
	if kind == api.KindFolder {
		return "-"
	}
	return cliutil.HumanBytes(size)
}
