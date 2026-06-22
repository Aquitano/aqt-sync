package main

import (
	"fmt"
	"text/tabwriter"
	"os"

	"github.com/spf13/cobra"
)

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List your resources",
		// v1 lists ids, visibility, and version. Decrypting the (encrypted)
		// names would require unlocking and the per-resource wrapped keys; that
		// is a follow-up (DESIGN.md section 5).
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, _, err := authedClient()
			if err != nil {
				return err
			}
			items, err := cl.ListResources()
			if err != nil {
				return err
			}
			if len(items) == 0 {
				fmt.Fprintln(os.Stderr, "no resources yet")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tVISIBILITY\tVERSION")
			for _, it := range items {
				fmt.Fprintf(w, "%s\t%s\t%d\n", it.ID, it.Visibility, it.Version)
			}
			return w.Flush()
		},
	}
}
