// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func usageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Show your account's storage usage on the server",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runUsage(flagJSON) },
	}
	markJSONSupported(cmd)
	return cmd
}

func runUsage(asJSON bool) error {
	cl, _, err := authedClient()
	if err != nil {
		return err
	}
	u, err := cl.Usage()
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(u)
	}
	storage := humanBytes(u.StorageBytes)
	if u.QuotaBytes > 0 {
		storage = fmt.Sprintf("%s of %s (%.0f%%)",
			storage, humanBytes(u.QuotaBytes), 100*float64(u.StorageBytes)/float64(u.QuotaBytes))
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "storage\t%s\n", storage)
	fmt.Fprintf(w, "resources\t%d\n", u.Resources)
	fmt.Fprintf(w, "snapshots\t%d\n", u.Snapshots)
	fmt.Fprintf(w, "packs\t%d\n", u.Packs)
	fmt.Fprintf(w, "objects\t%d\n", u.Objects)
	fmt.Fprintf(w, "devices\t%d\n", u.Devices)
	return w.Flush()
}
