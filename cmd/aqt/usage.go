// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/cliutil"
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
	storage := cliutil.HumanBytes(u.StorageBytes)
	if u.QuotaBytes > 0 {
		storage = fmt.Sprintf("%s of %s (%.0f%%)",
			storage, cliutil.HumanBytes(u.QuotaBytes), 100*float64(u.StorageBytes)/float64(u.QuotaBytes))
	}
	return printTable(os.Stdout, nil, [][]string{
		{"storage", storage},
		{"resources", strconv.FormatInt(u.Resources, 10)},
		{"snapshots", strconv.FormatInt(u.Snapshots, 10)},
		{"packs", strconv.FormatInt(u.Packs, 10)},
		{"objects", strconv.FormatInt(u.Objects, 10)},
		{"devices", strconv.FormatInt(u.Devices, 10)},
	})
}
