package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func devicesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "devices",
		Short: "List or revoke the devices attached to your account",
		Args:  cobra.NoArgs,
		// Bare `aqt devices` lists; `aqt devices ls|rm` use the subcommands.
		RunE: func(cmd *cobra.Command, args []string) error { return runDevicesList(flagJSON) },
	}
	cmd.AddCommand(devicesLsCmd(), devicesRmCmd())
	markJSONSupported(cmd)
	return cmd
}

func devicesLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List attached devices",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runDevicesList(flagJSON) },
	}
	markJSONSupported(cmd)
	return cmd
}

func devicesRmCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rm <device-id>...",
		Short: "Revoke one or more devices",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := confirmDestructive(fmt.Sprintf("Revoke %d device(s)? A revoked device must re-login. [y/N] ", len(args)), yes); err != nil {
				return err
			}
			return runDevicesRemove(args)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

func runDevicesList(asJSON bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	devices, err := cl.ListDevices()
	if err != nil {
		return err
	}
	for i := range devices {
		devices[i].Current = devices[i].ID == prof.DeviceID
	}
	if asJSON {
		return printJSON(devices)
	}
	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "no devices")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\t")
	for _, d := range devices {
		marker := ""
		if d.Current {
			marker = "(this device)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", d.ID, d.Name, marker)
	}
	return w.Flush()
}

func runDevicesRemove(ids []string) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	revokedSelf := false
	for _, id := range ids {
		if id == prof.DeviceID {
			revokedSelf = true
		}
		if err := cl.DeleteDevice(id); err != nil {
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("device %s not found (or not yours); run `aqt devices` to list yours", id)
			}
			return err
		}
		if !flagJSON {
			fmt.Fprintf(os.Stderr, "revoked %s\n", id)
		}
	}
	// Revoking this device invalidated its own token, so drop the now-useless
	// cached key to match (the profile stays, so `aqt login` can re-attach).
	if revokedSelf {
		if err := identity.ClearSession(firstNonEmpty(flagProfile, identity.DefaultProfile)); err != nil {
			return err
		}
		if !flagJSON {
			fmt.Fprintln(os.Stderr, "revoked the current device; run `aqt login` to re-attach this machine")
		}
	}
	if flagJSON {
		return printJSON(map[string]any{"revoked": ids, "revokedSelf": revokedSelf})
	}
	return nil
}
