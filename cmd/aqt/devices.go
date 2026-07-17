package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
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
	return runDevicesRemoveWithClient(cl, prof.DeviceID, ids, func() error {
		return identity.ClearSession(firstNonEmpty(flagProfile, identity.DefaultProfile))
	})
}

type deviceRemoveClient interface {
	ListDevices() ([]api.Device, error)
	DeleteDevice(string) error
}

func runDevicesRemoveWithClient(cl deviceRemoveClient, currentID string, requested []string, clearSession func() error) error {
	devices, err := cl.ListDevices()
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(devices))
	for _, device := range devices {
		known[device.ID] = true
	}

	ids := append([]string(nil), requested...)
	for i, id := range ids {
		if id == currentID && i != len(ids)-1 {
			copy(ids[i:], ids[i+1:])
			ids[len(ids)-1] = id
			break
		}
	}
	results := newBatchResults(ids)
	failures := map[int]error{}
	for i, id := range ids {
		if !known[id] {
			failures[i] = fmt.Errorf("device %s not found (or not yours); run `aqt devices` to list yours", id)
		}
	}
	if len(failures) > 0 {
		err = failBatchPreflight(results, failures)
		return finishDestructiveBatch(destructiveBatchReport{Results: results}, "revoke", err)
	}

	for i, id := range ids {
		deleteErr := cl.DeleteDevice(id)
		if id == currentID {
			// Once the self-revoke request is sent its outcome is uncertain on any
			// transport error. Discard the local session even if the response is lost.
			deleteErr = errors.Join(deleteErr, clearSession())
		}
		if deleteErr != nil {
			if errors.Is(deleteErr, client.ErrNotFound) {
				deleteErr = fmt.Errorf("device %s not found (or not yours); run `aqt devices` to list yours", id)
			}
			err = markBatchFailure(results, i, deleteErr)
			return finishDestructiveBatch(destructiveBatchReport{Results: results}, "revoke", err)
		}
		results[i].Status = batchSucceeded
	}
	return finishDestructiveBatch(destructiveBatchReport{Complete: true, Results: results}, "revoked", nil)
}
