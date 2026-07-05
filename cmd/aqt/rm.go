package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
)

func rmCmd() *cobra.Command {
	var withSnapshots bool
	cmd := &cobra.Command{
		Use:   "rm <id>...",
		Short: "Delete the server-side ciphertext and metadata for one or more resources",
		Args:  cobra.MinimumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runRemove(args, withSnapshots) },
	}
	cmd.Flags().BoolVar(&withSnapshots, "with-snapshots", false, "also delete every snapshot of each resource")
	return cmd
}

func runRemove(refs []string, withSnapshots bool) error {
	cl, _, err := authedClient()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		id, _, _ := parseRef(ref)
		if err := cl.DeleteResource(id); err != nil {
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours); run `aqt ls` to list yours", id)
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "deleted %s\n", id)
		// Snapshots pin the resource's ciphertext independently of the live row, so a
		// plain rm leaves every snapshotted version fetchable. Listing after the delete
		// closes the race where the scheduled snapshot job pins the resource again
		// between a list and the delete; snapshot rows outlive their resource.
		snaps, err := cl.ListSnapshots(id)
		if err != nil {
			return fmt.Errorf("list snapshots of %s: %w", id, err)
		}
		if len(snaps) == 0 {
			continue
		}
		if !withSnapshots {
			fmt.Fprintf(os.Stderr, "note: %d snapshot(s) still retain %s's data; list them with `aqt snapshot list --id %s`, or delete with `aqt snapshot prune`\n", len(snaps), id, id)
			continue
		}
		for _, sn := range snaps {
			if err := cl.DeleteSnapshot(sn.ID); err != nil {
				return fmt.Errorf("delete snapshot %s of %s: %w", sn.ID, id, err)
			}
		}
		fmt.Fprintf(os.Stderr, "deleted %d snapshot(s) of %s\n", len(snaps), id)
	}
	return nil
}
