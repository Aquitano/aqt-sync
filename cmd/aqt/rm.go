package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
)

func rmCmd() *cobra.Command {
	var (
		withSnapshots bool
		yes           bool
	)
	cmd := &cobra.Command{
		Use:   "rm <name-or-id|tracked-path>...",
		Short: "Delete the server-side ciphertext and metadata for one or more resources",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(args, withSnapshots, yes)
		},
	}
	cmd.Flags().BoolVar(&withSnapshots, "with-snapshots", false, "also delete every snapshot of each resource")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

// rmResult is one deleted resource, as reported by `aqt rm --json`.
type rmResult struct {
	ID                 string `json:"id"`
	SnapshotsDeleted   int    `json:"snapshotsDeleted,omitempty"`
	SnapshotsRemaining int    `json:"snapshotsRemaining,omitempty"`
}

func runRemove(refs []string, withSnapshots, assumeYes bool) error {
	if err := requireConfirmable(assumeYes); err != nil {
		return err
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
	items, err := cl.ListResources()
	if err != nil {
		return err
	}
	// Resolve every ref before asking for confirmation, so the prompt names what
	// will actually be deleted rather than echoing unresolved arguments.
	seen := make(map[string]bool, len(refs))
	ids := make([]string, 0, len(refs))
	labels := make([]string, 0, len(refs))
	for _, ref := range refs {
		id, ok, err := trackedResourceID(ref)
		if !ok {
			id, err = resolveOwnedResourceIDFromItems(items, mk, ref)
		}
		if err != nil {
			return err
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
		labels = append(labels, resourceLabel(items, mk, id))
	}
	if !flagJSON {
		for _, label := range labels {
			fmt.Fprintf(os.Stderr, "will delete %s\n", label)
		}
	}
	prompt := fmt.Sprintf("Permanently delete %d resource(s) from the server? [y/N] ", len(ids))
	if withSnapshots {
		prompt = fmt.Sprintf("Permanently delete %d resource(s) AND every snapshot of them? [y/N] ", len(ids))
	}
	if err := confirmDestructive(prompt, assumeYes); err != nil {
		return err
	}
	results := make([]rmResult, 0, len(ids))
	for _, id := range ids {
		if err := cl.DeleteResource(id); err != nil {
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours); run `aqt ls` to list yours", id)
			}
			return err
		}
		result := rmResult{ID: id}
		if !flagJSON {
			fmt.Fprintf(os.Stderr, "deleted %s\n", id)
		}
		// Snapshots pin the resource's ciphertext independently of the live row, so a
		// plain rm leaves every snapshotted version fetchable. Listing after the delete
		// closes the race where the scheduled snapshot job pins the resource again
		// between a list and the delete; snapshot rows outlive their resource.
		snaps, err := cl.ListSnapshots(id)
		if err != nil {
			return fmt.Errorf("list snapshots of %s: %w", id, err)
		}
		switch {
		case len(snaps) == 0:
		case !withSnapshots:
			result.SnapshotsRemaining = len(snaps)
			if !flagJSON {
				fmt.Fprintf(os.Stderr, "note: %d snapshot(s) still retain %s's data; list them with `aqt snapshot list --id %s`, or delete with `aqt snapshot prune`\n", len(snaps), id, id)
			}
		default:
			for _, sn := range snaps {
				if err := cl.DeleteSnapshot(sn.ID); err != nil {
					return fmt.Errorf("delete snapshot %s of %s: %w", sn.ID, id, err)
				}
			}
			result.SnapshotsDeleted = len(snaps)
			if !flagJSON {
				fmt.Fprintf(os.Stderr, "deleted %d snapshot(s) of %s\n", len(snaps), id)
			}
		}
		results = append(results, result)
	}
	if flagJSON {
		return printJSON(results)
	}
	return nil
}
