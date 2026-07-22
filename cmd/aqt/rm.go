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
	knownResources := make(map[string]bool, len(items))
	// The listing already carries every version, so the delete pins itself from it
	// rather than re-fetching each resource (which, for an inline one, would download
	// the whole ciphertext to read an integer).
	versions := make(map[string]int, len(items))
	for _, item := range items {
		knownResources[item.ID] = true
		versions[item.ID] = item.Version
	}
	// Resolve and inspect every target before asking for confirmation or mutating.
	seen := make(map[string]bool, len(refs))
	ids := make([]string, 0, len(refs))
	labels := make([]string, 0, len(refs))
	resolveFailures := make(map[int]error)
	for _, ref := range refs {
		id, ok, err := trackedResourceID(ref)
		if !ok {
			id, err = resolveOwnedResourceIDFromItems(items, mk, ref)
		}
		if err != nil {
			resolveFailures[len(ids)] = err
			ids = append(ids, ref)
			labels = append(labels, ref)
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
		labels = append(labels, resourceLabel(items, mk, id))
	}
	for i, id := range ids {
		if resolveFailures[i] == nil && !knownResources[id] {
			resolveFailures[i] = fmt.Errorf("resource %s not found (or not yours); run `aqt ls` to list yours", id)
		}
	}
	results := newBatchResults(ids)
	if len(resolveFailures) > 0 {
		err = failBatchPreflight(results, resolveFailures)
		return finishDestructiveBatch(destructiveBatchReport{Results: results}, "delete", err)
	}

	// Preflight only refuses anchored snapshots; the list the deletes actually work
	// from is re-fetched after each resource is gone, so a snapshot pinned in between
	// is not missed.
	if withSnapshots {
		failures := make(map[int]error)
		for i, id := range ids {
			snaps, listErr := cl.ListSnapshots(id)
			if listErr != nil {
				failures[i] = fmt.Errorf("list snapshots of %s: %w", id, listErr)
				continue
			}
			for _, snapshot := range snaps {
				if snapshot.Anchored {
					failures[i] = fmt.Errorf("resource %s has anchored snapshot %s; unanchor it before deleting with --with-snapshots", id, snapshot.ID)
					break
				}
			}
		}
		if len(failures) > 0 {
			err = failBatchPreflight(results, failures)
			return finishDestructiveBatch(destructiveBatchReport{Results: results}, "delete", err)
		}
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
	for i, id := range ids {
		deleteErr := cl.DeleteResourceVersion(id, versions[id])
		if deleteErr != nil {
			if errors.Is(deleteErr, client.ErrNotFound) {
				deleteErr = fmt.Errorf("resource %s not found (or not yours); run `aqt ls` to list yours", id)
			}
			err = markBatchFailure(results, i, deleteErr)
			return finishDestructiveBatch(destructiveBatchReport{Results: results}, "delete", err)
		}
		// Snapshots pin the resource's ciphertext independently of the live row, so a
		// plain rm leaves every snapshotted version fetchable. Listing after the delete
		// closes the race where the scheduled snapshot job pins the resource again
		// between a list and the delete; snapshot rows outlive their resource. That
		// applies just as much to --with-snapshots, which would otherwise leave the
		// newly-pinned snapshot behind and still report success.
		snaps, listErr := cl.ListSnapshots(id)
		if listErr != nil {
			err = markBatchFailure(results, i, fmt.Errorf("list snapshots of %s: %w", id, listErr))
			return finishDestructiveBatch(destructiveBatchReport{Results: results}, "delete", err)
		}
		// The resource itself is already gone; from here on a failure must not be
		// reported as a failed delete, or a retry hits "resource not found".
		switch {
		case len(snaps) == 0:
		case !withSnapshots:
			results[i].SnapshotsRemaining = len(snaps)
			if !flagJSON {
				fmt.Fprintf(os.Stderr, "note: %d snapshot(s) still retain %s's data; list them with `aqt snapshot list --id %s`, or delete with `aqt snapshot prune`\n", len(snaps), id, id)
			}
		default:
			for _, sn := range snaps {
				if snapErr := cl.DeleteSnapshot(sn.ID); snapErr != nil {
					results[i].SnapshotsRemaining = len(snaps) - results[i].SnapshotsDeleted
					results[i].Status = batchSucceeded
					err = fmt.Errorf("deleted resource %s, but snapshot %s could not be deleted: %w; remove the rest with `aqt snapshot prune --id %s`", id, sn.ID, snapErr, id)
					return finishDestructiveBatch(destructiveBatchReport{Results: results}, "delete", err)
				}
				results[i].SnapshotsDeleted++
			}
		}
		results[i].Status = batchSucceeded
	}
	return finishDestructiveBatch(destructiveBatchReport{Complete: true, Results: results}, "deleted", nil)
}
