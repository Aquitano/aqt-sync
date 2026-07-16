package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// checkpointCmd creates a named, anchored snapshot: sugar for `snapshot create`
// that seals the name as the label and pins the result against retention.
func checkpointCmd() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "checkpoint <name> [dir]",
		Short: "Save a named, anchored snapshot that retention never prunes",
		Long: "Snapshot a tracked folder's current state under a sealed name and anchor it, so\n" +
			"retention (`snapshot prune`, the scheduled job) can never reclaim it. Restore it\n" +
			"later by name with `aqt restore <name>`. The name is encrypted on this machine\n" +
			"before upload, exactly like a snapshot label.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return errors.New("checkpoint name must not be empty")
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			resourceID, err := resolveResourceID(checkpointDir(args), id)
			if err != nil {
				return err
			}
			sealed, err := sealSnapshotLabel(cl, prof, resourceID, name)
			if err != nil {
				return err
			}
			info, err := cl.CreateSnapshot(resourceID, sealed, true)
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours)", resourceID)
			}
			if err != nil {
				return err
			}
			// Fail closed: an older server silently ignores the anchor field and returns an
			// unanchored (prunable) snapshot, which would be a checkpoint in name only. Drop
			// it best-effort so no half-checkpoint lingers, and report the server is too old.
			if !info.Anchored {
				if delErr := cl.DeleteSnapshot(info.ID); delErr != nil {
					return fmt.Errorf("server did not anchor the checkpoint (it is too old to support anchors), "+
						"and the unanchored snapshot %s could not be cleaned up (%v); prune it manually and upgrade the server", info.ID, delErr)
				}
				return errors.New("server did not anchor the checkpoint (it is too old to support anchors); nothing was kept — upgrade the server")
			}
			if flagJSON {
				return printJSON(info)
			}
			fmt.Printf("checkpoint %q saved as snapshot %s (anchored, version %d)\n", name, info.ID, info.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "checkpoint this resource id directly instead of a tracked dir")
	markJSONSupported(cmd)
	return cmd
}

// checkpointDir returns the optional [dir] argument that follows the name, defaulting
// to the current directory.
func checkpointDir(args []string) string {
	if len(args) == 2 {
		return args[1]
	}
	return "."
}

// restoreCmd resolves a checkpoint by its sealed name (or any snapshot by id) and
// restores it — side-by-side by default, since a restore that overwrites the live
// tree must be the explicit choice (--in-place), never the default. It replaces the
// old `snapshot restore`, whose opposite default made the two restores the most
// dangerous surprise in the CLI.
func restoreCmd() *cobra.Command {
	var (
		id      string
		into    string
		inPlace bool
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "restore <name-or-id> [dir]",
		Short: "Restore a checkpoint by name or a snapshot by id (side-by-side by default)",
		Long: "Look up <name-or-id> against the tracked folder's checkpoint names first, then as\n" +
			"a snapshot id, and restore it. By default the snapshot is materialized side-by-side\n" +
			"into a new directory (aqt-restore-<snapshot-id>, or --into). --in-place instead\n" +
			"rolls the live tracked folder back (with a confirmation prompt) and re-syncs the\n" +
			"rollback to every device.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if inPlace && into != "" {
				return errors.New("--in-place and --into are mutually exclusive")
			}
			dir := "."
			if len(args) == 2 {
				dir = args[1]
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			snap, err := resolveRestoreTarget(cl, prof, args[0], dir, id)
			if err != nil {
				return err
			}
			if inPlace {
				return restoreInPlace(cl, prof, snap, dir, yes)
			}
			dest := into
			if dest == "" {
				dest = "aqt-restore-" + snap.Snapshot.ID
			}
			abs, err := filepath.Abs(dest)
			if err != nil {
				return err
			}
			meta, err := reconstructSnapshot(cl, prof, snap, abs)
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(map[string]any{
					"snapshotId": snap.Snapshot.ID, "name": meta.Name,
					"version": snap.Snapshot.Version, "into": abs,
				})
			}
			fmt.Printf("restored %q (version %d) into %s\n", meta.Name, snap.Snapshot.Version, abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "scope the name lookup to this resource id instead of a tracked dir")
	cmd.Flags().StringVar(&into, "into", "", "restore side-by-side into this (new) directory (default aqt-restore-<snapshot-id>)")
	cmd.Flags().BoolVar(&inPlace, "in-place", false, "roll the live tracked folder back and re-sync it to every device")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the in-place confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

// resolveRestoreTarget maps a name-or-id to a fetched snapshot: it matches the token
// against the tracked folder's decrypted checkpoint names first, then falls back to
// treating it as a snapshot id. A name that matches several snapshots errors with the
// candidates rather than guessing.
func resolveRestoreTarget(cl *client.Client, prof *identity.Profile, token, dir, id string) (api.GetSnapshotResponse, error) {
	resourceID, resErr := resolveResourceID(dir, id)
	if resErr == nil {
		matchedID, err := matchCheckpointLabel(cl, prof, resourceID, token)
		if err != nil {
			return api.GetSnapshotResponse{}, err
		}
		if matchedID != "" {
			token = matchedID
		}
	}

	snap, err := cl.GetSnapshot(token)
	if errors.Is(err, client.ErrNotFound) {
		if resErr == nil {
			return api.GetSnapshotResponse{}, fmt.Errorf("no checkpoint named %q, and no snapshot with id %q", token, token)
		}
		return api.GetSnapshotResponse{}, fmt.Errorf("snapshot %s not found (or not yours)", token)
	}
	if err != nil {
		return api.GetSnapshotResponse{}, err
	}
	return snap, nil
}

// matchCheckpointLabel returns the id of the snapshot in resourceID whose decrypted
// label equals name, or "" when none matches (the caller then tries the token as an
// id). When several match, an anchored one wins; if that is still ambiguous it errors
// with the candidate ids and timestamps.
func matchCheckpointLabel(cl *client.Client, prof *identity.Profile, resourceID, name string) (string, error) {
	snaps, err := cl.ListSnapshots(resourceID)
	if err != nil {
		return "", err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return "", err
	}
	defer mk.Wipe()

	var cands []api.SnapshotInfo
	for _, s := range snaps {
		if _, label := snapshotNameLabel(s, mk); label == name {
			cands = append(cands, s)
		}
	}
	switch len(cands) {
	case 0:
		return "", nil
	case 1:
		return cands[0].ID, nil
	}
	// Prefer anchored checkpoints: a name reused across an anchored checkpoint and
	// ordinary labeled snapshots resolves to the checkpoint the user pinned.
	var anchored []api.SnapshotInfo
	for _, s := range cands {
		if s.Anchored {
			anchored = append(anchored, s)
		}
	}
	if len(anchored) == 1 {
		return anchored[0].ID, nil
	}
	pick := cands
	if len(anchored) > 1 {
		pick = anchored
	}
	return "", ambiguousCheckpointError(name, pick)
}

func ambiguousCheckpointError(name string, cands []api.SnapshotInfo) error {
	var b strings.Builder
	fmt.Fprintf(&b, "checkpoint %q matches %d snapshots; pass a snapshot id instead:", name, len(cands))
	for _, s := range cands {
		anchor := ""
		if s.Anchored {
			anchor = "  (anchored)"
		}
		fmt.Fprintf(&b, "\n  %s  %s%s", s.ID, formatTime(s.CreatedAt), anchor)
	}
	return errors.New(b.String())
}
