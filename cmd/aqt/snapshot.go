package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func snapshotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create, browse, and restore point-in-time snapshots",
		Long: "Snapshots are immutable, point-in-time copies of a tracked folder or file, " +
			"pinned server-side so a later sync (or a mistaken delete) cannot reclaim them. " +
			"They are account-global: any of your devices can browse and restore them.",
	}
	cmd.AddCommand(snapshotCreateCmd(), snapshotListCmd(), snapshotRestoreCmd(), snapshotExportCmd(), snapshotPruneCmd(), snapshotAutoCmd())
	return cmd
}

// --- create ---

func snapshotCreateCmd() *cobra.Command {
	var (
		id    string
		label string
	)
	cmd := &cobra.Command{
		Use:   "create [dir]",
		Short: "Snapshot a tracked folder's (or a resource's) current state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			resourceID, err := resolveResourceID(dirArg(args), id)
			if err != nil {
				return err
			}
			// A label is sealed under the resource content key here, so the server stores
			// only ciphertext; this needs the key, so it is the one path that unlocks.
			var sealed *crypto.SealedBlob
			if label != "" {
				if sealed, err = sealSnapshotLabel(cl, prof, resourceID, label); err != nil {
					return err
				}
			}
			info, err := cl.CreateSnapshot(resourceID, sealed)
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours)", resourceID)
			}
			if err != nil {
				return err
			}
			if flagJSON {
				return printJSON(info)
			}
			fmt.Printf("snapshot %s of %s (version %d)\n", info.ID, resourceID, info.Version)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "snapshot this resource id directly (e.g. a pushed file) instead of a tracked dir")
	cmd.Flags().StringVarP(&label, "label", "l", "", "attach a label, encrypted on this machine before upload")
	return cmd
}

// sealSnapshotLabel encrypts a snapshot label under the resource's content key, so
// the server stores it as opaque ciphertext that a later browse decrypts the same
// way it decrypts the name. It fetches the resource to recover its wrapped key, then
// unwraps it with the master key.
func sealSnapshotLabel(cl *client.Client, prof *identity.Profile, resourceID, label string) (*crypto.SealedBlob, error) {
	res, err := cl.GetResource(resourceID)
	if errors.Is(err, client.ErrNotFound) {
		return nil, fmt.Errorf("resource %s not found (or not yours)", resourceID)
	}
	if err != nil {
		return nil, err
	}
	if res.WrappedKey == nil {
		return nil, errors.New("cannot label this snapshot: the resource is public (no owner key to seal under)")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return nil, err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return nil, fmt.Errorf("unwrap resource key: %w", err)
	}
	defer ck.Wipe()
	sealed, err := crypto.Seal([]byte(label), ck, crypto.AADSnapshotLabel)
	if err != nil {
		return nil, err
	}
	return &sealed, nil
}

// --- list ---

func snapshotListCmd() *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:     "list [dir]",
		Aliases: []string{"ls"},
		Short:   "List snapshots, newest first, with decrypted names",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			// A bare `snapshot list` lists every snapshot; a dir or --id scopes it to one
			// resource's history.
			resourceID := id
			if resourceID == "" && len(args) > 0 {
				if resourceID, err = resolveResourceID(args[0], ""); err != nil {
					return err
				}
			}
			snaps, err := cl.ListSnapshots(resourceID)
			if err != nil {
				return err
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			defer mk.Wipe()
			if flagJSON {
				return printJSON(snapshotRows(snaps, mk))
			}
			if len(snaps) == 0 {
				fmt.Fprintln(os.Stderr, "no snapshots yet")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "CREATED\tNAME\tLABEL\tVERSION\tSNAPSHOT-ID\tRESOURCE")
			for _, r := range snapshotRows(snaps, mk) {
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", r.Created, r.Name, r.Label, r.Version, r.ID, r.ResourceID)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "list snapshots of this resource id")
	return cmd
}

// snapshotRow is one snapshot as shown by `aqt snapshot list`, with its name
// decrypted locally from the copied sealed metadata.
type snapshotRow struct {
	ID         string `json:"id"`
	ResourceID string `json:"resourceId"`
	Name       string `json:"name"`
	Label      string `json:"label,omitempty"`
	Version    int    `json:"version"`
	Created    string `json:"created"`
	CreatedAt  int64  `json:"createdAt"`
}

func snapshotRows(snaps []api.SnapshotInfo, mk crypto.MasterKey) []snapshotRow {
	rows := make([]snapshotRow, 0, len(snaps))
	for _, s := range snaps {
		name, label := snapshotNameLabel(s, mk)
		rows = append(rows, snapshotRow{
			ID: s.ID, ResourceID: s.ResourceID, Name: name, Label: label, Version: s.Version,
			Created: formatTime(s.CreatedAt), CreatedAt: s.CreatedAt,
		})
	}
	return rows
}

// snapshotNameLabel decrypts the resource name and the optional user label a
// snapshot carries, unwrapping the content key once for both (the same key both
// were sealed under). A snapshot that cannot be decrypted is still listed, with a
// placeholder name and no label.
func snapshotNameLabel(s api.SnapshotInfo, mk crypto.MasterKey) (name, label string) {
	name = "(unreadable)"
	if s.WrappedKey == nil {
		return name, ""
	}
	ck, err := crypto.UnwrapKey(*s.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return name, ""
	}
	defer ck.Wipe()
	if plain, err := crypto.Open(s.EncryptedMeta, ck, crypto.AADMeta); err == nil {
		var m api.Metadata
		if json.Unmarshal(plain, &m) == nil {
			if name = m.Name; name == "" {
				name = "(unnamed)"
			}
		}
	}
	if s.EncryptedLabel != nil {
		if plain, err := crypto.Open(*s.EncryptedLabel, ck, crypto.AADSnapshotLabel); err == nil {
			label = string(plain)
		}
	}
	return name, label
}

// --- restore ---

func snapshotRestoreCmd() *cobra.Command {
	var (
		into    string
		inPlace bool
		dir     string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "restore <snapshot-id>",
		Short: "Restore a snapshot side-by-side (default) or in place",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if inPlace && into != "" {
				return errors.New("--in-place and --into are mutually exclusive")
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			snap, err := cl.GetSnapshot(args[0])
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("snapshot %s not found (or not yours)", args[0])
			}
			if err != nil {
				return err
			}
			if inPlace {
				return restoreInPlace(cl, prof, snap, dir, yes)
			}
			dest := into
			if dest == "" {
				dest = fmt.Sprintf("aqt-restore-%s", snap.Snapshot.ID)
			}
			abs, err := filepath.Abs(dest)
			if err != nil {
				return err
			}
			meta, err := reconstructSnapshot(cl, prof, snap, abs)
			if err != nil {
				return err
			}
			fmt.Printf("restored %q (version %d) into %s\n", meta.Name, snap.Snapshot.Version, abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&into, "into", "", "restore side-by-side into this (new) directory")
	cmd.Flags().BoolVar(&inPlace, "in-place", false, "overwrite the live tracked folder and re-sync to every device")
	cmd.Flags().StringVar(&dir, "dir", ".", "the tracked folder to roll back (with --in-place)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the in-place confirmation prompt")
	return cmd
}

// restoreInPlace rolls a tracked folder back to a snapshot and pushes the result to
// every device. It reconstructs the snapshot into a staging dir first, so a failed
// reconstruction never leaves the live folder half-overwritten, then swaps it in and
// runs a normal sync (force: an explicit rollback wins any divergence).
func restoreInPlace(cl *client.Client, prof *identity.Profile, snap api.GetSnapshotResponse, dir string, assumeYes bool) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	st, err := loadState(root)
	if err != nil {
		return fmt.Errorf("read folder state: %w", err)
	}
	if st.ID != snap.Snapshot.ResourceID {
		return fmt.Errorf("snapshot belongs to resource %s, but %s tracks %s; "+
			"restore it side-by-side with --into instead", snap.Snapshot.ResourceID, root, st.ID)
	}
	if !assumeYes {
		ok, err := promptYesNo(fmt.Sprintf("Roll %s back to snapshot %s and push to every device? "+
			"Current contents are replaced. [y/N] ", root, snap.Snapshot.ID), false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
	}

	staging, err := os.MkdirTemp(filepath.Dir(root), ".aqt-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	meta, err := reconstructSnapshot(cl, prof, snap, staging)
	if err != nil {
		return err
	}
	if meta.Kind != api.KindFolder {
		return errors.New("in-place restore is only for tracked folders; use --into for a single file")
	}
	if err := swapTree(root, staging); err != nil {
		return fmt.Errorf("swap restored tree into place: %w", err)
	}
	fmt.Fprintln(os.Stderr, "rolled back; syncing to propagate...")
	return runSync(root, syncOptions{force: true})
}

// swapTree replaces root's contents (everything but the .aqt control dir) with
// staging's, then removes the now-empty staging dir. Both live under the same parent
// so the renames stay on one filesystem.
func swapTree(root, staging string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == syncengine.ControlDir {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
			return err
		}
	}
	staged, err := os.ReadDir(staging)
	if err != nil {
		return err
	}
	for _, e := range staged {
		if err := os.Rename(filepath.Join(staging, e.Name()), filepath.Join(root, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// --- export ---

func snapshotExportCmd() *cobra.Command {
	var to string
	cmd := &cobra.Command{
		Use:   "export <snapshot-id>",
		Short: "Decrypt a snapshot to a plaintext tree for offsite backup",
		Long: "Reconstructs a snapshot and writes it as plaintext to --to. Decryption happens " +
			"entirely on this machine; the server never sees a key. The output is NOT encrypted, " +
			"so it leaves aqt's zero-knowledge boundary: store it somewhere you trust.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if to == "" {
				return errors.New("--to <dir> is required")
			}
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			snap, err := cl.GetSnapshot(args[0])
			if errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("snapshot %s not found (or not yours)", args[0])
			}
			if err != nil {
				return err
			}
			abs, err := filepath.Abs(to)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "warning: writing DECRYPTED plaintext to %s (outside aqt's encryption)\n", abs)
			meta, err := reconstructSnapshot(cl, prof, snap, abs)
			if err != nil {
				return err
			}
			fmt.Printf("exported %q (version %d) to %s\n", meta.Name, snap.Snapshot.Version, abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "write the decrypted plaintext tree here (required)")
	return cmd
}

// --- prune ---

func snapshotPruneCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "prune <snapshot-id>...",
		Short: "Delete snapshots; objects no other snapshot or resource needs are reclaimed",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, _, err := authedClient()
			if err != nil {
				return err
			}
			if !yes {
				ok, err := promptYesNo(fmt.Sprintf("Permanently delete %d snapshot(s)? [y/N] ", len(args)), false)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}
			for _, id := range args {
				if err := cl.DeleteSnapshot(id); errors.Is(err, client.ErrNotFound) {
					return fmt.Errorf("snapshot %s not found (or not yours)", id)
				} else if err != nil {
					return err
				}
				fmt.Printf("pruned %s\n", id)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

// --- auto (scheduled opt-out) ---

func snapshotAutoCmd() *cobra.Command {
	var (
		id  string
		off bool
	)
	cmd := &cobra.Command{
		Use:   "auto [dir]",
		Short: "Toggle whether the scheduled job snapshots a tracked root (default: on)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, _, err := authedClient()
			if err != nil {
				return err
			}
			resourceID, err := resolveResourceID(dirArg(args), id)
			if err != nil {
				return err
			}
			if err := cl.SetAutoSnapshot(resourceID, !off); errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("resource %s not found (or not yours)", resourceID)
			} else if err != nil {
				return err
			}
			state := "enabled"
			if off {
				state = "disabled"
			}
			fmt.Printf("scheduled snapshots %s for %s\n", state, resourceID)
			return nil
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "target this resource id instead of a tracked dir")
	cmd.Flags().BoolVar(&off, "off", false, "exclude this root from the scheduled job")
	return cmd
}

// --- shared ---

// reconstructSnapshot decrypts a snapshot client-side and materializes it under
// destDir, reusing the same paths as clone/pull: a folder is untarred or streamed
// from its objects, a single file is written by its name. It returns the decrypted
// metadata. The server only ever returned ciphertext and the wrapped key.
func reconstructSnapshot(cl *client.Client, prof *identity.Profile, snap api.GetSnapshotResponse, destDir string) (api.Metadata, error) {
	info := snap.Snapshot
	if info.WrappedKey == nil {
		return api.Metadata{}, errors.New("snapshot has no owner key (the resource was public); cannot restore")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return api.Metadata{}, err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*info.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.Metadata{}, fmt.Errorf("unwrap snapshot key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(info.EncryptedMeta, ck)
	if err != nil {
		return api.Metadata{}, err
	}
	res := api.GetResourceResponse{
		ID:            info.ResourceID,
		Visibility:    api.Private,
		Blob:          snap.Blob,
		EncryptedMeta: info.EncryptedMeta,
		WrappedKey:    info.WrappedKey,
		Version:       info.Version,
	}
	if meta.Kind == api.KindFolder {
		if err := ensureEmptyDir(destDir); err != nil {
			return meta, err
		}
		if _, err := materializeClone(cl, destDir, res, ck, meta); err != nil {
			return meta, err
		}
		return meta, nil
	}
	// A single file (inline or streamed): write it under destDir by its name.
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return meta, err
	}
	dest := filepath.Join(destDir, safeOutputName(meta.Name))
	if meta.Streamed {
		root, err := syncengine.OpenFileRoot(res.Blob, ck)
		if err != nil {
			return meta, fmt.Errorf("decrypt file root: %w", err)
		}
		src, err := newPackSource(cl, root.ChunkIDs())
		if err != nil {
			return meta, err
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return meta, err
		}
		if err := syncengine.WriteFileRoot(f, root, src.get); err != nil {
			f.Close()
			_ = os.Remove(dest)
			return meta, err
		}
		return meta, f.Close()
	}
	plain, err := crypto.Open(res.Blob, ck, crypto.AADBlob)
	if err != nil {
		return meta, fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	return meta, os.WriteFile(dest, plain, 0o600)
}

// resolveResourceID maps a tracked-folder path (or an explicit --id) to a resource
// id. An explicit id wins; otherwise the nearest .aqt root's recorded id is used.
func resolveResourceID(dir, id string) (string, error) {
	if id != "" {
		return id, nil
	}
	root, err := trackedRoot(dir)
	if err != nil {
		return "", err
	}
	st, err := loadState(root)
	if err != nil {
		return "", fmt.Errorf("read folder state: %w", err)
	}
	if st.ID == "" {
		return "", fmt.Errorf("%s has no synced resource yet; run `aqt sync` first", root)
	}
	return st.ID, nil
}

func formatTime(unix int64) string {
	if unix == 0 {
		return "-"
	}
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04")
}
