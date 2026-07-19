package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/gitremote"
)

func repoCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "repo", Short: "Manage encrypted Git remotes", Args: cobra.NoArgs}
	cmd.AddCommand(repoCreateCmd(), repoListCmd(), repoInfoCmd(), repoGCCmd(), repoRestoreCmd(), repoRemoveCmd())
	return cmd
}

func repoRestoreCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "restore <snapshot-id>",
		Short: "Restore an encrypted Git remote from a pre-compaction snapshot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoRestore(args[0], yes, flagJSON)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

func repoGCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc <name-or-id>",
		Short: "Compact an encrypted Git remote into one full bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoGC(args[0], flagJSON)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func repoRemoveCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "rm <name-or-id>",
		Aliases: []string{"remove"},
		Short:   "Delete an encrypted Git remote",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoRemove(args[0], yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

func repoCreateCmd() *cobra.Command {
	compactAt := gitremote.DefaultCompactAt
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an empty encrypted Git remote",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoCreate(args[0], compactAt)
		},
	}
	cmd.Flags().IntVar(&compactAt, "compact-at", gitremote.DefaultCompactAt, "compact the bundle chain at this many bundles")
	markJSONSupported(cmd)
	return cmd
}

type repoRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Bundles    int    `json:"bundles"`
	Size       int64  `json:"size"`
	Version    int    `json:"version"`
	Generation int    `json:"generation"`
	CompactAt  int    `json:"compactAt"`
	UpdatedAt  int64  `json:"updatedAt,omitempty"`
}

type repoInfoRow struct {
	repoRow
	Head          string            `json:"head,omitempty"`
	Refs          map[string]string `json:"refs"`
	ObjectFormat  string            `json:"objectFormat,omitempty"`
	AutoSnapshot  bool              `json:"autoSnapshot"`
	SnapshotCount int               `json:"snapshotCount"`
}

// gitRemoteItems centralizes the server-visible discriminator for encrypted Git
// remotes. Metadata kind is still verified after decryption at each trust boundary.
func gitRemoteItems(items []api.ResourceListItem) []api.ResourceListItem {
	remotes := make([]api.ResourceListItem, 0, len(items))
	for _, item := range items {
		if item.CompactAt > 0 {
			remotes = append(remotes, item)
		}
	}
	return remotes
}

func repoListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List encrypted Git remotes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoList(flagJSON)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func repoInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <name-or-id>",
		Short: "Show refs and bundle-chain state for an encrypted Git remote",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRepoInfo(args[0], flagJSON)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func runRepoCreate(name string, compactAt int) error {
	if name == "" {
		return errors.New("repository name cannot be empty")
	}
	if compactAt < 1 {
		return errors.New("--compact-at must be at least 1")
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
	for _, item := range gitRemoteItems(items) {
		if meta, ok := openMetadata(item, mk); ok && meta.Kind == api.KindGitRemote && meta.Name == name {
			return fmt.Errorf("git remote %q already exists (%s)", name, item.ID)
		}
	}

	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer ck.Wipe()
	rootBlob, err := gitremote.SealRefsRoot(gitremote.NewRefsRoot(), ck, "")
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: name, Kind: api.KindGitRemote})
	if err != nil {
		return err
	}
	metaBlob, err := crypto.SealBound(metaJSON, ck, crypto.AADMeta, "")
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}
	resp, err := cl.PutResource(api.PutResourceRequest{
		Visibility: api.Private, Blob: rootBlob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, MinClient: api.CapabilityGitRemote, CompactAt: compactAt,
	})
	if err != nil {
		return err
	}
	url := "aqt::" + name
	if flagJSON {
		return printJSON(map[string]any{"id": resp.ID, "name": name, "url": url, "compactAt": compactAt})
	}
	fmt.Println(url)
	if _, err := exec.LookPath("git-remote-aqt"); err != nil {
		fmt.Fprintln(os.Stderr, "warning: git-remote-aqt is not on PATH; run `make build` and add ./bin to PATH before cloning")
	}
	return nil
}

func loadRepoRows(cl *client.Client, mk crypto.MasterKey) ([]repoRow, map[string]api.ResourceListItem, error) {
	items, err := cl.ListResources()
	if err != nil {
		return nil, nil, err
	}
	rows := make([]repoRow, 0)
	byID := make(map[string]api.ResourceListItem)
	for _, item := range gitRemoteItems(items) {
		meta, ok := openMetadata(item, mk)
		if !ok || meta.Kind != api.KindGitRemote {
			continue
		}
		if item.WrappedKey == nil {
			return nil, nil, fmt.Errorf("git remote %s has no owner key", item.ID)
		}
		res, err := cl.GetResource(item.ID)
		if err != nil {
			return nil, nil, err
		}
		ck, err := crypto.UnwrapKey(*item.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return nil, nil, err
		}
		root, openErr := gitremote.OpenRefsRoot(res.Blob, ck, item.ID)
		ck.Wipe()
		if openErr != nil {
			return nil, nil, fmt.Errorf("open git remote %s: %w", item.ID, openErr)
		}
		rows = append(rows, repoRow{
			ID: item.ID, Name: meta.Name, Bundles: len(root.Bundles), Size: root.Size(),
			Version: item.Version, Generation: root.Generation, CompactAt: item.CompactAt, UpdatedAt: item.UpdatedAt,
		})
		byID[item.ID] = item
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Name == rows[j].Name {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].Name < rows[j].Name
	})
	return rows, byID, nil
}

func runRepoList(asJSON bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	rows, _, err := loadRepoRows(cl, mk)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no git remotes yet")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tBUNDLES\tSIZE\tVERSION\tID")
	for _, row := range rows {
		fmt.Fprintf(w, "%s\t%d\t%s\tv%d\t%s\n", row.Name, row.Bundles, humanBytes(row.Size), row.Version, row.ID)
	}
	return w.Flush()
}

func runRepoInfo(ref string, asJSON bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	rows, items, err := loadRepoRows(cl, mk)
	if err != nil {
		return err
	}
	row, err := selectRepoRow(rows, ref)
	if err != nil {
		return err
	}
	item := items[row.ID]
	res, err := cl.GetResource(row.ID)
	if err != nil {
		return err
	}
	ck, err := crypto.UnwrapKey(*item.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}
	defer ck.Wipe()
	root, err := gitremote.OpenRefsRoot(res.Blob, ck, row.ID)
	if err != nil {
		return err
	}
	snapshots, err := cl.ListSnapshots(row.ID)
	if err != nil {
		return err
	}
	out := repoInfoRow{
		repoRow: row, Head: root.Head, Refs: root.Refs, ObjectFormat: root.ObjectFormat,
		AutoSnapshot: item.AutoSnapshot, SnapshotCount: len(snapshots),
	}
	if asJSON {
		return printJSON(out)
	}
	fmt.Printf("%s · %s\n", row.Name, row.ID)
	fmt.Printf("bundles %d · size %s · generation %d · version %d · compact at %d\n",
		row.Bundles, humanBytes(row.Size), row.Generation, row.Version, row.CompactAt)
	if root.Head != "" {
		fmt.Printf("HEAD -> %s\n", root.Head)
	}
	names := make([]string, 0, len(root.Refs))
	for name := range root.Refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("%s %s\n", root.Refs[name], name)
	}
	fmt.Printf("snapshots %d · automatic %t\n", len(snapshots), item.AutoSnapshot)
	return nil
}

func selectRepoRow(rows []repoRow, ref string) (repoRow, error) {
	var matches []repoRow
	for _, row := range rows {
		if row.ID == ref || row.Name == ref {
			matches = append(matches, row)
		}
	}
	if len(matches) == 0 {
		return repoRow{}, fmt.Errorf("git remote %q not found", ref)
	}
	if len(matches) > 1 {
		return repoRow{}, fmt.Errorf("git remote name %q is ambiguous; use an id", ref)
	}
	return matches[0], nil
}

func runRepoGC(ref string, asJSON bool) error {
	// Unlike the helper protocol, this is an interactive CLI command: unlock once
	// here if needed, which also populates the cache h.openRemote requires.
	_, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	h := &remoteHelper{
		rawURL: ref,
		errOut: os.Stderr,
	}
	compacted, before, generation, err := h.compact(true)
	if err != nil {
		return err
	}
	if !compacted {
		if asJSON {
			return printJSON(map[string]any{"compacted": false, "bundlesBefore": before, "bundlesAfter": before, "generation": generation})
		}
		fmt.Printf("already compacted · %d bundle(s) · generation %d\n", before, generation)
		return nil
	}
	if asJSON {
		return printJSON(map[string]any{"compacted": true, "bundlesBefore": before, "bundlesAfter": 1, "generation": generation})
	}
	fmt.Printf("compacted %d bundle(s) to 1 · generation %d\n", before, generation)
	return nil
}

func runRepoRestore(snapshotID string, assumeYes, asJSON bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	snap, err := cl.GetSnapshot(snapshotID)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("snapshot %s not found (or not yours)", snapshotID)
	}
	if err != nil {
		return err
	}
	if snap.Snapshot.WrappedKey == nil {
		return errors.New("git remote snapshot has no owner key")
	}
	ck, err := crypto.UnwrapKey(*snap.Snapshot.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap git remote snapshot key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(snap.Snapshot.EncryptedMeta, ck, snap.Snapshot.ResourceID)
	if err != nil {
		return err
	}
	if meta.Kind != api.KindGitRemote {
		return fmt.Errorf("snapshot %s is %s content, not a git remote", snapshotID, meta.Kind)
	}
	root, err := gitremote.OpenRefsRoot(snap.Blob, ck, snap.Snapshot.ResourceID)
	if err != nil {
		return fmt.Errorf("open git remote snapshot root: %w", err)
	}
	current, err := cl.GetResource(snap.Snapshot.ResourceID)
	if err != nil {
		return fmt.Errorf("get live git remote: %w", err)
	}
	if current.CompactAt == 0 {
		return errors.New("live resource is no longer a git remote")
	}
	if err := confirmDestructive(fmt.Sprintf("Restore git remote %q to snapshot %s? Current refs are replaced. [y/N] ", meta.Name, snapshotID), assumeYes); err != nil {
		return err
	}
	if _, err := cl.CreateAutoSnapshot(snap.Snapshot.ResourceID); err != nil {
		return fmt.Errorf("create pre-restore snapshot: %w", err)
	}
	resp, err := cl.PutResource(api.PutResourceRequest{
		ID: snap.Snapshot.ResourceID, Visibility: api.Private,
		Blob: snap.Blob, EncryptedMeta: snap.Snapshot.EncryptedMeta,
		WrappedKey: snap.Snapshot.WrappedKey, ChunkRefs: root.SegmentIDs(),
		ExpectedVersion: current.Version, MinClient: max(snap.MinClient, api.CapabilityGitRemote),
		CompactAt: current.CompactAt,
	})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(map[string]any{"restored": true, "snapshotId": snapshotID, "resourceId": resp.ID, "version": resp.Version, "generation": root.Generation, "bundles": len(root.Bundles)})
	}
	fmt.Printf("restored %q to snapshot %s · %d bundle(s) · generation %d · version %d\n", meta.Name, snapshotID, len(root.Bundles), root.Generation, resp.Version)
	return nil
}

func runRepoRemove(ref string, assumeYes bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	rows, _, err := loadRepoRows(cl, mk)
	mk.Wipe()
	if err != nil {
		return err
	}
	row, err := selectRepoRow(rows, ref)
	if err != nil {
		return err
	}
	if err := runRemove([]string{row.ID}, false, assumeYes); err != nil {
		return err
	}
	if _, err = cl.GC(); err != nil {
		// The remote is already deleted. Report cleanup as a warning so a caller
		// never retries a destructive operation that actually succeeded.
		fmt.Fprintln(os.Stderr, "warning: post-delete pack GC failed:", err)
	}
	return nil
}
