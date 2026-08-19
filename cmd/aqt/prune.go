// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/gitremote"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func pruneCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete stored chunks no resource or snapshot references",
		Long: `Computes the set of chunks reachable from every resource and snapshot of the
account, then deletes what the server stores beyond it. On an account with
client-managed garbage collection this is the only way stored bytes are
reclaimed; run it occasionally, or after deleting large folders.

The whole account must be readable: if any resource or snapshot cannot be
decoded, nothing is deleted.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPrune(dryRun, flagJSON)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be deleted without deleting")
	markJSONSupported(cmd)
	return cmd
}

// pruneReport is the machine-readable summary of one prune run.
type pruneReport struct {
	Roots         int   `json:"roots"`
	Reachable     int   `json:"reachable"`
	Stored        int   `json:"stored"`
	Unreachable   int   `json:"unreachable"`
	Deleted       int   `json:"deleted"`
	SkippedRecent int   `json:"skippedRecent"`
	FreedBytes    int64 `json:"freedBytes"`
	DryRun        bool  `json:"dryRun,omitempty"`
}

func runPrune(dryRun, asJSON bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()

	reachable := map[string]bool{}
	roots := 0

	items, err := cl.ListResources()
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.MinClient > api.ClientCapability {
			return fmt.Errorf("resource %s needs client capability %d to read; prune must decode every resource before it can delete anything", item.ID, item.MinClient)
		}
		res, err := cl.GetResource(item.ID)
		if errors.Is(err, client.ErrGone) {
			continue // a reclaimed link tombstone roots nothing
		}
		if err != nil {
			return fmt.Errorf("read resource %s: %w", item.ID, err)
		}
		if err := addClosure(cl, reachable, res.Blob, res.WrappedKey, res.EncryptedMeta, item.ID, mk, conv); err != nil {
			return fmt.Errorf("resource %s: %w", item.ID, err)
		}
		roots++
	}
	snaps, err := cl.ListSnapshots("")
	if err != nil {
		return err
	}
	for _, s := range snaps {
		snap, err := cl.GetSnapshot(s.ID)
		if err != nil {
			return fmt.Errorf("read snapshot %s: %w", s.ID, err)
		}
		if snap.MinClient > api.ClientCapability {
			return fmt.Errorf("snapshot %s needs client capability %d to read; prune must decode every snapshot before it can delete anything", s.ID, snap.MinClient)
		}
		// Snapshot blobs and metadata are sealed bound to the source resource's id,
		// under the content key captured with the snapshot.
		if err := addClosure(cl, reachable, snap.Blob, snap.Snapshot.WrappedKey, snap.Snapshot.EncryptedMeta, snap.Snapshot.ResourceID, mk, conv); err != nil {
			return fmt.Errorf("snapshot %s: %w", s.ID, err)
		}
		roots++
	}

	var stored []string
	cursor := ""
	for {
		page, err := cl.ListChunks(cursor)
		if err != nil {
			return err
		}
		stored = append(stored, page.IDs...)
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	var unreachable []string
	for _, id := range stored {
		if !reachable[id] {
			unreachable = append(unreachable, id)
		}
	}
	sort.Strings(unreachable)

	rep := pruneReport{
		Roots: roots, Reachable: len(reachable),
		Stored: len(stored), Unreachable: len(unreachable),
		DryRun: dryRun,
	}
	if !dryRun {
		// The reachability view above can go stale while it is being computed: a
		// push committing after a root was walked may re-reference a chunk this
		// view calls unreachable, and once that chunk's pack ages past the server's
		// grace window a delete would land. Re-listing closes the gap: any root
		// added or moved since the walk aborts the prune, and a push landing after
		// this check re-arms its packs recently enough that the grace window
		// refuses the delete (the batches below run in minutes, the window is an
		// hour).
		itemsNow, err := cl.ListResources()
		if err != nil {
			return err
		}
		snapsNow, err := cl.ListSnapshots("")
		if err != nil {
			return err
		}
		if rootsDrifted(items, itemsNow, snaps, snapsNow) {
			return errors.New("the account changed while prune was computing reachability; nothing was deleted — re-run `aqt prune`")
		}
		const batch = 10_000 // the server-side per-request id cap
		for start := 0; start < len(unreachable); start += batch {
			end := min(start+batch, len(unreachable))
			resp, err := cl.DeleteChunks(unreachable[start:end])
			if err != nil {
				return err
			}
			rep.Deleted += resp.Deleted
			rep.SkippedRecent += resp.SkippedRecent
			rep.FreedBytes += resp.FreedBytes
		}
		// The deletes free whole packs immediately; a GC pass compacts the packs
		// that now mix deleted and remaining objects.
		if gc, err := cl.GC(); err == nil {
			rep.FreedBytes += gc.ReclaimedBytes
		}
	}

	if asJSON {
		return printJSON(rep)
	}
	rows := [][]string{
		{"roots", strconv.Itoa(rep.Roots)},
		{"reachable chunks", strconv.Itoa(rep.Reachable)},
		{"stored chunks", strconv.Itoa(rep.Stored)},
		{"unreachable", strconv.Itoa(rep.Unreachable)},
	}
	if dryRun {
		fmt.Println("dry run: nothing deleted")
		return printTable(os.Stdout, nil, rows)
	}
	rows = append(rows,
		[]string{"deleted", strconv.Itoa(rep.Deleted)},
		[]string{"freed", cliutil.HumanBytes(rep.FreedBytes)},
	)
	if rep.SkippedRecent > 0 {
		rows = append(rows, []string{"skipped (recently touched)", strconv.Itoa(rep.SkippedRecent)})
		fmt.Fprintln(os.Stderr, "some chunks were uploaded or touched too recently to delete safely; re-run `aqt prune` in an hour")
	}
	return printTable(os.Stdout, nil, rows)
}

// rootsDrifted reports whether the account's root set moved between the two
// listings: a resource that appeared or changed version, or a snapshot that
// appeared, may root chunks the first listing's walk never saw. Removals are
// fine — a vanished root only makes the computed reachable set conservative.
func rootsDrifted(items, itemsNow []api.ResourceListItem, snaps, snapsNow []api.SnapshotInfo) bool {
	versions := make(map[string]int, len(items))
	for _, it := range items {
		versions[it.ID] = it.Version
	}
	for _, it := range itemsNow {
		if v, ok := versions[it.ID]; !ok || v != it.Version {
			return true
		}
	}
	snapIDs := make(map[string]bool, len(snaps))
	for _, s := range snaps {
		snapIDs[s.ID] = true
	}
	for _, s := range snapsNow {
		if !snapIDs[s.ID] {
			return true
		}
	}
	return false
}

// addClosure decodes one root (a resource or a snapshot) and adds every chunk id
// reachable from it. An undecodable root aborts the prune: a closure the client
// cannot compute means the diff against the inventory would count that root's
// chunks as garbage.
func addClosure(cl *client.Client, reachable map[string]bool, blob crypto.SealedBlob, wrapped *crypto.WrappedKey, encMeta crypto.SealedBlob, id string, mk crypto.MasterKey, conv crypto.ConvergenceKey) error {
	if wrapped == nil {
		return errors.New("no owner key stored; its chunk closure cannot be computed")
	}
	ck, err := crypto.UnwrapKey(*wrapped, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(encMeta, ck, id)
	if err != nil {
		return err
	}
	refs, err := closureRefs(cl, blob, ck, id, meta, conv)
	if err != nil {
		return err
	}
	for _, r := range refs {
		reachable[r] = true
	}
	return nil
}

// closureRefs recomputes the exact ref set a root's format would declare on a
// push, per kind — the same reconstruction the share rotations use.
func closureRefs(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey, id string, meta api.Metadata, conv crypto.ConvergenceKey) ([]string, error) {
	switch {
	case meta.Kind == api.KindGitRemote:
		root, err := gitremote.OpenRefsRoot(blob, ck, id)
		if err != nil {
			return nil, fmt.Errorf("decrypt git-remote root: %w", err)
		}
		return root.SegmentIDs(), nil
	case meta.Packed:
		return nil, errors.New("packed folder format is no longer readable; export it with an aqt release that reads it (v0.7.x or earlier)")
	case meta.Kind == api.KindFolder && meta.Tree:
		root, err := syncengine.OpenTreeRoot(blob, ck, id)
		if err != nil {
			return nil, fmt.Errorf("decrypt folder root: %w", err)
		}
		manifest, err := syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, nil))
		if err != nil {
			return nil, err
		}
		sealed, refs, err := syncengine.SealTree(manifest, conv, nil)
		if err != nil {
			return nil, err
		}
		// The recomputed root must reproduce the stored one, or the refs describe a
		// different tree than the server holds.
		if sealed.Root.ID != root.Root.ID {
			return nil, fmt.Errorf("recomputed tree root %s does not match stored root %s", sealed.Root.ID, root.Root.ID)
		}
		return refs, nil
	case meta.Kind == api.KindFolder:
		return nil, errors.New("pre-tree folder format is no longer readable")
	case meta.Streamed:
		root, err := syncengine.OpenFileRoot(blob, ck, id)
		if err != nil {
			return nil, fmt.Errorf("decrypt file root: %w", err)
		}
		chunks := root.Chunks
		if root.Indirect() {
			segSrc, err := newPackSource(cl, root.ChunkIDs())
			if err != nil {
				return nil, err
			}
			chunks, err = root.Resolve(segSrc.get)
			if err != nil {
				return nil, err
			}
		}
		return root.Refs(chunks), nil
	default:
		return nil, nil // inline: the blob references no objects
	}
}
