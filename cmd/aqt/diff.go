package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
	textmerge "github.com/aquitano/aqt-sync/internal/syncengine/merge"
)

// diffAgainstRemote is the reserved --against value naming the folder's current
// remote state, the one comparison that goes through neither the base nor a snapshot.
// Snapshot ids are server-assigned and prefixed, so the word cannot collide with one.
const diffAgainstRemote = "remote"

type diffOptions struct {
	remote     bool
	against    string
	nameStatus bool
}

// pathLevel reports whether to render classified paths rather than a unified text
// diff. --json implies it: a line diff has no JSON form, so the structured output is
// always the path-level comparison.
func (o diffOptions) pathLevel() bool { return o.nameStatus || flagJSON }

func diffCmd() *cobra.Command {
	var opts diffOptions
	cmd := &cobra.Command{
		Use:   "diff [path...] [dir]",
		Short: "Compare the working tree with the base, a snapshot, or the current remote",
		Long: "Compares two states of a tracked folder and prints the difference. By default " +
			"the working tree is compared with the last-synced base as a unified text diff; " +
			"--remote compares the base with the current remote instead, and --against names " +
			"a snapshot or the literal `remote` as the left-hand side.\n\n" +
			"--name-status (implied by --json) reports classified paths instead of file " +
			"content: added, modified, permission-only, type change, deleted, and renamed.\n\n" +
			"Every mode is read-only. Nothing is uploaded, nothing lands in the working tree, " +
			"and neither the last-synced base nor the recorded remote version is touched, so a " +
			"comparison never changes what a later `aqt sync` would do.\n\n" +
			"This is not `aqt status` (local and incoming, each measured against the base) or " +
			"`aqt sync --dry-run` (the three-way plan a reconcile would execute): a comparison " +
			"names two states and reports only how they differ.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, paths := diffInvocation(args)
			return runDiff(dir, paths, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.remote, "remote", false, "diff incoming remote changes against the last-synced base")
	cmd.Flags().StringVar(&opts.against, "against", "",
		"compare the working tree against a `snapshot-id|remote` — a snapshot, or the folder's current remote state")
	cmd.Flags().BoolVar(&opts.nameStatus, "name-status", false,
		"list changed paths and their kind (A/M/P/T/D/R) instead of file content")
	markJSONSupported(cmd)
	return cmd
}

// diffInvocation treats the final argument as dir only when it is itself a tracked
// root. Existing subdirectories therefore remain usable as path filters.
func diffInvocation(args []string) (dir string, paths []string) {
	dir, paths = ".", args
	if len(args) == 0 {
		return dir, paths
	}
	candidate := args[len(args)-1]
	if fi, err := os.Stat(filepath.Join(candidate, syncengine.ControlDir)); err == nil && fi.IsDir() {
		return candidate, args[:len(args)-1]
	}
	return dir, paths
}

func runDiff(dir string, paths []string, opts diffOptions) error {
	if opts.remote && opts.against != "" {
		return errors.New("--remote and --against are mutually exclusive")
	}
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	if err := bindTrackedRoot(root); err != nil {
		return err
	}
	filters, err := normalizeDiffPaths(root, dir, paths)
	if err != nil {
		return err
	}
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	if opts.against == diffAgainstRemote {
		return runDiffRemote(cl, prof, root, filters, opts)
	}

	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	if cfg.Pack && opts.against == "" {
		return errors.New("aqt diff against the last-synced base requires a chunked folder; " +
			"use --against with a snapshot id, or --against=remote, for pack-and-seal content")
	}
	var base, local syncengine.Manifest
	if opts.against != "" {
		local, err = syncengine.Scan(root)
	} else {
		var exists bool
		base, exists, err = loadBaseForSync(root)
		if err == nil && !exists {
			return errSyncNoBase
		}
		if err == nil {
			local, err = syncengine.ScanReusing(root, &base, true)
		}
	}
	if err != nil {
		return err
	}

	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()

	if opts.against != "" {
		return diffAgainstSnapshot(cl, mk, root, local, filters, opts.against, opts)
	}
	baseSide := diffSide{Label: "last-synced base", Version: base.Version}
	if opts.remote {
		res, err := folderResource(cl, root)
		if err != nil {
			return err
		}
		remote, err := remoteManifest(cl, res, mk, base)
		if err != nil {
			return err
		}
		return renderDiff(opts, filters, base, remote,
			baseSide, diffSide{Label: "remote", Version: res.Version},
			manifestEntryReader(cl), manifestEntryReader(cl))
	}
	return renderDiff(opts, filters, base, local,
		baseSide, diffSide{Label: "working tree"},
		manifestEntryReader(cl), diskEntryReader(root))
}

// runDiffRemote compares the working tree with the folder's current remote state.
// The path-level rendering answers from metadata alone, so a chunked folder costs a
// few directory-node fetches; a unified text diff needs both sides' bytes, which for
// a pack-and-seal folder means reconstructing it — the one mode that cannot stay in
// memory, and the reason it lands in a temp dir rather than the working tree.
func runDiffRemote(cl *client.Client, prof *identity.Profile, root string, filters []string, opts diffOptions) error {
	if opts.pathLevel() {
		c, err := compareWorkingTreeToRemote(cl, prof, root)
		if err != nil {
			return err
		}
		return emitComparison(c.filter(filters))
	}
	res, err := folderResource(cl, root)
	if err != nil {
		return err
	}
	mk, unlocked, err := unlockForComparison(prof)
	if err != nil {
		return err
	}
	if !unlocked {
		printComparison(unavailableComparison(remoteSide(res), workingTreeSide, reasonSessionLocked))
		return nil
	}
	defer mk.Wipe()

	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	local, err := syncengine.Scan(root)
	if err != nil {
		return err
	}
	if cfg.Pack {
		tmp, err := os.MkdirTemp("", "aqt-line-diff-remote-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		if _, err := materializeWithMaster(cl, mk, res, tmp); err != nil {
			return fmt.Errorf("reconstruct remote %s: %w", res.ID, err)
		}
		remote, err := syncengine.Scan(tmp)
		if err != nil {
			return err
		}
		return renderManifestDiff(remote, local, filters, diskEntryReader(tmp), diskEntryReader(root))
	}
	base, err := loadBase(root)
	if err != nil {
		return err
	}
	remote, err := remoteManifest(cl, res, mk, base)
	if err != nil {
		return err
	}
	return renderManifestDiff(remote, local, filters, manifestEntryReader(cl), diskEntryReader(root))
}

// folderResource fetches the resource a tracked root points at.
func folderResource(cl *client.Client, root string) (api.GetResourceResponse, error) {
	st, err := loadState(root)
	if err != nil {
		return api.GetResourceResponse{}, err
	}
	res, err := cl.GetResource(st.ID)
	if errors.Is(err, client.ErrNotFound) {
		return api.GetResourceResponse{}, fmt.Errorf("folder resource %s not found on the server", st.ID)
	}
	return res, err
}

// renderDiff prints one comparison in the shape the flags asked for: classified paths,
// or a unified text diff of the entries' bytes.
func renderDiff(opts diffOptions, filters []string, oldManifest, newManifest syncengine.Manifest, oldSide, newSide diffSide, readOld, readNew entryReader) error {
	if !opts.pathLevel() {
		return renderManifestDiff(oldManifest, newManifest, filters, readOld, readNew)
	}
	return emitComparison(newComparison(oldSide, newSide, syncengine.Diff(oldManifest, newManifest)).filter(filters))
}

func emitComparison(c comparison) error {
	if flagJSON {
		return printJSON(c)
	}
	printComparison(c)
	return nil
}

func diffAgainstSnapshot(cl *client.Client, mk crypto.MasterKey, root string, local syncengine.Manifest, filters []string, snapshotID string, opts diffOptions) error {
	snap, err := cl.GetSnapshot(snapshotID)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("snapshot %s not found (or not yours)", snapshotID)
	}
	if err != nil {
		return err
	}
	st, err := loadState(root)
	if err != nil {
		return err
	}
	if snap.Snapshot.ResourceID != st.ID {
		return fmt.Errorf("snapshot %s belongs to resource %s, not this folder (%s)", snapshotID, snap.Snapshot.ResourceID, st.ID)
	}
	snapshotSide := diffSide{Label: "snapshot " + snapshotID, Version: snap.Snapshot.Version}
	if opts.pathLevel() {
		// Which paths differ is a question about metadata, and the snapshot's manifest
		// already answers it — read it the way --against=remote reads the remote's
		// rather than reconstructing the whole tree on disk to hash back what the
		// manifest records. base.json is only a node-reuse hint here; an absent one
		// loads empty, which is why this mode never required it.
		base, err := loadBase(root)
		if err != nil {
			return err
		}
		snapshotManifest, err := remoteManifest(cl, snapshotAsResource(snap), mk, base)
		if err != nil {
			return fmt.Errorf("read snapshot %s: %w", snapshotID, err)
		}
		return emitComparison(newComparison(snapshotSide, workingTreeSide,
			syncengine.Diff(snapshotManifest, local)).filter(filters))
	}
	// A unified text diff needs both sides' bytes, which is the one thing the manifest
	// cannot supply, so this mode still reconstructs the snapshot.
	tmp, err := os.MkdirTemp("", "aqt-line-diff-snapshot-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if _, err := materializeWithMaster(cl, mk, snapshotAsResource(snap), tmp); err != nil {
		return fmt.Errorf("reconstruct snapshot %s: %w", snapshotID, err)
	}
	snapshotManifest, err := syncengine.Scan(tmp)
	if err != nil {
		return err
	}
	return renderManifestDiff(snapshotManifest, local, filters, diskEntryReader(tmp), diskEntryReader(root))
}

type entryReader func(syncengine.Entry) ([]byte, error)

func manifestEntryReader(cl *client.Client) entryReader {
	source := newEmptyPackSource(cl)
	return func(e syncengine.Entry) ([]byte, error) {
		if e.IsSymlink() {
			return []byte(e.Link), nil
		}
		if len(e.Chunks) == 0 {
			return syncengine.FileBytes(e, nil)
		}
		if err := source.locate(distinctChunkIDs([]syncengine.Entry{e})); err != nil {
			return nil, err
		}
		return syncengine.FileBytes(e, source.get)
	}
}

func diskEntryReader(root string) entryReader {
	return func(e syncengine.Entry) ([]byte, error) {
		path := filepath.Join(root, filepath.FromSlash(e.Path))
		if e.IsSymlink() {
			target, err := os.Readlink(path)
			return []byte(target), err
		}
		return os.ReadFile(path)
	}
}

func renderManifestDiff(oldManifest, newManifest syncengine.Manifest, filters []string, readOld, readNew entryReader) error {
	oldByPath, newByPath := oldManifest.ByPath(), newManifest.ByPath()
	paths := make([]string, 0, len(oldByPath)+len(newByPath))
	seen := map[string]bool{}
	for path := range oldByPath {
		seen[path] = true
	}
	for path := range newByPath {
		seen[path] = true
	}
	for path := range seen {
		if matchesDiffPath(path, filters) {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	var err error
	for _, path := range paths {
		oldEntry, oldOK := oldByPath[path]
		newEntry, newOK := newByPath[path]
		if oldOK && newOK && oldEntry.Hash == newEntry.Hash && oldEntry.IsSymlink() == newEntry.IsSymlink() {
			continue
		}
		oldName, newName := "a/"+path, "b/"+path
		if !oldOK {
			oldName = "/dev/null"
		}
		if !newOK {
			newName = "/dev/null"
		}
		if (oldOK && oldEntry.Size > textmerge.MaxTextSize) || (newOK && newEntry.Size > textmerge.MaxTextSize) ||
			(oldOK && newOK && oldEntry.IsSymlink() != newEntry.IsSymlink()) {
			fmt.Printf("Binary files %s and %s differ\n", oldName, newName)
			continue
		}
		var oldData, newData []byte
		if oldOK {
			oldData, err = readOld(oldEntry)
			if err != nil {
				return fmt.Errorf("read old %s: %w", path, err)
			}
		}
		if newOK {
			newData, err = readNew(newEntry)
			if err != nil {
				return fmt.Errorf("read new %s: %w", path, err)
			}
		}
		if !textmerge.Eligible(oldData, newData) {
			fmt.Printf("Binary files %s and %s differ\n", oldName, newName)
			continue
		}
		if _, err := os.Stdout.Write(textmerge.Unified(oldName, newName, oldData, newData)); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDiffPaths(root, start string, paths []string) ([]string, error) {
	startAbs, err := filepath.Abs(start)
	if err != nil {
		return nil, err
	}
	filters := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" || path == "." {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(startAbs, path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		path = filepath.ToSlash(filepath.Clean(rel))
		if path == ".." || strings.HasPrefix(path, "../") {
			return nil, fmt.Errorf("diff path %q escapes the tracked folder", path)
		}
		filters = append(filters, strings.TrimSuffix(path, "/"))
	}
	return filters, nil
}

func matchesDiffPath(path string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, filter := range filters {
		if path == filter || strings.HasPrefix(path, filter+"/") {
			return true
		}
	}
	return false
}
