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
	"github.com/aquitano/aqt-sync/internal/syncengine"
	textmerge "github.com/aquitano/aqt-sync/internal/syncengine/merge"
)

type diffOptions struct {
	remote  bool
	against string
}

func diffCmd() *cobra.Command {
	var opts diffOptions
	cmd := &cobra.Command{
		Use:   "diff [path...] [dir]",
		Short: "Show line-level local, incoming, or snapshot changes",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, paths := diffInvocation(args)
			return runDiff(dir, paths, opts)
		},
	}
	cmd.Flags().BoolVar(&opts.remote, "remote", false, "diff incoming remote changes against the last-synced base")
	cmd.Flags().StringVar(&opts.against, "against", "", "diff the working tree against this snapshot id")
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
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	if cfg.Pack && opts.against == "" {
		return errors.New("aqt diff against the last-synced base requires a chunked folder; use --against with a snapshot for pack-and-seal content")
	}
	filters, err := normalizeDiffPaths(root, dir, paths)
	if err != nil {
		return err
	}
	base, exists, err := loadBaseForSync(root)
	if err != nil {
		return err
	}
	if !exists {
		return errSyncNoBase
	}
	local, err := syncengine.ScanReusing(root, &base, true)
	if err != nil {
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

	if opts.against != "" {
		return diffAgainstSnapshot(cl, mk, root, local, filters, opts.against)
	}
	if opts.remote {
		st, err := loadState(root)
		if err != nil {
			return err
		}
		remote, err := currentRemoteManifest(cl, mk, st.ID)
		if err != nil {
			return err
		}
		return renderManifestDiff(base, remote, filters, manifestEntryReader(cl), manifestEntryReader(cl))
	}
	return renderManifestDiff(base, local, filters, manifestEntryReader(cl), diskEntryReader(root))
}

func currentRemoteManifest(cl *client.Client, mk crypto.MasterKey, id string) (syncengine.Manifest, error) {
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return syncengine.Manifest{}, fmt.Errorf("folder resource %s not found on the server", id)
	}
	if err != nil {
		return syncengine.Manifest{}, err
	}
	if res.WrappedKey == nil {
		return syncengine.Manifest{}, errors.New("folder resource has no owner key; cannot diff")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return syncengine.Manifest{}, fmt.Errorf("unwrap folder key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	if meta.Kind != api.KindFolder || meta.Packed || !meta.Tree {
		return syncengine.Manifest{}, errors.New("aqt diff currently requires a chunked folder")
	}
	return openRemoteTree(cl, res.Blob, ck, id)
}

func diffAgainstSnapshot(cl *client.Client, mk crypto.MasterKey, root string, local syncengine.Manifest, filters []string, snapshotID string) error {
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
	var sources = map[string]*packSource{}
	return func(e syncengine.Entry) ([]byte, error) {
		if e.IsSymlink() {
			return []byte(e.Link), nil
		}
		if len(e.Chunks) == 0 {
			return syncengine.FileBytes(e, nil)
		}
		// One source per entry keeps this closure simple; packSource still coalesces all
		// chunks of that file into ranges. The renderer only calls it for changed files.
		key := e.Path + "\x00" + e.Hash
		source := sources[key]
		if source == nil {
			var err error
			source, err = newPackSource(cl, distinctChunkIDs([]syncengine.Entry{e}))
			if err != nil {
				return nil, err
			}
			sources[key] = source
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
