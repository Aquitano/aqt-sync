package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// folderState is the per-folder pointer stored in .aqt/state.json: which resource
// on which server this directory tracks, plus when its packs were last GC'd.
type folderState struct {
	ID     string `json:"id"`
	Server string `json:"server"`
	LastGC int64  `json:"lastGC,omitempty"` // Unix seconds of the last reclaimPacks GC; throttles the next
	// RemoteVersion is the highest resource version this machine has observed —
	// the freshness pin. A server reporting a lower version has been rolled back
	// (restored from backup, or replaying an old state); syncing against it would
	// read the regression as remote changes and revert local files, so it is
	// refused unless --accept-rollback. 0 (state written by an older build)
	// disables the guard until the next successful sync records a version.
	RemoteVersion int `json:"remoteVersion,omitempty"`
}

const (
	stateFile = "state.json"
	baseFile  = "base.json"
	// packCacheBytes is the download pack-range cache budget: a pack shared by several
	// files is not re-GET per file, while download memory stays bounded by bytes (not
	// a fixed pack count) and independent of tree size.
	packCacheBytes = 128 << 20
	// maxSyncAttempts bounds the optimistic-concurrency retry: if this many
	// reconcile passes each lose the race to a concurrent sync, give up and ask
	// the user to re-run rather than spin.
	maxSyncAttempts = 5
	// gcMinInterval throttles how often a sync fires server GC. A pack the server
	// can actually reap is older than its own age guard (gcMinAge, 1h), so sweeping
	// after every push — the watch daemon does this every few seconds — almost always
	// scans for nothing while monopolizing the single DB connection. One sweep per
	// interval still reclaims a just-unrooted old pack within the hour.
	gcMinInterval = time.Hour
)

// --- commands ---

func initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [dir]",
		Short: "Mark a folder as tracked for sync",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runInit(dirArg(args)) },
	}
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [dir]",
		Short: "Show local changes since the last sync",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runStatus(dirArg(args)) },
	}
}

func syncCmd() *cobra.Command {
	var opts syncOptions
	cmd := &cobra.Command{
		Use:   "sync [dir]",
		Short: "Two-way reconcile a tracked folder with the server",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runSync(dirArg(args), opts) },
	}
	f := cmd.Flags()
	f.BoolVar(&opts.pushOnly, "push-only", false, "only upload local changes")
	f.BoolVar(&opts.pullOnly, "pull-only", false, "only download remote changes")
	f.BoolVar(&opts.dryRun, "dry-run", false, "print the plan without making changes")
	f.BoolVar(&opts.force, "force", false, "resolve conflicts in favor of local")
	f.BoolVar(&opts.reconcile, "reconcile", false, "reconcile without a base (.aqt/base.json missing): one-sided differences become conflicts to review")
	f.BoolVar(&opts.rehash, "rehash", false, "re-hash every file instead of trusting size+mtime (catches edits that preserve them)")
	f.BoolVar(&opts.acceptRollback, "accept-rollback", false, "proceed although the server reports an older version than previously seen (restored from backup): reconcile from scratch, one-sided differences become conflicts to review")
	return cmd
}

func cloneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clone <id|aqt://ref> [dir]",
		Short: "Materialize a tracked folder on this machine",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := ""
			if len(args) == 2 {
				dir = args[1]
			}
			return runClone(args[0], dir)
		},
	}
}

// --- init ---

func runInit(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(abs, syncengine.ControlDir)); err == nil {
		return errors.New("already a tracked folder")
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

	// aqt ignores .git by default; offer to track it when this tree holds a repo.
	syncGit := false
	if repo, ok := firstGitRepo(abs); ok {
		syncGit, err = promptSyncGit(repo)
		if err != nil {
			return err
		}
	}

	cfg, err := syncengine.LoadConfig(abs)
	if err != nil {
		return err
	}

	// Register an empty private folder resource; the first `sync` fills it. A
	// pack-and-seal folder (.aqtconfig pack=true) is created with an empty PackRoot;
	// the chunked default with an empty Merkle-DAG tree root.
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer ck.Wipe()
	manifest := syncengine.Manifest{Version: 1}
	var resp api.PutResourceResponse
	if cfg.Pack {
		resp, err = putPackFolderCreate(cl, syncengine.PackRoot{Version: syncengine.PackRootVersion}, ck, mk, abs)
	} else {
		manifest.Version = syncengine.TreeManifestVersion
		conv := crypto.DeriveConvergenceKey(mk)
		resp, err = putFolder(cl, conv, "", manifest, ck, mk, abs)
		conv.Wipe()
	}
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	if err := writeStarterIgnore(abs, syncGit); err != nil {
		return err
	}
	if err := saveState(abs, folderState{ID: resp.ID, Server: prof.Server, RemoteVersion: resp.Version}); err != nil {
		return err
	}
	if err := saveBase(abs, manifest); err != nil {
		return err
	}
	fmt.Printf("tracking %s\naqt://%s\n", abs, resp.ID)
	fmt.Fprintln(os.Stderr, "run `aqt sync` to push the current contents")
	return nil
}

// --- status ---

func runStatus(dir string) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	base, err := loadBase(root)
	if err != nil {
		return err
	}
	local, err := syncengine.Scan(root)
	if err != nil {
		return err
	}

	// status is intentionally offline: it compares the working tree to the last
	// synced manifest. Remote-side changes and conflicts surface during `sync`.
	var added, modified, deleted []string
	for _, a := range syncengine.Plan(local, base, base) {
		switch a.Kind {
		case syncengine.Upload:
			if _, ok := base.Lookup(a.Path); ok {
				modified = append(modified, a.Path)
			} else {
				added = append(added, a.Path)
			}
		case syncengine.DeleteRemote:
			deleted = append(deleted, a.Path)
		}
	}
	if len(added)+len(modified)+len(deleted) == 0 {
		fmt.Println("clean (no local changes since last sync)")
		return nil
	}
	printPaths("new", added)
	printPaths("modified", modified)
	printPaths("deleted", deleted)
	return nil
}

// --- sync ---

type syncOptions struct {
	pushOnly       bool
	pullOnly       bool
	dryRun         bool
	force          bool
	reconcile      bool
	rehash         bool
	acceptRollback bool
}

// errSyncNoBase signals that a sync has no last-synced state to reconcile against
// (.aqt/base.json missing or corrupt). Syncing with an empty base would resurrect
// deletions, so it is refused unless --reconcile is given.
var errSyncNoBase = errors.New("no last-synced state found (.aqt/base.json missing or corrupt); " +
	"syncing now could resurrect deleted files. Re-run with --reconcile to reconcile local and remote " +
	"(one-sided differences become conflicts to review), or `aqt clone` into a fresh directory")

// errConflictsRemain and errSyncRace are sentinels so main() can map them to the
// documented "sync conflict" exit code (4).
var (
	errConflictsRemain = errors.New("conflicts changed on both sides; resolve them or re-run with --force (local wins)")
	errSyncRace        = errors.New("sync kept racing concurrent updates; please run `aqt sync` again")
)

// errRollback marks a remote whose version regressed below what this machine has
// already seen. Zero-knowledge covers content, not freshness: without this guard a
// server restored from backup (or a hostile replay) looks like ordinary remote
// changes and silently reverts or deletes newer local files.
var errRollback = errors.New("refusing to apply a server rollback")

func rollbackErr(remote, seen int) error {
	return fmt.Errorf("%w: the server reports version %d but this machine already synced version %d. "+
		"The server was likely restored from a backup (or is replaying an old state); syncing would treat "+
		"that old state as remote changes and could revert or delete newer local files. If the rollback is "+
		"expected, re-run with --accept-rollback to reconcile from scratch (one-sided differences become "+
		"conflicts to review)", errRollback, remote, seen)
}

func runSync(dir string, opts syncOptions) error {
	if opts.pushOnly && opts.pullOnly {
		return errors.New("--push-only and --pull-only are mutually exclusive")
	}
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	// Serialize concurrent syncs of the same folder on this machine; the server
	// enforces the same per-resource on its side.
	release, err := acquireSyncLock(root)
	if err != nil {
		return err
	}
	defer release()
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	if cfg.Pack {
		return runPackSync(root, opts)
	}
	st, err := loadState(root)
	if err != nil {
		return err
	}
	base, baseExists, err := loadBaseForSync(root)
	if err != nil {
		return err
	}
	if !baseExists && !opts.reconcile {
		return errSyncNoBase
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
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()

	// Snapshot the working tree once; it does not change between retries. When this
	// sync will push, stream every changed file through the chunker and upload the
	// packs the server lacks as we go, so memory stays O(one pack) regardless of
	// tree size; the manifest we later PUT references those objects. A pull-only or
	// dry-run pass uploads nothing, so a metadata+hash scan is enough to plan.
	var local syncengine.Manifest
	if opts.pullOnly || opts.dryRun {
		local, err = syncengine.Scan(root)
		if err != nil {
			return err
		}
	} else {
		chunker, cerr := cfg.Chunker()
		if cerr != nil {
			return cerr
		}
		up := newPackUploader(cl)
		local, err = syncengine.Take(root, conv, chunker, &base, up, opts.rehash)
		if err != nil {
			up.Wait() // drain in-flight uploads before returning the snapshot error
			return err
		}
		if err := up.Flush(); err != nil {
			return err
		}
	}

	// reconcile runs one pass against the current remote. It returns
	// client.ErrConflict if another sync committed first; the loop below then
	// re-plans against the new remote, so a concurrent write is never lost.
	reconcile := func() error {
		res, err := cl.GetResource(st.ID)
		if errors.Is(err, client.ErrNotFound) {
			return fmt.Errorf("folder resource %s not found on the server", st.ID)
		}
		if err != nil {
			return err
		}
		// Freshness guard: a version below the recorded pin means the server rolled
		// back. Accepting it discards the base for this pass — the old remote state
		// must not be reconciled against a base that post-dates it, or one-sided
		// regressions read as remote edits/deletes and clobber local files. The
		// baseless reconcile turns them into conflicts to review instead.
		trustBase := baseExists
		if st.RemoteVersion > 0 && res.Version < st.RemoteVersion {
			if !opts.acceptRollback {
				return rollbackErr(res.Version, st.RemoteVersion)
			}
			fmt.Fprintf(os.Stderr, "accepting server rollback (version %d, previously %d); reconciling from scratch\n",
				res.Version, st.RemoteVersion)
			trustBase = false
		}
		planBase := base
		if !trustBase {
			planBase = syncengine.Manifest{}
		}
		if res.WrappedKey == nil {
			return errors.New("folder resource has no owner key; cannot sync")
		}
		ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return fmt.Errorf("unwrap folder key: %w", err)
		}
		defer ck.Wipe()
		// Route by the server's truth, not just local .aqtconfig: a pack-and-seal folder
		// reconciled as chunked would read an empty manifest and delete the whole tree.
		// Refuse it instead. (AAD domain separation also makes the manifest read below
		// fail, but this gives the actionable message.)
		meta, err := decodeMeta(res.EncryptedMeta, ck)
		if err != nil {
			return err
		}
		if meta.Packed {
			return errors.New("this folder is pack-and-seal on the server but is being synced as chunked; " +
				"set pack=true in .aqtconfig, or re-clone it")
		}
		if !meta.Tree {
			return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
		}
		// Read the remote tree. With a base, reuse it: any directory node whose id the
		// base tree already contains is byte-identical (nodes are content-addressed), so
		// it is served from memory and only the nodes on a changed spine are fetched — an
		// unchanged remote does zero node round-trips. Without a base (reconcile mode,
		// or an accepted rollback) there is nothing to reuse, so fall back to the full walk.
		var remote syncengine.Manifest
		if trustBase {
			remote, err = openRemoteTreeReusingBase(cl, res.Blob, ck, base, conv)
		} else {
			remote, err = openRemoteTree(cl, res.Blob, ck)
		}
		if errors.Is(err, client.ErrNotFound) {
			// We read version res.Version's root, but a concurrent sync superseded it
			// and GC reaped its now-unreferenced tree objects before we fetched them.
			// Re-reconcile against the current version (same path the server's own
			// version conflict takes), rather than hard-failing the sync.
			return client.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("decrypt remote manifest: %w", err)
		}
		// With no trusted base, reconcile from scratch: one-sided differences are
		// ambiguous and become conflicts to review rather than silent adds/deletes.
		var actions []syncengine.Action
		var dirActions []syncengine.DirAction
		if trustBase {
			actions = syncengine.Plan(local, base, remote)
			dirActions = syncengine.PlanDirs(local, base, remote)
		} else {
			actions = syncengine.PlanReconcile(local, remote)
			dirActions = syncengine.PlanDirsReconcile(local, remote)
		}
		if opts.dryRun {
			return printPlan(actions, dirActions)
		}
		if err := abortOnConflicts(actions, dirActions, opts.force); err != nil {
			return err
		}
		return applySync(applyCtx{
			root: root, cl: cl, opts: opts,
			base: planBase, local: local, remote: remote,
			conv: conv, ck: ck, mk: mk, meta: res.EncryptedMeta,
			version: res.Version, id: st.ID,
		}, actions, dirActions)
	}

	return reconcileWithRetry(reconcile)
}

// reconcileWithRetry runs one reconcile pass, retrying against the fresh remote on a
// version conflict (another sync committed first), up to maxSyncAttempts before giving
// up. The conflict retry is how a concurrent write is re-planned rather than lost.
func reconcileWithRetry(reconcile func() error) error {
	for attempt := 0; attempt < maxSyncAttempts; attempt++ {
		err := reconcile()
		if errors.Is(err, client.ErrConflict) {
			if attempt == 0 {
				fmt.Fprintln(os.Stderr, "remote changed during sync; re-reconciling")
			}
			continue
		}
		return err
	}
	return errSyncRace
}

// applyCtx bundles the state applySync needs, keeping its signature readable.
type applyCtx struct {
	root    string
	cl      *client.Client
	opts    syncOptions
	base    syncengine.Manifest
	local   syncengine.Manifest
	remote  syncengine.Manifest
	conv    crypto.ConvergenceKey
	ck      crypto.ContentKey
	mk      crypto.MasterKey
	meta    crypto.SealedBlob // the resource's existing sealed metadata, carried forward
	version int
	id      string
}

func applySync(c applyCtx, actions []syncengine.Action, dirActions []syncengine.DirAction) error {
	push := !c.opts.pullOnly
	pull := !c.opts.pushOnly
	localByPath := c.local.ByPath()
	remoteByPath := c.remote.ByPath()

	merged := c.remote.ByPath() // becomes the new server manifest
	newBase := c.base.ByPath()  // becomes the new last-synced record
	var uploads []syncengine.Entry
	var downloads []syncengine.Entry
	var localDeletes []string
	remoteChanged := false

	for _, a := range actions {
		switch a.Kind {
		case syncengine.Upload, syncengine.Conflict: // Conflict only survives here with --force
			if !push {
				continue
			}
			e, ok := localByPath[a.Path]
			if !ok {
				// A conflict resolved local-wins where the file is gone locally
				// (local delete vs remote modify): local winning means deleting it
				// on the remote too. Uploading the zero Entry here would PUT a
				// path-less empty entry, drop the remote edit, and corrupt the
				// manifest (several such paths collapse to one on reload).
				delete(merged, a.Path)
				delete(newBase, a.Path)
				remoteChanged = true
				continue
			}
			merged[a.Path] = e
			newBase[a.Path] = e
			uploads = append(uploads, e)
			remoteChanged = true
		case syncengine.DeleteRemote:
			if !push {
				continue
			}
			delete(merged, a.Path)
			delete(newBase, a.Path)
			remoteChanged = true
		case syncengine.Download:
			if !pull {
				continue
			}
			e := remoteByPath[a.Path]
			downloads = append(downloads, e)
			newBase[a.Path] = e
		case syncengine.DeleteLocal:
			if !pull {
				continue
			}
			localDeletes = append(localDeletes, a.Path)
			delete(newBase, a.Path)
		}
	}

	// Reconcile tracked directories (empty dirs and modes) alongside files. The file
	// apply path is untouched; directory filesystem ops run in a dedicated pass after
	// files (below). A directory mode conflict resolves local-wins — it is only
	// permission metadata, not worth blocking a sync.
	mergedDirs := c.remote.DirsByPath() // new server dirs
	newBaseDirs := c.base.DirsByPath()
	localDirs := c.local.DirsByPath()
	remoteDirs := c.remote.DirsByPath()
	var dirDownloads []syncengine.DirEntry
	var dirRemovals []string
	for _, a := range dirActions {
		switch a.Kind {
		case syncengine.Upload, syncengine.Conflict:
			if !push {
				continue
			}
			if d, ok := localDirs[a.Path]; ok {
				mergedDirs[a.Path] = d
				newBaseDirs[a.Path] = d
			} else { // a conflict resolved local-wins where the dir is gone locally
				delete(mergedDirs, a.Path)
				delete(newBaseDirs, a.Path)
			}
			remoteChanged = true
		case syncengine.DeleteRemote:
			if !push {
				continue
			}
			delete(mergedDirs, a.Path)
			delete(newBaseDirs, a.Path)
			remoteChanged = true
		case syncengine.Download:
			if !pull {
				continue
			}
			d := remoteDirs[a.Path]
			dirDownloads = append(dirDownloads, d)
			newBaseDirs[a.Path] = d
		case syncengine.DeleteLocal:
			if !pull {
				continue
			}
			dirRemovals = append(dirRemovals, a.Path)
			delete(newBaseDirs, a.Path)
		}
	}

	// Fold paths that converged to identical content on both sides into the new
	// base. Plan emits no action for them (there is nothing to transfer), so without
	// this they stay "changed on both sides" forever: a later remote-only delete is
	// then misread as a local add, the file is re-pushed, and the deletion never
	// propagates. Keep the local entry (same hash as remote): base.json is local-only
	// bookkeeping, and the local entry carries this machine's mtime, so the next sync
	// stat-fast-paths the file instead of re-hashing it.
	for p, le := range localByPath {
		if re, ok := remoteByPath[p]; ok && le.Hash == re.Hash {
			newBase[p] = le
		}
	}

	// Push the server-side change FIRST, before any local file is touched, so a
	// version conflict (another sync committed first) returns with nothing
	// half-applied on disk and the caller can re-plan cleanly. The objects these
	// entries reference were already packed and uploaded during the snapshot pass;
	// here we only commit the merged manifest that roots them.
	syncedVersion := c.version
	if push && remoteChanged {
		manifest := manifestFrom(merged, c.version+1)
		manifest.Dirs = dirsFrom(mergedDirs)
		resp, err := putFolderUpdate(c.cl, c.conv, c.id, manifest, c.meta, c.ck, c.mk, c.version)
		if err != nil {
			return err // client.ErrConflict on a stale version: retried by the caller
		}
		syncedVersion = resp.Version
		reclaimPacks(c.root, c.cl)
	}

	// Re-verify the on-disk bytes of every file we are about to overwrite or delete
	// still match what the snapshot saw. A mtime-preserving edit (cp -p, touch -r,
	// archive extract) or any edit landing in the snapshot->apply window would
	// otherwise be silently clobbered by a remote download or delete. A target whose
	// content drifted is downgraded to a conflict: its destructive op is skipped and
	// its base entry left untouched, so the next sync re-plans it as a both-sides
	// change to resolve (or --force to take local).
	baseByPath := c.base.ByPath()
	checkSafe := func(path string, isDownload bool) (bool, error) {
		h, exists, isDir, err := syncengine.HashOnDisk(c.root, path)
		if err != nil {
			return false, err
		}
		if !exists {
			return true, nil // nothing on disk to destroy
		}
		if isDir {
			// A download onto a directory is the dir->file replacement materialize
			// performs once its children are deleted; a delete whose target became a
			// directory is a window change and is not safe to remove.
			return isDownload, nil
		}
		if prev, ok := localByPath[path]; ok && h == prev.Hash {
			return true, nil // unchanged since the snapshot
		}
		if isDownload {
			if re, ok := remoteByPath[path]; ok && h == re.Hash {
				return true, nil // already converged to the remote content
			}
		}
		return false, nil // drifted in the snapshot->apply window
	}
	var conflicts []string
	restore := func(path string) {
		if e, ok := baseByPath[path]; ok {
			newBase[path] = e
		} else {
			delete(newBase, path)
		}
		conflicts = append(conflicts, path)
	}
	keptDownloads := make([]syncengine.Entry, 0, len(downloads))
	for _, e := range downloads {
		safe, err := checkSafe(e.Path, true)
		if err != nil {
			return err
		}
		if safe {
			keptDownloads = append(keptDownloads, e)
		} else {
			restore(e.Path)
		}
	}
	downloads = keptDownloads
	keptDeletes := make([]string, 0, len(localDeletes))
	for _, p := range localDeletes {
		safe, err := checkSafe(p, false)
		if err != nil {
			return err
		}
		if safe {
			keptDeletes = append(keptDeletes, p)
		} else {
			restore(p)
		}
	}
	localDeletes = keptDeletes

	// Server is updated; now bring the local tree in line. A local file or symlink the
	// remote turned into a directory must be removed before the download that creates
	// that directory, or the download would write through the stale entry (refused) or
	// the later delete would hit a now-populated directory. Every other delete stays
	// after the downloads, so local data is never removed before its replacement lands.
	earlyDeletes, lateDeletes := partitionDeletesByDownload(localDeletes, downloads)
	for _, p := range earlyDeletes {
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return err
		}
	}
	if err := runDownloads(c.cl, c.root, downloads); err != nil {
		return err
	}
	for _, p := range lateDeletes {
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return err
		}
	}

	// Directories last: create/chmod after files land (so a directory exists and gets
	// its mode), and remove emptied directories after file deletes.
	if err := materializeDirs(c.root, dirDownloads); err != nil {
		return err
	}
	if err := removeDirs(c.root, dirRemovals); err != nil {
		return err
	}

	newBaseManifest := manifestFrom(newBase, c.version+1)
	newBaseManifest.Dirs = dirsFrom(newBaseDirs)
	if err := saveBase(c.root, newBaseManifest); err != nil {
		return err
	}
	recordRemoteVersion(c.root, syncedVersion)
	summarize(uploads, downloads, localDeletes, remoteChanged)
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		printPaths("conflict", conflicts)
		return errConflictsRemain
	}
	return nil
}

// --- clone ---

func runClone(ref, dir string) error {
	id, _ := parseRef(ref) // v1 folders are private; no fragment key
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("folder %s not found (or not a private folder you own)", id)
	}
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("not a private folder you own (no owner key)")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap folder key: %w", err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck)
	if err != nil {
		return err
	}

	if dir == "" {
		dir = id
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	// Decrypt the resource root before creating the destination, so a wrong or corrupt
	// key fails the clone without leaving an empty directory behind. The root blob is
	// tiny; materializeClone re-opens it to do the actual reconstruction.
	if err := validateCloneRoot(res.Blob, ck, meta); err != nil {
		return err
	}
	if err := ensureEmptyDir(abs); err != nil {
		return err
	}
	base, err := materializeClone(cl, abs, res, ck, meta)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	if err := saveState(abs, folderState{ID: id, Server: prof.Server, RemoteVersion: res.Version}); err != nil {
		return err
	}
	if err := saveBase(abs, base); err != nil {
		return err
	}
	fmt.Printf("cloned %d files into %s\n", len(base.Entries), abs)
	return nil
}

// validateCloneRoot confirms the resource's sealed root decrypts under ck, using the
// root type the metadata selects. The AAD is domain-separated per type, so a folder
// mis-flagged fails here rather than opening as an empty tree. A folder with neither
// flag predates the v2 tree format and is no longer supported.
func validateCloneRoot(blob crypto.SealedBlob, ck crypto.ContentKey, meta api.Metadata) error {
	var err error
	switch {
	case meta.Packed:
		_, err = syncengine.OpenPackRoot(blob, ck)
	case meta.Tree:
		_, err = syncengine.OpenTreeRoot(blob, ck)
	default:
		return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
	}
	if err != nil {
		return fmt.Errorf("decrypt folder root: %w", err)
	}
	return nil
}

// materializeClone writes a freshly cloned folder's content under abs and returns
// the manifest to record as its base. A pack-and-seal folder is untarred from its
// sealed segments; the chunked default reassembles its Merkle DAG, streams each
// file from its packs, and materializes (empty) directories with their modes.
func materializeClone(cl *client.Client, abs string, res api.GetResourceResponse, ck crypto.ContentKey, meta api.Metadata) (syncengine.Manifest, error) {
	if meta.Packed {
		root, err := syncengine.OpenPackRoot(res.Blob, ck)
		if err != nil {
			return syncengine.Manifest{}, fmt.Errorf("decrypt pack root: %w", err)
		}
		base, err := extractPack(cl, abs, root, ck)
		if err != nil {
			return syncengine.Manifest{}, err
		}
		base.Version = res.Version
		return base, nil
	}
	manifest, err := openRemoteTree(cl, res.Blob, ck)
	if err != nil {
		return syncengine.Manifest{}, fmt.Errorf("decrypt manifest: %w", err)
	}
	if err := runDownloads(cl, abs, manifest.Entries); err != nil {
		return syncengine.Manifest{}, err
	}
	if err := materializeDirs(abs, manifest.Dirs); err != nil {
		return syncengine.Manifest{}, err
	}
	return manifest, nil
}

// --- chunk transfer ---

// packUploader is the ChunkSink Take feeds during a push. It buffers sealed chunks
// up to ~packTarget, then hands the batch to a bounded pool that asks the server
// which chunks it lacks, packs only those, and uploads the pack. Dispatching to the
// pool instead of uploading inline overlaps chunking with the two upload round-trips,
// so the CPU keeps sealing the next pack while earlier ones are in flight — the win
// over a WAN, where each pack otherwise cost two sequential RTTs of pure stall.
//
// The pool is bounded: group.Go blocks once uploadConcurrency packs are in flight,
// which is the backpressure that keeps push memory at O(uploadConcurrency packs)
// rather than O(tree). A per-run seen set dedups a chunk shared by several files
// within the same sync; it and the candidate buffer are touched only by the single
// producer goroutine (Take calls Add sequentially), while workers touch only their
// own batch and the concurrency-safe client, so no further synchronization is needed.
type packUploader struct {
	cl       *client.Client
	target   int
	seen     map[string]bool
	cand     []candidate
	candSize int
	group    *errgroup.Group
	ctx      context.Context
	waitOnce sync.Once
	waitErr  error
}

type candidate struct {
	id string
	ct []byte
}

// uploadConcurrency bounds how many packs are checked-and-uploaded at once. Uploads
// are IO-bound (two round-trips plus server ingest), so a small fixed fan-out hides
// latency without a per-core thread; it also caps peak push memory at roughly this
// many packs (each in-flight upload holds a candidate buffer plus its assembled pack,
// both ~DefaultPackTarget).
const uploadConcurrency = 4

func newPackUploader(cl *client.Client) *packUploader {
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(uploadConcurrency)
	return &packUploader{cl: cl, target: syncengine.DefaultPackTarget, seen: map[string]bool{}, group: g, ctx: ctx}
}

// Add buffers one sealed chunk, dispatching a pack once the buffer reaches the target.
func (u *packUploader) Add(ch crypto.Chunk, ciphertext []byte) error {
	if u.seen[ch.ID] {
		return nil
	}
	u.seen[ch.ID] = true
	u.cand = append(u.cand, candidate{id: ch.ID, ct: ciphertext})
	u.candSize += len(ciphertext)
	if u.candSize >= u.target {
		return u.dispatch()
	}
	return nil
}

// Flush dispatches any buffered remainder, then waits for every in-flight upload;
// call once after the snapshot pass. The manifest PUT that roots these objects must
// not race ahead of them, so Flush is the barrier that guarantees they are all stored.
func (u *packUploader) Flush() error {
	if err := u.dispatch(); err != nil {
		return err
	}
	return u.Wait()
}

// Wait blocks until all dispatched uploads finish and returns the first error. It is
// idempotent — errgroup.Wait must not be called twice — so a caller can drain the
// pool on a snapshot error and still have Flush return the same result on success.
func (u *packUploader) Wait() error {
	u.waitOnce.Do(func() { u.waitErr = u.group.Wait() })
	return u.waitErr
}

// dispatch hands the buffered candidates to an upload worker and resets the buffer,
// transferring ownership of the batch. group.Go blocks when uploadConcurrency uploads
// are already running — the backpressure that bounds memory. If a prior upload already
// failed the group context is cancelled, so stop feeding work and surface that error.
func (u *packUploader) dispatch() error {
	if len(u.cand) == 0 {
		return nil
	}
	batch := u.cand
	u.cand = nil
	u.candSize = 0
	if u.ctx.Err() != nil {
		return u.Wait()
	}
	u.group.Go(func() error { return u.upload(batch) })
	return nil
}

// upload runs one pack's have/want gate and PutPack. It owns cand exclusively (each
// ciphertext is an independent SealChunk allocation), so it needs no locking.
func (u *packUploader) upload(cand []candidate) error {
	ids := make([]string, len(cand))
	for i, c := range cand {
		ids[i] = c.id
	}
	missing, err := u.cl.CheckChunks(ids)
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(missing))
	for _, id := range missing {
		want[id] = true
	}
	pb := syncengine.NewPackBuilder()
	for _, c := range cand {
		if want[c.id] {
			pb.Add(c.id, c.ct)
		}
	}
	if pb.Empty() {
		return nil // every candidate already on the server (a re-sync)
	}
	packID, pack := pb.Finish()
	return u.cl.PutPack(packID, pack)
}

// runDownloads materializes each entry under root, streaming its chunks from the
// packs that hold them. A pack-backed chunk source range-fetches packs on demand
// and caches a few, so neither a whole file nor the whole tree is ever in memory.
func runDownloads(cl *client.Client, root string, entries []syncengine.Entry) error {
	src, err := newPackSource(cl, distinctChunkIDs(entries))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsSymlink() {
			if err := syncengine.WriteSymlink(root, e); err != nil {
				return err
			}
			continue
		}
		if err := syncengine.MaterializeFile(root, e, src.get); err != nil {
			return err
		}
	}
	return nil
}

// packSpan is the byte range of a pack covering every object a download needs from
// it — fetched in one Range request, never the whole pack when only a few objects
// are wanted.
type packSpan struct {
	base int64
	end  int64
}

// packSource resolves chunk ids to pack byte ranges (one locate up front) and
// serves their ciphertext, fetching each pack's covering span on demand and keeping
// a small LRU so a pack shared by several files is fetched once.
type packSource struct {
	cl    *client.Client
	locs  map[string]api.ObjectLocation
	spans map[string]packSpan
	cache *packCache
}

func newPackSource(cl *client.Client, ids []string) (*packSource, error) {
	s := &packSource{
		cl:    cl,
		locs:  make(map[string]api.ObjectLocation, len(ids)),
		spans: map[string]packSpan{},
		cache: newPackCache(packCacheBytes),
	}
	if len(ids) == 0 {
		return s, nil
	}
	located, err := cl.LocateChunks(ids)
	if err != nil {
		return nil, err
	}
	for _, loc := range located {
		s.locs[loc.ID] = loc
		span, ok := s.spans[loc.PackID]
		if !ok {
			s.spans[loc.PackID] = packSpan{base: loc.Off, end: loc.Off + loc.Len}
			continue
		}
		if loc.Off < span.base {
			span.base = loc.Off
		}
		if loc.Off+loc.Len > span.end {
			span.end = loc.Off + loc.Len
		}
		s.spans[loc.PackID] = span
	}
	return s, nil
}

func (s *packSource) get(id string) ([]byte, error) {
	loc, ok := s.locs[id]
	if !ok {
		// The object was not in the locate response: the owner no longer stores it
		// (e.g. a concurrent sync superseded this version and GC reaped it). Surface
		// ErrNotFound so a manifest read can retry against the current version.
		return nil, fmt.Errorf("server could not locate chunk %s: %w", id, client.ErrNotFound)
	}
	span := s.spans[loc.PackID]
	data, ok := s.cache.get(loc.PackID)
	if !ok {
		var err error
		data, err = s.cl.GetPackRange(loc.PackID, span.base, span.end-span.base)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) < span.end-span.base {
			return nil, fmt.Errorf("pack %s returned %d bytes, want %d", loc.PackID, len(data), span.end-span.base)
		}
		s.cache.put(loc.PackID, data)
	}
	start := loc.Off - span.base
	return data[start : start+loc.Len], nil
}

// packCache is a byte-bounded LRU of fetched pack byte-ranges, so download memory is
// capped by total bytes (not a fixed pack count): a pack shared by many files is not
// re-fetched just because a few other packs were touched, while a handful of large
// packs cannot blow the budget. At least the most-recent entry is always kept, so a
// single pack larger than the budget still serves.
type packCache struct {
	capBytes int
	bytes    int
	data     map[string][]byte
	order    []string // least-recently-used first
}

func newPackCache(capBytes int) *packCache {
	return &packCache{capBytes: capBytes, data: map[string][]byte{}}
}

func (c *packCache) get(id string) ([]byte, bool) {
	b, ok := c.data[id]
	if ok {
		c.touch(id)
	}
	return b, ok
}

func (c *packCache) put(id string, b []byte) {
	if old, ok := c.data[id]; ok {
		c.bytes += len(b) - len(old)
		c.data[id] = b
		c.touch(id)
		c.evict()
		return
	}
	c.data[id] = b
	c.bytes += len(b)
	c.order = append(c.order, id)
	c.evict()
}

// evict drops least-recently-used packs until the cache fits its byte budget, always
// keeping the most-recently-used entry so get can serve the pack just fetched.
func (c *packCache) evict() {
	for c.bytes > c.capBytes && len(c.order) > 1 {
		victim := c.order[0]
		c.order = c.order[1:]
		c.bytes -= len(c.data[victim])
		delete(c.data, victim)
	}
}

func (c *packCache) touch(id string) {
	for i, v := range c.order {
		if v == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, id)
}

// partitionDeletesByDownload splits local deletes into those a download must clear
// out of its way (run before downloads) and the rest (run after, so local data is
// never removed before its replacement lands). A delete races a download when their
// paths nest either way: the delete is an ancestor of a download (a file/symlink the
// remote turned into a directory, so the directory cannot be created until it is
// gone), or the delete is a descendant of a download (a directory the remote turned
// into a file, so the file cannot be materialized until the directory is emptied).
func partitionDeletesByDownload(deletes []string, downloads []syncengine.Entry) (early, late []string) {
	for _, d := range deletes {
		deletePrefix := d + "/"
		races := false
		for _, e := range downloads {
			if strings.HasPrefix(e.Path, deletePrefix) || strings.HasPrefix(d, e.Path+"/") {
				races = true
				break
			}
		}
		if races {
			early = append(early, d)
		} else {
			late = append(late, d)
		}
	}
	return early, late
}

func distinctChunkIDs(entries []syncengine.Entry) []string {
	seen := map[string]bool{}
	var ids []string
	for _, e := range entries {
		for _, ch := range e.Chunks {
			if !seen[ch.ID] {
				seen[ch.ID] = true
				ids = append(ids, ch.ID)
			}
		}
	}
	return ids
}

// --- folder resource helpers ---

// uploadTreeObjects seals a folder's Merkle DAG, uploading the node objects the
// server lacks (via the same pack pipeline as file content), and returns the tree
// root plus the resource's full GC roots: every directory-node id unioned with every
// file-chunk id reachable from the root. The objects must be on the server before
// the resource PUT roots them, hence the flush.
func uploadTreeObjects(cl *client.Client, conv crypto.ConvergenceKey, m syncengine.Manifest) (syncengine.TreeRoot, []string, error) {
	up := newPackUploader(cl)
	root, refs, err := syncengine.SealTree(m, conv, up)
	if err != nil {
		up.Wait() // drain in-flight uploads before returning the seal error
		return syncengine.TreeRoot{}, nil, err
	}
	if err := up.Flush(); err != nil {
		return syncengine.TreeRoot{}, nil, err
	}
	return root, refs, nil
}

// openRemoteTree reconstructs a folder's manifest from its tree root: it decrypts
// the tiny root, then walks the DAG, fetching and decrypting each directory node
// from its pack. The inverse of uploadTreeObjects.
func openRemoteTree(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey) (syncengine.Manifest, error) {
	root, err := syncengine.OpenTreeRoot(blob, ck)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.OpenTree(root, newNodeFetcher(cl))
}

// openRemoteTreeReusingBase is openRemoteTree with the last-synced manifest as a node
// cache. It seals the base tree in memory once and serves any node the remote shares with
// it from those bytes instead of the server: directory nodes are content-addressed, so a
// shared id is byte-identical, an unchanged subtree is reconstructed without a single fetch,
// and only nodes on a spine that changed since the base hit the network. The result is
// identical to openRemoteTree — OpenNode re-verifies every node against its address either
// way — so a stale base can only affect which nodes are fetched, never correctness.
func openRemoteTreeReusingBase(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey, base syncengine.Manifest, conv crypto.ConvergenceKey) (syncengine.Manifest, error) {
	root, err := syncengine.OpenTreeRoot(blob, ck)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	baseCT, err := syncengine.SealTreeCiphertexts(base, conv)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	remoteFetch := newNodeFetcher(cl)
	return syncengine.OpenTree(root, func(id string) ([]byte, error) {
		if ct, ok := baseCT[id]; ok {
			return ct, nil
		}
		return remoteFetch(id)
	})
}

// newNodeFetcher returns a fetch function for directory-node objects, locating and
// range-fetching each by id and caching it (nodes are small and the DAG walk may
// revisit shared subtree ids). A node the owner no longer stores — a concurrent sync
// superseded this version and GC reaped it — surfaces as client.ErrNotFound so a
// manifest read can retry against the current version.
func newNodeFetcher(cl *client.Client) func(id string) ([]byte, error) {
	cache := map[string][]byte{}
	return func(id string) ([]byte, error) {
		if b, ok := cache[id]; ok {
			return b, nil
		}
		located, err := cl.LocateChunks([]string{id})
		if err != nil {
			return nil, err
		}
		if len(located) == 0 {
			return nil, fmt.Errorf("server could not locate tree node %s: %w", id, client.ErrNotFound)
		}
		loc := located[0]
		b, err := cl.GetPackRange(loc.PackID, loc.Off, loc.Len)
		if err != nil {
			return nil, err
		}
		cache[id] = b
		return b, nil
	}
}

func putFolder(cl *client.Client, conv crypto.ConvergenceKey, id string, m syncengine.Manifest, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	root, refs, err := uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: filepath.Base(dir), Kind: api.KindFolder, Tree: true})
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaBlob, err := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return cl.PutResource(api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, ChunkRefs: refs,
	})
}

// putFolderUpdate replaces an existing folder's manifest, conditional on the
// resource still being at expectedVersion (else the server returns a conflict).
// The encrypted metadata (the folder name sealed at init) is carried forward
// unchanged, so a sync never clobbers it.
func putFolderUpdate(cl *client.Client, conv crypto.ConvergenceKey, id string, m syncengine.Manifest, meta crypto.SealedBlob, ck crypto.ContentKey, mk crypto.MasterKey, expectedVersion int) (api.PutResourceResponse, error) {
	root, refs, err := uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return cl.PutResource(api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
		WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expectedVersion,
	})
}

func manifestFrom(byPath map[string]syncengine.Entry, version int) syncengine.Manifest {
	m := syncengine.Manifest{Version: version}
	for _, e := range byPath {
		m.Entries = append(m.Entries, e)
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	return m
}

func dirsFrom(byPath map[string]syncengine.DirEntry) []syncengine.DirEntry {
	if len(byPath) == 0 {
		return nil
	}
	out := make([]syncengine.DirEntry, 0, len(byPath))
	for _, d := range byPath {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// materializeDirs creates each tracked directory under root with its recorded mode,
// shallowest first so a parent exists before its children. It materializes empty
// directories and applies directory permission changes during clone and pull.
func materializeDirs(root string, dirs []syncengine.DirEntry) error {
	sorted := append([]syncengine.DirEntry(nil), dirs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, d := range sorted {
		if err := syncengine.MaterializeDir(root, d); err != nil {
			return err
		}
	}
	return nil
}

// removeDirs removes tracked directories deepest first (a child before its parent),
// each only if empty, so a directory still holding data is never destroyed.
func removeDirs(root string, paths []string) error {
	sorted := append([]string(nil), paths...)
	sort.Sort(sort.Reverse(sort.StringSlice(sorted)))
	for _, p := range sorted {
		if err := syncengine.RemoveDir(root, p); err != nil {
			return err
		}
	}
	return nil
}

// --- local state ---

func controlPath(root, name string) string {
	return filepath.Join(root, syncengine.ControlDir, name)
}

// writeFileAtomic writes data to a temp file in path's directory, fsyncs it, and
// renames it over path, so a crash mid-write leaves the old control-state file
// intact rather than a torn one that wedges future syncs.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeStreamAtomic(path, perm, func(f *os.File) error {
		_, err := f.Write(data)
		return err
	})
}

// recordRemoteVersion pins the freshness guard to the version this sync observed or
// just committed — including a lower one after an accepted rollback, so subsequent
// syncs stop tripping the guard. Best-effort like reclaimPacks (the sync itself
// succeeded); the sync lock makes the read-modify-write race-free.
func recordRemoteVersion(root string, version int) {
	st, err := loadState(root)
	if err != nil || st.RemoteVersion == version {
		return
	}
	st.RemoteVersion = version
	if err := saveState(root, st); err != nil {
		fmt.Fprintf(os.Stderr, "warning: recording synced version failed: %v\n", err)
	}
}

func saveState(root string, st folderState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(controlPath(root, stateFile), b, 0o600)
}

func loadState(root string) (folderState, error) {
	var st folderState
	b, err := os.ReadFile(controlPath(root, stateFile))
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(b, &st)
}

func saveBase(root string, m syncengine.Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(controlPath(root, baseFile), b, 0o600)
}

// loadBaseForSync returns the last-synced manifest and whether a usable base
// exists. A missing or corrupt base reports exists=false so the caller can refuse
// the sync — reconciling against an empty base silently resurrects deletions —
// unless the user opts into --reconcile.
func loadBaseForSync(root string) (syncengine.Manifest, bool, error) {
	var m syncengine.Manifest
	b, err := os.ReadFile(controlPath(root, baseFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		fmt.Fprintf(os.Stderr, "warning: .aqt/base.json is corrupt (%v)\n", err)
		return syncengine.Manifest{}, false, nil
	}
	return m, true, nil
}

// loadBase returns the last-synced manifest, or an empty one if none exists yet.
// Used by the offline `status`, which tolerates a missing base (it shows every
// file as new). `sync` uses loadBaseForSync, which refuses an absent base.
func loadBase(root string) (syncengine.Manifest, error) {
	var m syncengine.Manifest
	b, err := os.ReadFile(controlPath(root, baseFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// trackedRoot walks up from start to find the directory holding .aqt/.
func trackedRoot(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if fi, err := os.Stat(filepath.Join(abs, syncengine.ControlDir)); err == nil && fi.IsDir() {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", errors.New("not a tracked folder (no .aqt found); run `aqt init` first")
		}
		abs = parent
	}
}

const starterIgnore = `# aqt ignore patterns (gitignore syntax)
.git/
node_modules/
.DS_Store
*.log
`

// starterIgnoreWithGit re-includes .git for a user who chose to track their git
// history at init: aqt always ignores .git, and a leading ! overrides that.
const starterIgnoreWithGit = `# aqt ignore patterns (gitignore syntax)
# track the git repository (aqt ignores .git by default; ! re-includes it)
!.git/
node_modules/
.DS_Store
*.log
`

func writeStarterIgnore(root string, syncGit bool) error {
	path := filepath.Join(root, ".aqtignore")
	if _, err := os.Stat(path); err == nil {
		return nil // do not clobber an existing one
	}
	body := starterIgnore
	if syncGit {
		body = starterIgnoreWithGit
	}
	return os.WriteFile(path, []byte(body), 0o644)
}

// promptSyncGit asks whether to track the git repository at repo (relative to the
// tracked root, "." for the root). Declined by default — syncing a live .git
// captures its locks and loose objects, which most users do not want.
func promptSyncGit(repo string) (bool, error) {
	where := "this folder is a git repository"
	if repo != "." {
		where = fmt.Sprintf("this folder contains a git repository at %s", repo)
	}
	fmt.Fprintf(os.Stderr, "%s; aqt ignores .git by default.\n", where)
	return promptYesNo("Sync the .git directory too? [y/N]: ", false)
}

// --- misc helpers ---

func dirArg(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "."
}

func ensureEmptyDir(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s already exists and is not empty", path)
	}
	return nil
}

// abortOnConflicts refuses a sync that has both-sides changes it cannot auto-resolve,
// unless --force (local wins) was given. Directory conflicts count too: a directory mode
// or existence that diverged on both sides is surfaced like a file conflict rather than
// silently taking local, so the user is told before anything is applied.
func abortOnConflicts(actions []syncengine.Action, dirActions []syncengine.DirAction, force bool) error {
	if force {
		return nil
	}
	var conflicts []string
	for _, a := range actions {
		if a.Kind == syncengine.Conflict {
			conflicts = append(conflicts, a.Path)
		}
	}
	for _, a := range dirActions {
		if a.Kind == syncengine.Conflict {
			conflicts = append(conflicts, a.Path)
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	sort.Strings(conflicts)
	printPaths("conflict", conflicts)
	return errConflictsRemain
}

func printPlan(actions []syncengine.Action, dirActions []syncengine.DirAction) error {
	if len(actions) == 0 && len(dirActions) == 0 {
		fmt.Println("already in sync")
		return nil
	}
	for _, a := range actions {
		fmt.Printf("%-13s %s\n", a.Kind, a.Path)
	}
	for _, a := range dirActions {
		fmt.Printf("%-13s %s/\n", a.Kind, a.Path) // trailing slash marks a directory
	}
	return nil
}

func printPaths(label string, paths []string) {
	for _, p := range paths {
		fmt.Printf("%-9s %s\n", label, p)
	}
}

func summarize(uploads, downloads []syncengine.Entry, localDeletes []string, pushed bool) {
	fmt.Printf("synced: %d up, %d down, %d removed locally\n", len(uploads), len(downloads), len(localDeletes))
	_ = pushed
}

// reclaimPacks sweeps the packs the just-superseded manifest no longer references,
// throttled to once per gcMinInterval per folder so a burst of syncs (notably the
// watch daemon) does not fire a full server sweep every time. The last-swept time is
// recorded in folder state; the sync lock makes the read-modify-write race-free.
// Best-effort: a sync that uploaded fine should not fail on cleanup.
func reclaimPacks(root string, cl *client.Client) {
	st, err := loadState(root)
	stateOK := err == nil
	if stateOK && st.LastGC > 0 && time.Since(time.Unix(st.LastGC, 0)) < gcMinInterval {
		return
	}
	r, err := cl.GC()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: pack GC failed: %v\n", err)
		return
	}
	if r.DeletedPacks > 0 {
		fmt.Fprintf(os.Stderr, "reclaimed %d packs (%d bytes)\n", r.DeletedPacks, r.FreedBytes)
	}
	if r.RepackedPacks > 0 {
		fmt.Fprintf(os.Stderr, "compacted %d packs (%d bytes)\n", r.RepackedPacks, r.ReclaimedBytes)
	}
	// Only record the sweep if state was readable, so a transient read error GCs
	// unthrottled next time rather than clobbering state.json with a partial record.
	if stateOK {
		st.LastGC = time.Now().Unix()
		_ = saveState(root, st)
	}
}
