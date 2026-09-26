// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
	textmerge "github.com/aquitano/aqt-sync/internal/syncengine/merge"
)

// applyCtx bundles the state applySync needs, keeping its signature readable.
type applyCtx struct {
	root       string
	cl         *client.Client
	opts       syncOptions
	base       syncengine.Manifest
	local      syncengine.Manifest
	remote     syncengine.Manifest
	conv       crypto.ConvergenceKey
	ck         crypto.ContentKey
	mk         crypto.MasterKey
	meta       crypto.SealedBlob // the resource's existing sealed metadata, carried forward
	visibility api.Visibility    // the resource's current visibility, carried forward (a shared folder stays shared)
	version    int
	id         string
	mode       conflictMode     // conflictCopy preserves the remote side of each conflict as a copy
	host       string           // sanitized hostname stamped into conflict-copy names (copy mode)
	now        time.Time        // sync wall-clock, stamped into conflict-copy names (copy mode)
	pushStart  time.Time        // when the snapshot upload pass began; arms the pre-PUT chunk re-check on long pushes
	copyMemo   conflictCopyMemo // copies materialized by earlier retry attempts, shared across the retry loop
	selector   syncengine.ChunkSelector
}

type cleanMerge struct {
	path     string
	data     []byte
	entry    syncengine.Entry
	original syncengine.Entry
}

// mergeConflictBytes is the pure per-file policy seam used by sync and fuzz tests:
// a clean eligible merge replaces the primary with no copy; every other input keeps
// local primary bytes and preserves remote bytes as the fallback copy.
func mergeConflictBytes(base, local, remote []byte) (primary, copy []byte, merged bool) {
	if textmerge.Eligible(base, local, remote) {
		if result, clean := textmerge.ThreeWay(base, local, remote); clean {
			return result, nil, true
		}
	}
	return local, remote, false
}

// maxMergedBytesHeld bounds the merged content resolveTextMerges keeps live. Each
// result has to survive until the post-CAS write, so the peak is the sum over every
// conflict in the sync, not the per-file MaxTextSize cap. Conflicts past the budget
// take the conflict-copy path, which streams to disk and holds nothing. A var so a
// test can reach the boundary without allocating its way there.
var maxMergedBytesHeld = 128 << 20

// resolveTextMerges materializes the three versions of each regular-file conflict,
// combines clean non-overlapping edits, and seals the result for the pending PUT.
// A missing base object, binary/oversized content, delete/modify pair, overlapping
// edit, or exhausted merge budget is returned in fallback so normal copy semantics
// preserve both sides.
func (app *application) resolveTextMerges(c applyCtx, actions []syncengine.Action, localByPath, remoteByPath map[string]syncengine.Entry) ([]cleanMerge, map[string]bool, error) {
	fallback := map[string]bool{}
	baseByPath := c.base.ByPath()
	var candidates []string
	var sourceEntries []syncengine.Entry
	for _, a := range actions {
		if a.Kind != syncengine.Conflict {
			continue
		}
		le, lok := localByPath[a.Path]
		be, bok := baseByPath[a.Path]
		re, rok := remoteByPath[a.Path]
		if !lok || !bok || !rok || le.IsSymlink() || be.IsSymlink() || re.IsSymlink() ||
			le.Size > textmerge.MaxTextSize || be.Size > textmerge.MaxTextSize || re.Size > textmerge.MaxTextSize {
			fallback[a.Path] = true
			continue
		}
		candidates = append(candidates, a.Path)
		sourceEntries = append(sourceEntries, be, re)
	}
	if len(candidates) == 0 {
		return nil, fallback, nil
	}
	source, err := packio.NewSource(c.cl, distinctChunkIDs(sourceEntries))
	if err != nil {
		return nil, nil, err
	}
	uploader := app.newUploader(c.cl, nil)
	defer func() { _ = uploader.Wait() }()
	var clean []cleanMerge
	var held int
	var deferred []string
	for _, path := range candidates {
		le := localByPath[path]
		be := baseByPath[path]
		re := remoteByPath[path]
		localData, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(path)))
		if err != nil {
			return nil, nil, err
		}
		remoteData, err := syncengine.FileBytes(re, source.Get)
		if err != nil {
			if errors.Is(err, client.ErrNotFound) {
				return nil, nil, client.ErrConflict
			}
			return nil, nil, err
		}
		baseData, err := syncengine.FileBytes(be, source.Get)
		if errors.Is(err, client.ErrNotFound) {
			fallback[path] = true
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		data, _, ok := mergeConflictBytes(baseData, localData, remoteData)
		if !ok {
			fallback[path] = true
			continue
		}
		if held+len(data) > maxMergedBytesHeld {
			fallback[path] = true
			deferred = append(deferred, path)
			continue
		}
		entry, err := syncengine.EntryFromBytes(path, data, le.Mode, c.conv, c.selector, uploader)
		if err != nil {
			return nil, nil, err
		}
		held += len(data)
		clean = append(clean, cleanMerge{path: path, data: data, entry: entry, original: le})
	}
	if err := uploader.Flush(); err != nil {
		return nil, nil, err
	}
	// Say what the budget cost. A silently copied conflict looks like an overlap the
	// merge could not resolve, which sends the user hunting for a conflict that is not
	// there; re-running after resolving some of these merges the rest.
	if len(deferred) > 0 {
		fmt.Fprintf(os.Stderr,
			"note: merged %s of conflicting text, the per-sync limit; %d further conflict(s) kept both versions instead. Re-run `aqt sync` to merge them.\n",
			cliutil.HumanBytes(int64(held)), len(deferred))
	}
	return clean, fallback, nil
}

// applyState is the manifest half of the working set the phases below hand to one
// another: the manifest a push commits, and the base this machine records afterwards.
type applyState struct {
	merged      map[string]syncengine.Entry
	newBase     map[string]syncengine.Entry
	mergedDirs  map[string]syncengine.DirEntry
	newBaseDirs map[string]syncengine.DirEntry
}

func newApplyState(c applyCtx) applyState {
	return applyState{
		merged:      c.remote.ByPath(),
		newBase:     c.base.ByPath(),
		mergedDirs:  c.remote.DirsByPath(),
		newBaseDirs: c.base.DirsByPath(),
	}
}

// actionSides is what one action stream reconciles: the two sides as they stand now,
// and the two manifests being built from them. merged and newBase are written in place.
type actionSides[T any] struct {
	local, remote   map[string]T
	merged, newBase map[string]T
}

// applyWork is the transfer work one action stream produces.
type applyWork[T any] struct {
	uploads       []T
	downloads     []T
	localDeletes  []string
	remoteChanged bool
}

// classifyActions folds one action stream into the merged manifest and the new base,
// and collects the transfers the apply pass will run. Files and tracked directories
// take the same four-case gate over different element types; --pull-only and
// --push-only drop the half the caller asked to skip. Nothing is uploaded for a
// directory — it rides in the manifest — so a directory stream's uploads are unused.
func classifyActions[T any](actions []syncengine.Action, sides actionSides[T], push, pull bool) applyWork[T] {
	var w applyWork[T]
	for _, a := range actions {
		switch a.Kind {
		case syncengine.Upload, syncengine.Conflict: // Conflict only survives here with --force
			if !push {
				continue
			}
			e, ok := sides.local[a.Path]
			if !ok {
				// A conflict resolved local-wins where the path is gone locally (local
				// delete vs remote modify): local winning means deleting it on the remote
				// too. Recording the zero element here would PUT a path-less empty entry,
				// drop the remote edit, and corrupt the manifest (several such paths
				// collapse to one on reload).
				delete(sides.merged, a.Path)
				delete(sides.newBase, a.Path)
				w.remoteChanged = true
				continue
			}
			sides.merged[a.Path] = e
			sides.newBase[a.Path] = e
			w.uploads = append(w.uploads, e)
			w.remoteChanged = true
		case syncengine.DeleteRemote:
			if !push {
				continue
			}
			delete(sides.merged, a.Path)
			delete(sides.newBase, a.Path)
			w.remoteChanged = true
		case syncengine.Download:
			if !pull {
				continue
			}
			e := sides.remote[a.Path]
			w.downloads = append(w.downloads, e)
			sides.newBase[a.Path] = e
		case syncengine.DeleteLocal:
			if !pull {
				continue
			}
			w.localDeletes = append(w.localDeletes, a.Path)
			delete(sides.newBase, a.Path)
		}
	}
	return w
}

// foldConvergedPaths records the paths the two sides already agree on, which Plan emits
// no action for. Content that converged to the same hash goes into the new base, or it
// stays "changed on both sides" forever: a later remote-only delete is then misread as a
// local add, the file is re-pushed, and the deletion never propagates. Keep the local
// entry (same hash as remote): base.json is local-only bookkeeping, and the local entry
// carries this machine's mtime, so the next sync stat-fast-paths the file instead of
// re-hashing it.
func foldConvergedPaths(st applyState, localByPath, remoteByPath map[string]syncengine.Entry, localDirs, remoteDirs map[string]syncengine.DirEntry) {
	for p, le := range localByPath {
		if re, ok := remoteByPath[p]; ok && le.Hash == re.Hash {
			st.newBase[p] = le
		}
	}
	dropVanished(st.newBase, localByPath, remoteByPath)
	dropVanished(st.newBaseDirs, localDirs, remoteDirs)
}

// dropVanished is the deletion counterpart of the fold: a path gone on both sides plans
// no action (agreement, not conflict), so nothing else removes its base record, and it
// would read as a forever-pending local delete.
func dropVanished[T any](recorded, local, remote map[string]T) {
	for p := range recorded {
		_, l := local[p]
		_, r := remote[p]
		if !l && !r {
			delete(recorded, p)
		}
	}
}

// materializeConflictCopies preserves the remote side of every content conflict as a
// local copy BEFORE any local-wins remote mutation runs, so the remote bytes survive on
// disk even if the push dies mid-apply. The primary path is resolved local-wins by the
// classifier. Copies land at fresh, collision-checked paths, so they never overwrite
// anything and skip the download drift guard.
func (app *application) materializeConflictCopies(c applyCtx, actions []syncengine.Action, mergeFallback map[string]bool, remoteByPath map[string]syncengine.Entry) error {
	if c.mode != conflictCopy && c.mode != conflictMerge {
		return nil
	}
	copyActions := actions
	if c.mode == conflictMerge {
		copyActions = nil
		for _, action := range actions {
			if mergeFallback[action.Path] {
				copyActions = append(copyActions, action)
			}
		}
	}
	copies := planConflictCopies(c.root, copyActions, remoteByPath, c.host, c.now, c.copyMemo)
	if len(copies) == 0 {
		return nil
	}
	entries := copyEntries(copies)
	cpProg := app.newProgressBar("writing conflict copies", entriesBytes(entries))
	// A conflict copy lands at a fresh untracked path, so it has no base entry to
	// stamp an mtime on; the next scan picks it up as a local add.
	_, cpErr := runDownloads(c.cl, nil, c.root, entries, cpProg)
	cpProg.finish(cpErr == nil)
	if cpErr != nil {
		return cpErr
	}
	// Record only after the write lands, so a failed/partial download is re-planned
	// rather than memoized as done; a retry rewrites the same path.
	for _, cp := range copies {
		c.copyMemo[cp.orig] = conflictCopyRecord{copyPath: cp.entry.Path, remoteHash: cp.entry.Hash}
		// stderr under --json so the summary object stays the only stdout output;
		// -q drops the line entirely, like every other per-file line.
		if app.quiet {
			continue
		}
		out := os.Stdout
		if app.json {
			out = os.Stderr
		}
		fmt.Fprintf(out, "conflict-copy %s -> %s\n", cp.orig, cp.entry.Path)
	}
	return nil
}

// pushMergedManifest commits the server-side change FIRST, before any local file is
// touched, so a version conflict (another sync committed first) returns with nothing
// half-applied on disk and the caller can re-plan cleanly. The objects these entries
// reference were already packed and uploaded during the snapshot pass; this commits
// only the merged manifest that roots them, and returns the version it landed as.
func (app *application) pushMergedManifest(c applyCtx, st applyState) (int, error) {
	manifest := manifestFrom(st.merged, c.version+1)
	manifest.Dirs = dirsFrom(st.mergedDirs)
	if err := rearmUploadedChunks(c.cl.CheckChunks, distinctChunkIDs(manifest.Entries), c.pushStart); err != nil {
		return 0, err
	}
	resp, err := app.putFolderUpdate(c.cl, c.conv, c.id, c.visibility, manifest, c.meta, c.ck, c.mk, c.version)
	if err != nil {
		return 0, err // client.ErrConflict on a stale version: retried by the caller
	}
	reclaimPacks(c.root, c.cl)
	return resp.Version, nil
}

// landCleanMerges writes each merged file to disk now that the root durably references
// the merged entry, and only if the path still holds the entry resolveTextMerges read.
// A newer local edit in the merge->PUT window wins on disk: its merge is reported as a
// conflict, its base record is left at the pre-merge entry, and the next sync re-plans
// it against the committed merge.
func landCleanMerges(c applyCtx, merges []cleanMerge, newBase map[string]syncengine.Entry) (landed []cleanMerge, conflicts []string, err error) {
	baseByPath := c.base.ByPath()
	landed = make([]cleanMerge, 0, len(merges))
	for _, resolution := range merges {
		hash, exists, isDir, err := syncengine.HashOnDisk(c.root, resolution.path)
		if err != nil {
			return nil, nil, err
		}
		if !exists || isDir || (hash != resolution.original.Hash && hash != resolution.entry.Hash) {
			if baseEntry, ok := baseByPath[resolution.path]; ok {
				newBase[resolution.path] = baseEntry
			} else {
				delete(newBase, resolution.path)
			}
			conflicts = append(conflicts, resolution.path)
			continue
		}
		mtime, err := syncengine.WriteFile(c.root, resolution.entry, resolution.data)
		if err != nil {
			return nil, nil, err
		}
		// A merged file is built in memory, so its entry carries no mtime either.
		stampMTimes(newBase, map[string]int64{resolution.path: mtime})
		landed = append(landed, resolution)
	}
	return landed, conflicts, nil
}

// localApply is the disk-side work the push leaves: what to write, and what to remove.
type localApply struct {
	downloads    []syncengine.Entry
	localDeletes []string
	dirDownloads []syncengine.DirEntry
	dirRemovals  []string
}

// applyLocalTree brings the local tree in line with the manifest just committed. It
// returns the work as executed: a case-only rename consumes the delete that would have
// destroyed its target, so the summary reports what actually happened.
func (app *application) applyLocalTree(c applyCtx, st applyState, w localApply, foldFS bool) (localApply, error) {
	// A case-only rename arrives as an add+delete pair whose two paths resolve to
	// the same physical file on a case-folding filesystem: the download lands on the
	// very file the late delete then destroys, and the next sync pushes that loss
	// fleet-wide. Convert each such delete into a real rename (executed before any
	// other byte moves, shallowest first so a renamed directory carries its subtree)
	// and drop it from the delete lists.
	if foldFS {
		var caseRenames []caseRename
		caseRenames, w.localDeletes, w.dirRemovals = planCaseOnlyRenames(w.localDeletes, w.dirRemovals, st.newBase, st.newBaseDirs)
		for _, r := range caseRenames {
			if err := syncengine.RenameCaseOnly(c.root, r.from, r.to); err != nil {
				return w, err
			}
		}
	}

	// A local file or symlink the remote turned into a directory must be removed before
	// the download that creates that directory, or the download would write through the
	// stale entry (refused) or the later delete would hit a now-populated directory.
	// Every other delete stays after the downloads, so local data is never removed
	// before its replacement lands.
	earlyDeletes, lateDeletes := partitionDeletesByDownload(w.localDeletes, w.downloads, foldFS)
	for _, p := range earlyDeletes {
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return w, err
		}
	}
	dlProg := app.newProgressBar("downloading", entriesBytes(w.downloads))
	dlMTimes, dlErr := runDownloads(c.cl, nil, c.root, w.downloads, dlProg)
	dlProg.finish(dlErr == nil)
	if dlErr != nil {
		return w, dlErr
	}
	stampMTimes(st.newBase, dlMTimes)
	for _, p := range lateDeletes {
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return w, err
		}
	}

	// Directories last: create/chmod after files land (so a directory exists and gets
	// its mode), and remove emptied directories after file deletes.
	if err := syncengine.MaterializeDirs(c.root, w.dirDownloads); err != nil {
		return w, err
	}
	if err := removeDirs(c.root, w.dirRemovals); err != nil {
		return w, err
	}
	// The deletes above prune now-empty parents blind to the tracked set (RemoveFile
	// and RemoveDir), so emptying a tracked directory takes the directory with it —
	// and the next sync would read that as a local delete and push it fleet-wide.
	// Recreate whatever the pruning took from the merged directory set.
	if len(earlyDeletes)+len(lateDeletes)+len(w.dirRemovals) > 0 {
		if err := syncengine.EnsureDirs(c.root, dirsFrom(st.newBaseDirs)); err != nil {
			return w, err
		}
	}
	return w, nil
}

// persistSyncState records what this pass established: the new base manifest, and the
// remote version it was reconciled against.
func (app *application) persistSyncState(c applyCtx, st applyState, syncedVersion int) error {
	newBaseManifest := manifestFrom(st.newBase, c.version+1)
	newBaseManifest.Dirs = dirsFrom(st.newBaseDirs)
	if err := folderstate.SaveBase(c.root, app.profile, newBaseManifest); err != nil {
		return err
	}
	folderstate.RecordRemoteVersion(c.root, syncedVersion)
	return nil
}

// applySync runs the reconciliation the plan describes, in the one order that is safe:
// classify both action streams, refuse case collisions, preserve conflicting remote
// bytes, commit the merged manifest to the server, then touch local files.
func (app *application) applySync(c applyCtx, actions []syncengine.Action, dirActions []syncengine.Action) error {
	// c holds by-value copies of the caller's keys ([32]byte, so the caller's
	// deferred wipes do not reach them); scrub this frame's copies on exit.
	defer c.ck.Wipe()
	defer c.conv.Wipe()
	defer c.mk.Wipe()
	push := !c.opts.pullOnly
	pull := !c.opts.pushOnly
	localByPath := c.local.ByPath()
	remoteByPath := c.remote.ByPath()
	var cleanMerges []cleanMerge
	mergeFallback := map[string]bool{}
	if c.mode == conflictMerge {
		var err error
		cleanMerges, mergeFallback, err = app.resolveTextMerges(c, actions, localByPath, remoteByPath)
		if err != nil {
			return err
		}
		for _, resolution := range cleanMerges {
			localByPath[resolution.path] = resolution.entry
		}
	}

	st := newApplyState(c)
	files := classifyActions(actions, actionSides[syncengine.Entry]{
		local: localByPath, remote: remoteByPath, merged: st.merged, newBase: st.newBase,
	}, push, pull)
	// Tracked directories (empty dirs and modes) reconcile alongside files, but their
	// filesystem ops run in a dedicated pass after files. Any remaining directory
	// conflict has already been accepted by --force.
	localDirs := c.local.DirsByPath()
	remoteDirs := c.remote.DirsByPath()
	dirs := classifyActions(dirActions, actionSides[syncengine.DirEntry]{
		local: localDirs, remote: remoteDirs, merged: st.mergedDirs, newBase: st.newBaseDirs,
	}, push, pull)
	remoteChanged := files.remoteChanged || dirs.remoteChanged

	foldConvergedPaths(st, localByPath, remoteByPath, localDirs, remoteDirs)

	// A push must not commit case-twins to the server — they arm a data-loss trap
	// for every case-insensitive device — and a pull onto a case-folding filesystem
	// must not land them locally. An inherited remote twin deliberately wedges the
	// push too: renaming one member locally is the resolution, and the error says so.
	foldFS := syncengine.CaseInsensitiveDir(c.root)
	if (push && remoteChanged) || foldFS {
		if err := refuseCaseCollisions(manifestFrom(st.merged, 0).Entries, dirsFrom(st.mergedDirs)); err != nil {
			return err
		}
	}

	if err := app.materializeConflictCopies(c, actions, mergeFallback, remoteByPath); err != nil {
		return err
	}

	syncedVersion := c.version
	if push && remoteChanged {
		version, err := app.pushMergedManifest(c, st)
		if err != nil {
			return err
		}
		syncedVersion = version
	}

	landedMerges, mergeConflicts, err := landCleanMerges(c, cleanMerges, st.newBase)
	if err != nil {
		return err
	}

	downloads, localDeletes, conflicts, err := filterDriftedTargets(c.root, files.downloads, files.localDeletes, localByPath, remoteByPath, c.base.ByPath(), st.newBase)
	if err != nil {
		return err
	}
	conflicts = append(conflicts, mergeConflicts...)

	work, err := app.applyLocalTree(c, st, localApply{
		downloads: downloads, localDeletes: localDeletes,
		dirDownloads: dirs.downloads, dirRemovals: dirs.localDeletes,
	}, foldFS)
	if err != nil {
		return err
	}

	if err := app.persistSyncState(c, st, syncedVersion); err != nil {
		return err
	}
	mergedPaths := make([]string, len(landedMerges))
	for i, resolution := range landedMerges {
		mergedPaths[i] = resolution.path
	}
	app.summarize(files.uploads, work.downloads, work.localDeletes, mergedPaths)
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		printPaths("conflict", conflicts)
		return errConflictsRemain
	}
	return nil
}

// filterDriftedTargets re-verifies the on-disk bytes of every file we are about to
// overwrite or delete still match what the snapshot saw. A mtime-preserving edit
// (cp -p, touch -r, archive extract) or any edit landing in the snapshot->apply
// window would otherwise be silently clobbered by a remote download or delete. A
// target whose content drifted is downgraded to a conflict: its destructive op is
// skipped and its base entry left untouched, so the next sync re-plans it as a
// both-sides change to resolve (or --force to take local).
func filterDriftedTargets(root string, downloads []syncengine.Entry, localDeletes []string, localByPath, remoteByPath, baseByPath, newBase map[string]syncengine.Entry) ([]syncengine.Entry, []string, []string, error) {
	checkSafe := func(path string, isDownload bool) (bool, error) {
		h, exists, isDir, err := syncengine.HashOnDisk(root, path)
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
			return nil, nil, nil, err
		}
		if safe {
			keptDownloads = append(keptDownloads, e)
		} else {
			restore(e.Path)
		}
	}
	keptDeletes := make([]string, 0, len(localDeletes))
	for _, p := range localDeletes {
		safe, err := checkSafe(p, false)
		if err != nil {
			return nil, nil, nil, err
		}
		if safe {
			keptDeletes = append(keptDeletes, p)
		} else {
			restore(p)
		}
	}
	return keptDownloads, keptDeletes, conflicts, nil
}

// partitionDeletesByDownload splits local deletes into those a download must clear
// out of its way (run before downloads) and the rest (run after, so local data is
// never removed before its replacement lands). A delete races a download when their
// paths nest either way: the delete is an ancestor of a download (a file/symlink the
// remote turned into a directory, so the directory cannot be created until it is
// gone), or the delete is a descendant of a download (a directory the remote turned
// into a file, so the file cannot be materialized until the directory is emptied).
// On a case-folding filesystem (fold) the nesting compares folded names
// (syncengine.FoldName), because that is how the filesystem will resolve the paths.
// A remote directory rename arrives as N deletes plus N downloads with no nesting
// between them, so this must not compare every pair: each delete answers both
// nesting questions against the download keys directly — a sorted slice for "is
// any download under this delete?" (keys sharing a prefix sort contiguously, so
// the first key at or after the prefix decides) and a set for "is any ancestor of
// this delete a download?" (a path has only O(depth) ancestors).
func partitionDeletesByDownload(deletes []string, downloads []syncengine.Entry, fold bool) (early, late []string) {
	key := func(p string) string {
		if fold {
			return syncengine.FoldName(p)
		}
		return p
	}
	sorted := make([]string, len(downloads))
	downloadKeys := make(map[string]struct{}, len(downloads))
	for i, e := range downloads {
		k := key(e.Path)
		sorted[i] = k
		downloadKeys[k] = struct{}{}
	}
	sort.Strings(sorted)
	for _, d := range deletes {
		kd := key(d)
		deletePrefix := kd + "/"
		i := sort.SearchStrings(sorted, deletePrefix)
		races := i < len(sorted) && strings.HasPrefix(sorted[i], deletePrefix)
		for j := 0; !races && j < len(kd); j++ {
			if kd[j] == '/' {
				_, races = downloadKeys[kd[:j]]
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

// caseRename is a local delete converted into a rename: its target survives the
// merge under a name differing only by case or Unicode normalization, so on a
// case-folding filesystem the delete and the survivor are one physical entry.
type caseRename struct {
	from, to string
}

// planCaseOnlyRenames pairs each pending local delete (file or directory) with a
// surviving merged path that folds to the same name (syncengine.FoldName). Each pair
// becomes a rename and leaves the delete lists; everything unpaired is kept. Only
// meaningful on a case-folding filesystem, where applying such a delete after its
// survivor lands would destroy the survivor. Renames come back sorted shallowest
// first, so a renamed directory moves before its children are retargeted.
func planCaseOnlyRenames(localDeletes, dirRemovals []string, newBase map[string]syncengine.Entry, newBaseDirs map[string]syncengine.DirEntry) (renames []caseRename, keptDeletes, keptDirRemovals []string) {
	fileSurvivors := make(map[string]string, len(newBase))
	for p := range newBase {
		fileSurvivors[syncengine.FoldName(p)] = p
	}
	dirSurvivors := make(map[string]string, len(newBaseDirs))
	for p := range newBaseDirs {
		dirSurvivors[syncengine.FoldName(p)] = p
	}
	for _, d := range localDeletes {
		if s, ok := fileSurvivors[syncengine.FoldName(d)]; ok && s != d {
			renames = append(renames, caseRename{from: d, to: s})
		} else {
			keptDeletes = append(keptDeletes, d)
		}
	}
	for _, d := range dirRemovals {
		if s, ok := dirSurvivors[syncengine.FoldName(d)]; ok && s != d {
			renames = append(renames, caseRename{from: d, to: s})
		} else {
			keptDirRemovals = append(keptDirRemovals, d)
		}
	}
	sort.Slice(renames, func(i, j int) bool { return renames[i].from < renames[j].from })
	return renames, keptDeletes, keptDirRemovals
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
