// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

const (
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

func (app *application) syncCmd() *cobra.Command {
	var opts syncOptions
	cmd := &cobra.Command{
		Use:   "sync [dir]",
		Short: "Two-way reconcile a tracked folder with the server",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return app.runSyncCmd(dirArg(args), opts) },
	}
	f := cmd.Flags()
	f.BoolVar(&opts.pushOnly, "push-only", false, "only upload local changes")
	f.BoolVar(&opts.pullOnly, "pull-only", false, "only download remote changes")
	f.BoolVar(&opts.dryRun, "dry-run", false, "print the plan without making changes")
	f.BoolVar(&opts.force, "force", false, "resolve conflicts in favor of local")
	f.BoolVar(&opts.reconcile, "reconcile", false, "reconcile without a base (.aqt/base.json missing): one-sided differences become conflicts to review")
	f.BoolVar(&opts.rehash, "rehash", false, "re-hash every file instead of trusting size+mtime (catches edits that preserve them)")
	f.BoolVar(&opts.acceptRollback, "accept-rollback", false, "proceed although the server reports an older version than previously seen (restored from backup): reconcile from scratch, one-sided differences become conflicts to review")
	f.StringVar(&opts.conflicts, "conflicts", "", "conflict handling: block (default), copy, or merge (three-way text merge; falls back to copy)")
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	markProgressSupported(cmd)
	return cmd
}

// warnSkipped names the tracked paths a scan could not read. Such a path keeps
// whatever the base recorded for it, so it is neither uploaded nor deleted and the
// command proceeds — but a file that has quietly stopped syncing is worth a line on
// stderr. Only the first few are named; one unreadable directory stands in for its
// whole subtree, so the list is short unless permissions are broken file by file.
func warnSkipped(skipped []syncengine.SkippedPath) {
	const show = 5
	for _, s := range skipped[:min(show, len(skipped))] {
		fmt.Fprintf(os.Stderr, "warning: skipped %s: %v; it stays as last synced (fix the cause or add it to .aqtignore)\n", s.Path, s.Err)
	}
	if rest := len(skipped) - show; rest > 0 {
		fmt.Fprintf(os.Stderr, "warning: and %d more skipped path(s)\n", rest)
	}
}

// refuseCaseCollisions fails an operation whose manifest holds paths that differ
// only by case. Materializing them on a case-insensitive filesystem (the macOS and
// Windows defaults) collapses them into one file, last writer wins, and the next
// sync uploads the survivor's bytes under both names — so the collision destroys
// both copies on the server, silently. Push refuses regardless of the local
// filesystem: creating such a tree remotely arms the same trap for every other
// device.
func refuseCaseCollisions(entries []syncengine.Entry, dirs []syncengine.DirEntry) error {
	groups := syncengine.CaseCollisions(entries, dirs)
	if len(groups) == 0 {
		return nil
	}
	const show = 3
	names := make([]string, 0, show)
	for _, g := range groups[:min(show, len(groups))] {
		names = append(names, strings.Join(g, " / "))
	}
	suffix := ""
	if rest := len(groups) - show; rest > 0 {
		suffix = fmt.Sprintf(" and %d more", rest)
	}
	return fmt.Errorf("refusing to sync case-colliding paths (%s%s): a case-insensitive filesystem would collapse each group into one file and the next sync would destroy the others; rename or .aqtignore all but one of each",
		strings.Join(names, "; "), suffix)
}

type syncOptions struct {
	pushOnly       bool
	pullOnly       bool
	dryRun         bool
	force          bool
	reconcile      bool
	rehash         bool
	acceptRollback bool
	conflicts      string // "" (use .aqtconfig, else block), "block", "copy", or "merge"
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

// gitGuardPoll is how often the manual-sync git guard rechecks a busy repo while
// waiting for it to go idle (bounded by gitIdleWaitOnce).
const gitGuardPoll = 250 * time.Millisecond

// runSyncCmd is the `aqt sync` command entry. It arms the git-busy guard the watch
// daemon already applies, then delegates to runSync. Keeping the guard here — not in
// runSync — leaves the watcher (which does its own git check) and direct callers
// unchanged, so only an interactive sync gains the wait.
func (app *application) runSyncCmd(dir string, opts syncOptions) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	if err := guardTrackedGit(root, opts); err != nil {
		return err
	}
	return app.runSync(root, opts)
}

// guardTrackedGit holds a push back while a tracked .git is mid git-operation, so a
// manual sync of a repo (the Brain-vault shape: a folder that syncs its own .git)
// cannot capture a half-written index or packfile. It applies only when the folder
// actually tracks .git (a `!.git/` re-include) and the guard is enabled in .aqtconfig;
// a pull-only or dry-run pushes nothing, so it is exempt. On a repo that stays busy
// past the wait it defers rather than push, mapping to the same exit 75 as
// `watch --once` so cron can tell "deferred" from "failed".
func guardTrackedGit(root string, opts syncOptions) error {
	return guardTrackedGitWait(root, opts, gitIdleWaitOnce, gitGuardPoll)
}

// guardTrackedGitWait is guardTrackedGit with the wait bound injected, so a test can
// exercise the busy-defer path without blocking for the full production timeout.
func guardTrackedGitWait(root string, opts syncOptions, timeout, poll time.Duration) error {
	if opts.pullOnly || opts.dryRun {
		return nil
	}
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	if !cfg.Watch.GitGuardEnabled() {
		return nil
	}
	if waitTrackedGitIdle(root, timeout, poll) {
		return nil
	}
	return fmt.Errorf("%w (a git operation is in progress in a tracked repository; retry when it "+
		"finishes, or set \"watch\":{\"gitGuard\":false} in .aqtconfig to disable this guard)", errWatchSkipped)
}

// waitTrackedGitIdle waits up to timeout for every tracked-.git repository under root
// to leave its git operation, polling every poll. It returns true once none is busy,
// or false if one stays busy past the deadline. A read error can't confirm a lock, so
// trackedGitBusy reports "not busy" and the sync proceeds rather than block forever.
func waitTrackedGitIdle(root string, timeout, poll time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if busy, _ := trackedGitBusy(root); !busy {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(poll)
	}
}

func (app *application) runSync(dir string, opts syncOptions) error {
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
	// Under the lock: binding may back-fill state.json, which must not race a
	// concurrent sync's own state write.
	if err := app.bindTrackedRoot(root); err != nil {
		return err
	}
	// A kill mid-swap during an in-place restore leaves a half-emptied root that
	// scans as mass deletion; syncing it would push those deletions fleet-wide.
	if torn, err := loadMarker[interruptedRestore](root, restoreMarkerFile); err != nil {
		return err
	} else if torn.Present {
		return fmt.Errorf("an in-place restore of this folder (snapshot %s) was interrupted mid-swap, so the "+
			"working tree may be incomplete; re-run `aqt restore %s --in-place` to finish it, or move the "+
			"original contents back from the .aqt-backup-* directory beside this folder and then remove "+
			".aqt/%s", torn.Payload.SnapshotID, torn.Payload.SnapshotID, restoreMarkerFile)
	}
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	mode, err := effectiveConflictMode(opts, cfg)
	if err != nil {
		return err
	}
	if mode == conflictCopy || mode == conflictMerge {
		if err := validateResolvingMode(opts, mode); err != nil {
			return err
		}
	}
	selector, err := cfg.ChunkSelector()
	if err != nil {
		return err
	}
	sess, err := app.openSyncSession(root, opts)
	if err != nil {
		return err
	}
	defer sess.Wipe()
	// The master key is read through the session rather than copied out; a local copy
	// would outlive the deferred wipe.
	base, baseExists, cl := sess.base, sess.baseExists, sess.cl
	conv := crypto.DeriveConvergenceKey(sess.mk)
	defer conv.Wipe()

	// Snapshot the working tree once; it does not change between retries. When this
	// sync will push, stream every changed file through the chunker and upload the
	// packs the server lacks as we go, so memory stays O(one pack) regardless of
	// tree size; the manifest we later PUT references those objects. A pull-only or
	// dry-run pass uploads nothing, so a metadata+hash scan is enough to plan.
	pushStart := time.Now()
	var local syncengine.Manifest
	if opts.pullOnly || opts.dryRun {
		var scanBase *syncengine.Manifest
		if baseExists {
			scanBase = &base
		}
		local, err = syncengine.ScanReusing(root, scanBase, opts.rehash)
		if err != nil {
			return err
		}
		warnSkipped(local.Skipped)
	} else {
		// The bar reports bytes moved rather than a percentage. A push learns its byte
		// count only by walking the tree, and Take's walk below is the upload itself, so
		// sizing it up front cost a second full-tree walk — and a second hash of every
		// file on a first sync, where there is no base to stat against.
		prog := app.newUnsizedBar("uploading")
		up := app.newUploader(cl, prog)
		local, err = syncengine.Take(root, conv, selector, &base, up, opts.rehash)
		if err != nil {
			_ = up.Wait() // drain in-flight uploads before returning the snapshot error
			prog.finish(false)
			return err
		}
		if err := up.Flush(); err != nil {
			prog.finish(false)
			return err
		}
		prog.finish(true)
		warnSkipped(local.Skipped)
	}

	// Seal the base tree's node ciphertexts once, up front, and reuse them across every
	// reconcile attempt. This is the base-serving map the reuse read consults so an
	// unchanged remote subtree costs no fetch; sealing it here (rather than inside the
	// retry closure) stops a conflict retry from re-sealing the whole DAG each pass.
	var baseCT map[string][]byte
	if baseExists {
		baseCT, err = syncengine.SealTreeCiphertexts(base, conv, openSealMemo())
		if err != nil {
			return err
		}
	}

	// Stamp every conflict-copy from this sync with one host and one wall-clock time,
	// so copies made in the same run share a suffix and a retry does not re-time them.
	var copyHost string
	var copyMemo conflictCopyMemo
	if mode == conflictCopy || mode == conflictMerge {
		copyHost = conflictHost()
		copyMemo = conflictCopyMemo{}
	}
	syncStart := time.Now()

	// reconcile runs one pass against the current remote. It returns
	// client.ErrConflict if another sync committed first; the loop below then
	// re-plans against the new remote, so a concurrent write is never lost.
	reconcile := func() error {
		rs, err := sess.openRemote(opts)
		if err != nil {
			return err
		}
		defer rs.ck.Wipe()
		planBase := base
		if !rs.trustBase {
			planBase = syncengine.Manifest{}
		}
		// Read the remote tree. With a base, reuse it: any directory node whose id the
		// base tree already contains is byte-identical (nodes are content-addressed), so
		// it is served from memory and only the nodes on a changed spine are fetched — an
		// unchanged remote does zero node round-trips. Without a base (reconcile mode,
		// or an accepted rollback) there is nothing to reuse, so fall back to the full walk.
		var remote syncengine.Manifest
		if rs.trustBase {
			remote, err = openRemoteTreeReusingBase(cl, rs.res.Blob, rs.ck, sess.st.ID, baseCT)
		} else {
			remote, err = openRemoteTree(cl, rs.res.Blob, rs.ck, sess.st.ID)
		}
		if errors.Is(err, client.ErrNotFound) {
			// We read the root of the version this attempt fetched, but a concurrent sync superseded it
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
		var dirActions []syncengine.Action
		if rs.trustBase {
			actions = syncengine.Plan(local, base, remote)
			dirActions = syncengine.PlanDirs(local, base, remote)
			syncengine.MarkTypeClashes(actions, dirActions, local)
			syncengine.KeepParents(actions, dirActions, local)
		} else {
			actions = syncengine.PlanReconcile(local, remote)
			dirActions = syncengine.PlanDirsReconcile(local, remote)
		}
		if opts.dryRun {
			acts, dacts, renames := coalescePlanRenames(actions, dirActions, local, base, remote)
			if mode == conflictCopy {
				return app.printCopyPlan(root, acts, dacts, renames, remote, copyHost, syncStart)
			}
			return app.printPlan(acts, dacts, renames)
		}
		// Copy mode resolves conflicts local-wins (like --force) after preserving the
		// remote side as a copy, so it must not abort on them.
		if err := app.abortOnConflicts(actions, dirActions, opts.force || mode == conflictCopy || mode == conflictMerge); err != nil {
			return err
		}
		return app.applySync(applyCtx{
			root: root, cl: cl, opts: opts,
			base: planBase, local: local, remote: remote,
			conv: conv, ck: rs.ck, mk: sess.mk, meta: rs.res.EncryptedMeta,
			visibility: rs.res.Visibility, version: rs.res.Version, id: sess.st.ID,
			mode: mode, host: copyHost, now: syncStart, pushStart: pushStart, copyMemo: copyMemo, selector: selector,
		}, actions, dirActions)
	}

	return reconcileWithRetry(reconcile)
}

// reconcileWithRetry runs one reconcile pass, retrying against the fresh remote on a
// version conflict (another sync committed first), up to maxSyncAttempts before giving
// up. The conflict retry is how a concurrent write is re-planned rather than lost.
func reconcileWithRetry(reconcile func() error) error {
	for attempt := range maxSyncAttempts {
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

func controlPath(root, name string) string {
	return filepath.Join(root, syncengine.ControlDir, name)
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

func dirArg(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "."
}

// abortOnConflicts refuses a sync that has both-sides changes it cannot auto-resolve,
// unless --force (local wins) was given. Directory conflicts count too: a directory mode
// or existence that diverged on both sides is surfaced like a file conflict rather than
// silently taking local, so the user is told before anything is applied.
func (app *application) abortOnConflicts(actions []syncengine.Action, dirActions []syncengine.Action, force bool) error {
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
	if app.json {
		_ = printJSON(map[string]any{"conflicts": conflicts})
	} else {
		printPaths("conflict", conflicts)
	}
	return errConflictsRemain
}

// planLine is one dry-run plan entry as emitted by `sync --dry-run --json`. Renames
// use action "rename" with from/to; a copy-mode conflict carries the copy path.
type planLine struct {
	Action string `json:"action"`
	Path   string `json:"path,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Dir    bool   `json:"dir,omitempty"`
	Copy   string `json:"copy,omitempty"`
}

func printPlanJSON(lines []planLine) error {
	if lines == nil {
		lines = []planLine{}
	}
	return printJSON(lines)
}

func (app *application) printPlan(actions []syncengine.Action, dirActions []syncengine.Action, renames []syncengine.Rename) error {
	if app.json {
		var lines []planLine
		for _, r := range renames {
			lines = append(lines, planLine{Action: "rename", From: r.From, To: r.To, Dir: r.Dir})
		}
		for _, a := range actions {
			lines = append(lines, planLine{Action: string(a.Kind), Path: a.Path})
		}
		for _, a := range dirActions {
			lines = append(lines, planLine{Action: string(a.Kind), Path: a.Path, Dir: true})
		}
		return printPlanJSON(lines)
	}
	if len(actions) == 0 && len(dirActions) == 0 && len(renames) == 0 {
		fmt.Println("already in sync")
		return nil
	}
	for _, r := range renames {
		fmt.Printf("%-13s %s\n", "renamed", renameArrow(r))
	}
	for _, a := range actions {
		fmt.Printf("%-13s %s\n", a.Kind, a.Path)
	}
	for _, a := range dirActions {
		fmt.Printf("%-13s %s/\n", a.Kind, a.Path) // trailing slash marks a directory
	}
	return nil
}

// printCopyPlan is the dry-run report for --conflicts=copy: it renders like printPlan
// but shows each content conflict as the copy it would create (conflict-copy
// <path> -> <copy-path>) rather than a bare "conflict", without writing anything. A
// conflict with no remote bytes (local edit vs remote delete) has no copy, so it is
// shown as a plain conflict. Directory conflicts carry no copy (they resolve
// local-wins) and pass through unchanged.
func (app *application) printCopyPlan(root string, actions []syncengine.Action, dirActions []syncengine.Action, renames []syncengine.Rename, remote syncengine.Manifest, host string, now time.Time) error {
	if !app.json && len(actions) == 0 && len(dirActions) == 0 && len(renames) == 0 {
		fmt.Println("already in sync")
		return nil
	}
	var lines []planLine
	for _, r := range renames {
		lines = append(lines, planLine{Action: "rename", From: r.From, To: r.To, Dir: r.Dir})
	}
	remoteByPath := remote.ByPath()
	taken := takenPaths(remoteByPath) // same collision set the real apply uses
	for _, a := range actions {
		if a.Kind == syncengine.Conflict {
			if _, ok := remoteByPath[a.Path]; ok {
				cp := conflictCopyPath(root, a.Path, host, now, taken)
				taken[cp] = true
				lines = append(lines, planLine{Action: "conflict-copy", Path: a.Path, Copy: cp})
				continue
			}
		}
		lines = append(lines, planLine{Action: string(a.Kind), Path: a.Path})
	}
	for _, a := range dirActions {
		lines = append(lines, planLine{Action: string(a.Kind), Path: a.Path, Dir: true})
	}
	if app.json {
		return printPlanJSON(lines)
	}
	for _, l := range lines {
		switch {
		case l.Action == "rename":
			fmt.Printf("%-13s %s\n", "renamed", renameArrow(syncengine.Rename{From: l.From, To: l.To, Dir: l.Dir}))
		case l.Copy != "":
			fmt.Printf("%-13s %s -> %s\n", l.Action, l.Path, l.Copy)
		case l.Dir:
			fmt.Printf("%-13s %s/\n", l.Action, l.Path) // trailing slash marks a directory
		default:
			fmt.Printf("%-13s %s\n", l.Action, l.Path)
		}
	}
	return nil
}

// coalescePlanRenames pairs delete+add actions that move unchanged content —
// an upload of a path new to the base with a delete-remote (local rename), and
// a download new to the base with a delete-local (remote rename) — into
// renames for the dry-run display. It never alters what a real sync executes.
// A whole-directory move also swallows its now-redundant directory actions
// (DetectRenames only coalesces a dir when its tracked dirs move with modes
// intact, so those actions carry no information beyond the rename).
func coalescePlanRenames(actions []syncengine.Action, dirActions []syncengine.Action, local, base, remote syncengine.Manifest) ([]syncengine.Action, []syncengine.Action, []syncengine.Rename) {
	baseBy := base.ByPath()
	var upAdds, upDels, downAdds, downDels []string
	for _, a := range actions {
		switch a.Kind {
		case syncengine.Upload:
			if _, ok := baseBy[a.Path]; !ok {
				upAdds = append(upAdds, a.Path)
			}
		case syncengine.DeleteRemote:
			upDels = append(upDels, a.Path)
		case syncengine.Download:
			if _, ok := baseBy[a.Path]; !ok {
				downAdds = append(downAdds, a.Path)
			}
		case syncengine.DeleteLocal:
			downDels = append(downDels, a.Path)
		}
	}
	localRen, _, _ := syncengine.DetectRenames(upAdds, upDels, local, base)
	remoteRen, _, _ := syncengine.DetectRenames(downAdds, downDels, remote, base)
	if len(localRen)+len(remoteRen) == 0 {
		return actions, dirActions, nil
	}

	coversAdded := func(r syncengine.Rename, path string) bool {
		if r.Dir {
			return strings.HasPrefix(path, r.To+"/")
		}
		return path == r.To
	}
	coversDeleted := func(r syncengine.Rename, path string) bool {
		if r.Dir {
			return strings.HasPrefix(path, r.From+"/")
		}
		return path == r.From
	}
	keepActions := actions[:0:0]
	for _, a := range actions {
		if !renameCovers(a.Kind, localRen, remoteRen, a.Path, coversAdded, coversDeleted) {
			keepActions = append(keepActions, a)
		}
	}
	atOrUnder := func(path, dir string) bool {
		return path == dir || strings.HasPrefix(path, dir+"/")
	}
	dirCoversAdded := func(r syncengine.Rename, path string) bool {
		return r.Dir && atOrUnder(path, r.To)
	}
	dirCoversDeleted := func(r syncengine.Rename, path string) bool {
		return r.Dir && atOrUnder(path, r.From)
	}
	keepDirs := dirActions[:0:0]
	for _, a := range dirActions {
		if !renameCovers(a.Kind, localRen, remoteRen, a.Path, dirCoversAdded, dirCoversDeleted) {
			keepDirs = append(keepDirs, a)
		}
	}
	renames := slices.Concat(localRen, remoteRen)
	sort.Slice(renames, func(i, j int) bool { return renames[i].From < renames[j].From })
	return keepActions, keepDirs, renames
}

// renameCovers reports whether a detected rename subsumes an action of the given
// kind on path. coversAdded tests the added (To) side of a rename, coversDeleted
// the deleted (From) side; the kind picks which. Local renames cover the push side
// of an action (Upload/DeleteRemote); remote renames cover the pull side
// (Download/DeleteLocal).
func renameCovers(kind syncengine.ActionKind, localRen, remoteRen []syncengine.Rename, path string, coversAdded, coversDeleted func(r syncengine.Rename, path string) bool) bool {
	for _, r := range localRen {
		if (kind == syncengine.Upload && coversAdded(r, path)) ||
			(kind == syncengine.DeleteRemote && coversDeleted(r, path)) {
			return true
		}
	}
	for _, r := range remoteRen {
		if (kind == syncengine.Download && coversAdded(r, path)) ||
			(kind == syncengine.DeleteLocal && coversDeleted(r, path)) {
			return true
		}
	}
	return false
}

func printPaths(label string, paths []string) {
	for _, p := range paths {
		fmt.Printf("%-9s %s\n", label, p)
	}
}

func (app *application) summarize(uploads, downloads []syncengine.Entry, localDeletes, merged []string) {
	if app.json {
		_ = printJSON(map[string]any{
			"uploaded": len(uploads), "uploadedBytes": entriesBytes(uploads),
			"downloaded": len(downloads), "downloadedBytes": entriesBytes(downloads),
			"removedLocally": len(localDeletes), "merged": merged,
		})
		return
	}
	// A quiet sync says nothing about the work it did; what it could not do (the
	// conflict list below, printed by the caller) still reaches the terminal.
	if app.quiet {
		return
	}
	fmt.Printf("synced: %d up (%s), %d down (%s), %d removed locally\n",
		len(uploads), cliutil.HumanBytes(entriesBytes(uploads)),
		len(downloads), cliutil.HumanBytes(entriesBytes(downloads)), len(localDeletes))
	for _, path := range merged {
		fmt.Printf("~ merged %s\n", path)
	}
}

// reclaimPacks sweeps the packs the just-superseded manifest no longer references,
// throttled to once per gcMinInterval per folder so a burst of syncs (notably the
// watch daemon) does not fire a full server sweep every time. The last-swept time is
// recorded in folder state; the sync lock makes the read-modify-write race-free.
// Best-effort: a sync that uploaded fine should not fail on cleanup.
func reclaimPacks(root string, cl *client.Client) {
	st, err := folderstate.LoadState(root)
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
		_ = folderstate.SaveState(root, st)
	}
}
