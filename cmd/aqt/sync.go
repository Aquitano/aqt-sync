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
	"golang.org/x/sync/singleflight"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// folderState is the per-folder pointer stored in .aqt/state.json: which resource
// on which server this directory tracks, plus when its packs were last GC'd.
type folderState struct {
	ID     string `json:"id"`
	Server string `json:"server"`
	// Profile and Fingerprint bind the folder to the account that owns its remote
	// resource: Profile is the local profile name commands default to, and
	// Fingerprint pins the account's signing-key fingerprint so a profile that was
	// re-logged into a different account is detected instead of silently syncing
	// this folder against it. Empty on state written by an older build; backfilled
	// by bindTrackedRoot once the recorded server identity checks out.
	Profile     string `json:"profile,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	LastGC      int64  `json:"lastGC,omitempty"` // Unix seconds of the last reclaimPacks GC; throttles the next
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
	var opts statusOptions
	cmd := &cobra.Command{
		Use:   "status [dir]",
		Short: "Show local changes since the last sync, and any incoming changes on the server",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runStatus(dirArg(args), opts) },
	}
	cmd.Flags().BoolVar(&opts.offline, "offline", false, "report only local changes; skip the server check for incoming changes")
	markJSONSupported(cmd)
	return cmd
}

func syncCmd() *cobra.Command {
	var opts syncOptions
	cmd := &cobra.Command{
		Use:   "sync [dir]",
		Short: "Two-way reconcile a tracked folder with the server",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return runSyncCmd(dirArg(args), opts) },
	}
	f := cmd.Flags()
	f.BoolVar(&opts.pushOnly, "push-only", false, "only upload local changes")
	f.BoolVar(&opts.pullOnly, "pull-only", false, "only download remote changes")
	f.BoolVar(&opts.dryRun, "dry-run", false, "print the plan without making changes")
	f.BoolVar(&opts.force, "force", false, "resolve conflicts in favor of local")
	f.BoolVar(&opts.reconcile, "reconcile", false, "reconcile without a base (.aqt/base.json missing): one-sided differences become conflicts to review")
	f.BoolVar(&opts.rehash, "rehash", false, "re-hash every file instead of trusting size+mtime (catches edits that preserve them)")
	f.BoolVar(&opts.acceptRollback, "accept-rollback", false, "proceed although the server reports an older version than previously seen (restored from backup): reconcile from scratch, one-sided differences become conflicts to review")
	f.StringVar(&opts.conflicts, "conflicts", "", "conflict handling: block (default) or copy (keep local, write remote to <name>.conflict-<suffix>)")
	markJSONSupported(cmd)
	return cmd
}

func cloneCmd() *cobra.Command {
	var (
		adopt bool
		pw    passwordFlags
	)
	cmd := &cobra.Command{
		Use:   "clone <id|aqt://ref|share-url> [dir]",
		Short: "Materialize a tracked folder (or a shared folder link) on this machine",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := ""
			if len(args) == 2 {
				dir = args[1]
			}
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runClone(args[0], dir, adopt, password)
		},
	}
	cmd.Flags().BoolVar(&adopt, "adopt", false,
		"adopt an existing non-empty directory: write tracking, reuse matching local files by hash, and reconcile differences as conflicts")
	pw.bind(cmd, "password for a gated link")
	markJSONSupported(cmd)
	return cmd
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

	// Stage the local control state before touching the server: creating .aqt and
	// the starter ignore up front surfaces permission problems while there is still
	// nothing remote to orphan. Everything staged here is removed again if a later
	// step fails.
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	wroteIgnore, err := writeStarterIgnore(abs, syncGit)
	if err != nil {
		os.RemoveAll(filepath.Join(abs, syncengine.ControlDir))
		return err
	}
	cleanupLocal := func() {
		os.RemoveAll(filepath.Join(abs, syncengine.ControlDir))
		if wroteIgnore {
			os.Remove(filepath.Join(abs, ".aqtignore"))
		}
	}

	// Register an empty private folder resource; the first `sync` fills it. A
	// pack-and-seal folder (.aqtconfig pack=true) is created with an empty PackRoot;
	// the chunked default with an empty Merkle-DAG tree root.
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		cleanupLocal()
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
		cleanupLocal()
		return err
	}

	if err := commitInitState(abs, prof, resp, manifest); err != nil {
		// The resource was just created and nothing references it yet; deleting it
		// keeps a failed init side-effect-free instead of leaving an orphan the
		// user cannot see locally.
		cleanupLocal()
		if delErr := cl.DeleteResource(resp.ID); delErr != nil {
			return fmt.Errorf("%w (additionally, the just-created remote resource %s could not be removed: %v; `aqt rm %s` deletes it)", err, resp.ID, delErr, resp.ID)
		}
		return err
	}
	fmt.Printf("tracking %s\naqt://%s\n", abs, resp.ID)
	fmt.Fprintln(os.Stderr, "run `aqt sync` to push the current contents")
	return nil
}

// commitInitState writes the tracking pointer and empty base for a fresh init.
// Split out (as a var) so a test can fail the local commit and assert the remote
// resource is cleaned up.
var commitInitState = func(abs string, prof *identity.Profile, resp api.PutResourceResponse, manifest syncengine.Manifest) error {
	profileName, fingerprint := stateIdentity(prof)
	if err := saveState(abs, folderState{
		ID: resp.ID, Server: prof.Server,
		Profile: profileName, Fingerprint: fingerprint,
		RemoteVersion: resp.Version,
	}); err != nil {
		return err
	}
	return saveBase(abs, manifest)
}

// --- status ---

type statusOptions struct {
	offline bool
}

func runStatus(dir string, opts statusOptions) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	// Even the offline half needs the folder's own identity: the base manifest is
	// sealed under the owning profile's key.
	if err := bindTrackedRoot(root); err != nil {
		return err
	}
	base, err := loadBase(root)
	if err != nil {
		return err
	}
	local, err := syncengine.ScanReusing(root, &base, false)
	if err != nil {
		return err
	}

	// The local half is offline: it compares the working tree to the last synced
	// manifest. Conflicts (both sides changed) still surface only during `sync`.
	ch := computeLocalChanges(local, base)

	if flagJSON {
		renamed := ch.renamed
		if renamed == nil {
			renamed = []syncengine.Rename{}
		}
		out := map[string]any{
			"clean":    ch.total() == 0,
			"added":    nonNil(ch.added),
			"modified": nonNil(ch.modified),
			"deleted":  nonNil(ch.deleted),
			"renamed":  renamed,
		}
		if !opts.offline {
			if rep := collectIncoming(root, base); rep != nil {
				out["incoming"] = rep
			}
		}
		return printJSON(out)
	}

	if ch.total() == 0 {
		fmt.Println("clean (no local changes since last sync)")
	} else {
		printPaths("new", ch.added)
		printPaths("modified", ch.modified)
		printPaths("deleted", ch.deleted)
		for _, r := range ch.renamed {
			fmt.Printf("%-9s %s\n", "renamed", renameArrow(r))
		}
	}

	if opts.offline {
		return nil
	}
	printIncomingReport(collectIncoming(root, base))
	return nil
}

// localChanges classifies the working tree against the last-synced base manifest:
// the offline half of `status`, shared with the TUI's files panel.
type localChanges struct {
	added    []string
	modified []string
	deleted  []string
	renamed  []syncengine.Rename
}

func (c localChanges) total() int {
	return len(c.added) + len(c.modified) + len(c.deleted) + len(c.renamed)
}

func computeLocalChanges(local, base syncengine.Manifest) localChanges {
	baseByPath := base.ByPath()
	var c localChanges
	for _, a := range syncengine.Plan(local, base, base) {
		switch a.Kind {
		case syncengine.Upload:
			if _, ok := baseByPath[a.Path]; ok {
				c.modified = append(c.modified, a.Path)
			} else {
				c.added = append(c.added, a.Path)
			}
		case syncengine.DeleteRemote:
			c.deleted = append(c.deleted, a.Path)
		}
	}
	c.renamed, c.added, c.deleted = syncengine.DetectRenames(c.added, c.deleted, local, base)
	return c
}

// incomingSummary is the file-level view of what the server holds that this machine
// has not yet pulled: entries added or modified on the remote since the last sync,
// and entries the remote dropped. Like the local status view it is files-only.
type incomingSummary struct {
	added    []string
	modified []string
	deleted  []string
	renamed  []syncengine.Rename
}

func (s incomingSummary) total() int {
	return len(s.added) + len(s.modified) + len(s.deleted) + len(s.renamed)
}

// incomingReport is the server-side half of `status`: whether the server holds
// changes this machine has not pulled, at file level when the folder key is at hand.
type incomingReport struct {
	State         string              `json:"state"` // "up-to-date" | "ahead" | "rollback"
	AheadBy       int                 `json:"aheadBy,omitempty"`
	ServerVersion int                 `json:"serverVersion,omitempty"` // set on rollback
	SeenVersion   int                 `json:"seenVersion,omitempty"`   // set on rollback
	Files         bool                `json:"-"`                       // the file-level lists below are populated
	Added         []string            `json:"added,omitempty"`
	Modified      []string            `json:"modified,omitempty"`
	Deleted       []string            `json:"deleted,omitempty"`
	Renamed       []syncengine.Rename `json:"renamed,omitempty"`
}

// collectIncoming reports whether the server holds changes this machine has not
// pulled, or nil when that cannot be determined. It is best-effort and never fails
// `status`: the command is primarily an offline, local-changes view, so a missing
// profile or an unreachable server downgrades to a short note on stderr. A precise
// file count needs the folder key, so it is computed only when an unlocked session
// is already cached — status never prompts for a passphrase; otherwise the coarser
// version delta is reported.
func collectIncoming(root string, base syncengine.Manifest) *incomingReport {
	prof := loadProfileOptional()
	if prof == nil {
		return nil // never logged in: no server to compare against
	}
	st, err := loadState(root)
	if err != nil {
		return nil
	}
	cl, err := client.New(prof.Server, prof.Token)
	if err != nil {
		return nil
	}
	res, err := cl.GetResource(st.ID)
	if err != nil {
		noteIncomingUnavailable(err)
		return nil
	}

	// Cheap freshness compare first: RemoteVersion is the server version this machine
	// last integrated (recorded by every init/clone/sync), so the resource header alone
	// answers "is the server ahead?" — no folder key, no tree walk.
	switch {
	case st.RemoteVersion > 0 && res.Version < st.RemoteVersion:
		return &incomingReport{State: "rollback", ServerVersion: res.Version, SeenVersion: st.RemoteVersion}
	case st.RemoteVersion > 0 && res.Version == st.RemoteVersion:
		return &incomingReport{State: "up-to-date"}
	}

	// The server is ahead (or RemoteVersion predates version tracking). Try for a
	// file-level breakdown; it needs the folder key, available without a prompt only
	// when a session is already unlocked, and only for a chunked folder — a pack-and-seal
	// folder is one opaque blob with no per-file remote diff, so it stays version-level.
	if cfg, cerr := syncengine.LoadConfig(root); cerr == nil && !cfg.Pack {
		if mk, ok := identity.LoadSession(prof.Name); ok {
			defer mk.Wipe()
			if inc, ierr := incomingFiles(cl, res, base, mk); ierr == nil {
				state := "ahead"
				if inc.total() == 0 {
					state = "up-to-date"
				}
				return &incomingReport{
					State: state, Files: true,
					Added: inc.added, Modified: inc.modified, Deleted: inc.deleted, Renamed: inc.renamed,
				}
			}
		}
	}

	// Fallback: the server advanced but we cannot (or need not) enumerate the files.
	if st.RemoteVersion == 0 {
		return &incomingReport{State: "ahead"}
	}
	return &incomingReport{State: "ahead", AheadBy: res.Version - st.RemoteVersion}
}

// printIncomingReport renders collectIncoming's result for the human status view.
func printIncomingReport(rep *incomingReport) {
	if rep == nil {
		return
	}
	switch {
	case rep.State == "rollback":
		fmt.Printf("server reports an older version (%d < %d): it may have been restored from a backup; run `aqt sync`\n",
			rep.ServerVersion, rep.SeenVersion)
	case rep.State == "up-to-date":
		fmt.Println("up to date with the server")
	case rep.Files:
		printIncoming(incomingSummary{added: rep.Added, modified: rep.Modified, deleted: rep.Deleted, renamed: rep.Renamed})
	case rep.AheadBy > 0:
		fmt.Printf("incoming: the server is ahead by %d version(s); run `aqt sync` to pull\n", rep.AheadBy)
	default:
		fmt.Println("the server may hold changes to pull; run `aqt sync`")
	}
}

// incomingFiles decrypts the remote manifest and diffs it against the last-synced
// base, yielding the files this machine would pull. It reuses the base tree's node
// ciphertexts so an unchanged remote subtree costs no fetch, exactly like a sync's
// remote read.
func incomingFiles(cl *client.Client, res api.GetResourceResponse, base syncengine.Manifest, mk crypto.MasterKey) (incomingSummary, error) {
	if res.WrappedKey == nil {
		return incomingSummary{}, errors.New("folder resource has no owner key")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return incomingSummary{}, err
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return incomingSummary{}, err
	}
	if !meta.Tree {
		return incomingSummary{}, errors.New("unsupported remote folder format")
	}
	remote, err := readRemoteManifest(cl, res, ck, base, mk)
	if err != nil {
		return incomingSummary{}, err
	}
	return diffIncoming(base, remote), nil
}

// readRemoteManifest reconstructs the remote folder manifest, reusing the base tree's
// node ciphertexts when a base is present (an unchanged subtree then costs no fetch)
// and falling back to a full walk when there is nothing to reuse.
func readRemoteManifest(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, base syncengine.Manifest, mk crypto.MasterKey) (syncengine.Manifest, error) {
	if len(base.Entries) == 0 && len(base.Dirs) == 0 {
		return openRemoteTree(cl, res.Blob, ck, res.ID)
	}
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()
	baseCT, err := syncengine.SealTreeCiphertexts(base, conv)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return openRemoteTreeReusingBase(cl, res.Blob, ck, res.ID, baseCT)
}

// diffIncoming reports the file-level changes the server holds relative to the last
// synced base. It mirrors the planner's notion of "changed" (content or mode), and
// like the local status view it considers files only, not tracked directories.
func diffIncoming(base, remote syncengine.Manifest) incomingSummary {
	baseByPath := base.ByPath()
	remoteByPath := remote.ByPath()
	var s incomingSummary
	for path, re := range remoteByPath {
		switch be, ok := baseByPath[path]; {
		case !ok:
			s.added = append(s.added, path)
		case be.Hash != re.Hash || be.Mode != re.Mode:
			s.modified = append(s.modified, path)
		}
	}
	for path := range baseByPath {
		if _, ok := remoteByPath[path]; !ok {
			s.deleted = append(s.deleted, path)
		}
	}
	sort.Strings(s.added)
	sort.Strings(s.modified)
	sort.Strings(s.deleted)
	s.renamed, s.added, s.deleted = syncengine.DetectRenames(s.added, s.deleted, remote, base)
	return s
}

func printIncoming(s incomingSummary) {
	if s.total() == 0 {
		fmt.Println("up to date with the server")
		return
	}
	fmt.Printf("incoming: %d to pull (%s); run `aqt sync`\n", s.total(), incomingBreakdown(s))
	printIncomingPaths("new", s.added)
	printIncomingPaths("modified", s.modified)
	printIncomingPaths("deleted", s.deleted)
	for _, r := range s.renamed {
		fmt.Printf("  %-9s %s\n", "renamed", renameArrow(r))
	}
}

// printIncomingPaths lists incoming paths indented under the "incoming:" summary, so
// they read as a group and never look like the top-level local changes above them.
func printIncomingPaths(label string, paths []string) {
	for _, p := range paths {
		fmt.Printf("  %-9s %s\n", label, p)
	}
}

func incomingBreakdown(s incomingSummary) string {
	var parts []string
	if n := len(s.added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if n := len(s.modified); n > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", n))
	}
	if n := len(s.deleted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d deleted", n))
	}
	if n := len(s.renamed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d renamed", n))
	}
	return strings.Join(parts, ", ")
}

func noteIncomingUnavailable(err error) {
	switch {
	case isNetworkError(err):
		fmt.Fprintln(os.Stderr, "note: could not reach the server to check for incoming changes")
	case errors.Is(err, client.ErrNotFound):
		fmt.Fprintln(os.Stderr, "note: this folder no longer exists on the server")
	default:
		fmt.Fprintf(os.Stderr, "note: could not check the server for incoming changes: %v\n", err)
	}
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
	conflicts      string // "" (use .aqtconfig, else block), "block", or "copy"
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
func runSyncCmd(dir string, opts syncOptions) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	if err := guardTrackedGit(root, opts); err != nil {
		return err
	}
	return runSync(root, opts)
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
	// Under the lock: binding may back-fill state.json, which must not race a
	// concurrent sync's own state write.
	if err := bindTrackedRoot(root); err != nil {
		return err
	}
	cfg, err := syncengine.LoadConfig(root)
	if err != nil {
		return err
	}
	mode, err := effectiveConflictMode(opts, cfg)
	if err != nil {
		return err
	}
	if cfg.Pack {
		if mode == conflictCopy {
			return errors.New("--conflicts=copy does not apply to a pack-and-seal folder: it reconciles the whole folder at once, so there is no per-file conflict to copy")
		}
		return runPackSync(root, opts)
	}
	if mode == conflictCopy {
		if err := validateCopyMode(opts); err != nil {
			return err
		}
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
		var scanBase *syncengine.Manifest
		if baseExists {
			scanBase = &base
		}
		local, err = syncengine.ScanReusing(root, scanBase, opts.rehash)
		if err != nil {
			return err
		}
	} else {
		selector, cerr := cfg.ChunkSelector()
		if cerr != nil {
			return cerr
		}
		// With --progress on a terminal, size the upload up front so the bar shows a real
		// percentage. Chunked content streams during Take (below) before any plan exists,
		// so there is no cheaper moment to learn the total. A sizing scan tolerates a stale
		// estimate (the bar snaps to 100% on completion), so it runs the cheap stat
		// fast-path with rehash off — avoiding a second full-tree hash under --rehash — and
		// a scan error just leaves the bar off (total 0).
		var uploadTotal int64
		if progressActive() {
			scanBase := &base
			if !baseExists {
				scanBase = nil
			}
			if pre, perr := syncengine.ScanReusing(root, scanBase, false); perr == nil {
				uploadTotal = uploadBytes(pre, base, selector)
			}
		}
		prog := newProgressBar("uploading", uploadTotal)
		up := newPackUploader(cl, prog)
		local, err = syncengine.Take(root, conv, selector, &base, up, opts.rehash)
		if err != nil {
			up.Wait() // drain in-flight uploads before returning the snapshot error
			prog.finish(false)
			return err
		}
		if err := up.Flush(); err != nil {
			prog.finish(false)
			return err
		}
		prog.finish(true)
	}

	// Seal the base tree's node ciphertexts once, up front, and reuse them across every
	// reconcile attempt. This is the base-serving map the reuse read consults so an
	// unchanged remote subtree costs no fetch; sealing it here (rather than inside the
	// retry closure) stops a conflict retry from re-sealing the whole DAG each pass (3.3).
	var baseCT map[string][]byte
	if baseExists {
		baseCT, err = syncengine.SealTreeCiphertexts(base, conv)
		if err != nil {
			return err
		}
	}

	// Stamp every conflict-copy from this sync with one host and one wall-clock time,
	// so copies made in the same run share a suffix and a retry does not re-time them.
	var copyHost string
	var copyMemo conflictCopyMemo
	if mode == conflictCopy {
		copyHost = conflictHost()
		copyMemo = conflictCopyMemo{}
	}
	syncStart := time.Now()

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
		meta, err := decodeMeta(res.EncryptedMeta, ck, st.ID)
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
			remote, err = openRemoteTreeReusingBase(cl, res.Blob, ck, st.ID, baseCT)
		} else {
			remote, err = openRemoteTree(cl, res.Blob, ck, st.ID)
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
			acts, dacts, renames := coalescePlanRenames(actions, dirActions, local, base, remote)
			if mode == conflictCopy {
				return printCopyPlan(root, acts, dacts, renames, remote, copyHost, syncStart)
			}
			return printPlan(acts, dacts, renames)
		}
		// Copy mode resolves conflicts local-wins (like --force) after preserving the
		// remote side as a copy, so it must not abort on them.
		if err := abortOnConflicts(actions, dirActions, opts.force || mode == conflictCopy); err != nil {
			return err
		}
		return applySync(applyCtx{
			root: root, cl: cl, opts: opts,
			base: planBase, local: local, remote: remote,
			conv: conv, ck: ck, mk: mk, meta: res.EncryptedMeta,
			visibility: res.Visibility, version: res.Version, id: st.ID,
			mode: mode, host: copyHost, now: syncStart, copyMemo: copyMemo,
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
	copyMemo   conflictCopyMemo // copies materialized by earlier retry attempts, shared across the retry loop
}

func applySync(c applyCtx, actions []syncengine.Action, dirActions []syncengine.DirAction) error {
	// c holds by-value copies of the caller's keys ([32]byte, so the caller's
	// deferred wipes do not reach them); scrub this frame's copies on exit.
	defer c.ck.Wipe()
	defer c.conv.Wipe()
	defer c.mk.Wipe()
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

	// Copy mode: preserve the remote side of every content conflict as a local copy
	// BEFORE any local-wins remote mutation runs, so the remote bytes survive on disk
	// even if the push below dies mid-apply. The primary path is then resolved
	// local-wins by the action loop above. Copies land at fresh, collision-checked
	// paths, so they never overwrite anything and skip the download drift guard.
	if c.mode == conflictCopy {
		if copies := planConflictCopies(c.root, actions, remoteByPath, c.host, c.now, c.copyMemo); len(copies) > 0 {
			entries := copyEntries(copies)
			cpProg := newProgressBar("writing conflict copies", entriesBytes(entries))
			cpErr := runDownloads(c.cl, c.root, entries, cpProg)
			cpProg.finish(cpErr == nil)
			if cpErr != nil {
				return cpErr
			}
			// Record only after the write lands, so a failed/partial download is
			// re-planned rather than memoized as done; a retry rewrites the same path.
			for _, cp := range copies {
				c.copyMemo[cp.orig] = conflictCopyRecord{copyPath: cp.entry.Path, remoteHash: cp.entry.Hash}
				// stderr under --json so the summary object stays the only stdout output.
				out := os.Stdout
				if flagJSON {
					out = os.Stderr
				}
				fmt.Fprintf(out, "conflict-copy %s -> %s\n", cp.orig, cp.entry.Path)
			}
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
		resp, err := putFolderUpdate(c.cl, c.conv, c.id, c.visibility, manifest, c.meta, c.ck, c.mk, c.version)
		if err != nil {
			return err // client.ErrConflict on a stale version: retried by the caller
		}
		syncedVersion = resp.Version
		reclaimPacks(c.root, c.cl)
	}

	downloads, localDeletes, conflicts, err := filterDriftedTargets(c.root, downloads, localDeletes, localByPath, remoteByPath, c.base.ByPath(), newBase)
	if err != nil {
		return err
	}

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
	dlProg := newProgressBar("downloading", entriesBytes(downloads))
	dlErr := runDownloads(c.cl, c.root, downloads, dlProg)
	dlProg.finish(dlErr == nil)
	if dlErr != nil {
		return dlErr
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
	summarize(uploads, downloads, localDeletes)
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

// --- clone ---

func runClone(ref, dir string, adopt bool, password string) error {
	id, fragment, origin := parseRef(ref)
	// A ref carrying a fragment is a share link: the key comes from the link, not
	// the master key, and the read path is the unauthenticated public endpoint.
	if fragment != "" {
		if adopt {
			return errors.New("--adopt binds a directory to a folder you own; a share link is read-only, so there is nothing to sync with")
		}
		return runCloneLink(id, fragment, origin, dir, password)
	}
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
		// A grant read: materialize like a link clone, read-only, with the
		// grant-wrapped key and the authed exact-slice endpoint.
		if res.GrantKey != nil {
			if adopt {
				return errors.New("--adopt binds a directory to a folder you own; a granted folder is read-only, so there is nothing to sync with")
			}
			ck, err := contentKey(res, "", "", prof)
			if err != nil {
				return err
			}
			defer ck.Wipe()
			return cloneReadOnly(grantFetch(cl, id), res, ck, id, dir)
		}
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
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
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
	if err := validateCloneRoot(res.Blob, ck, meta, id); err != nil {
		return err
	}
	if adopt {
		return adoptClone(id, abs, prof, res.Version, meta)
	}
	// Content and control state are staged together and committed with one rename,
	// so an interrupted clone leaves no destination at all rather than a partial
	// tree (or a complete tree that is not yet tracked).
	var base syncengine.Manifest
	profileName, fingerprint := stateIdentity(prof)
	if err := materializeStaged(abs, func(staging string) error {
		var mErr error
		base, mErr = materializeClone(cl, staging, res, ck, meta)
		if mErr != nil {
			return mErr
		}
		if err := os.MkdirAll(filepath.Join(staging, syncengine.ControlDir), 0o700); err != nil {
			return err
		}
		if err := saveState(staging, folderState{
			ID: id, Server: prof.Server,
			Profile: profileName, Fingerprint: fingerprint,
			RemoteVersion: res.Version,
		}); err != nil {
			return err
		}
		return saveBase(staging, base)
	}); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"id": id, "dir": abs, "files": len(base.Entries), "tracked": true})
	}
	fmt.Printf("cloned %d files into %s\n", len(base.Entries), abs)
	return nil
}

// runCloneLink materializes a shared folder from its public link: the tree nodes and
// file content come through the unauthenticated public-object endpoint, and the
// folder key comes from the link fragment. The result is a plain directory, not a
// tracked folder — a link holder has no account token, so there is nothing to sync
// with; the link is pull-only by construction.
func runCloneLink(id, fragment, origin, dir, password string) error {
	prof := loadProfileOptional()
	cl, err := newLinkClient(origin, prof)
	if err != nil {
		return err
	}
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found (or no longer public)", id)
	}
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("this link has expired or reached its read limit: %w", err)
	}
	if err != nil {
		return err
	}
	ck, err := contentKey(res, fragment, password, prof)
	if err != nil {
		return err
	}
	defer ck.Wipe()
	return cloneReadOnly(publicFetch(cl, id), res, ck, id, dir)
}

// cloneReadOnly materializes a shared folder over an exact-slice transport — the
// common tail of a share-link clone and a grantee clone. The result is a plain
// directory, not a tracked folder: neither caller can write to the resource, so
// there is nothing to sync with.
func cloneReadOnly(fetch sliceFetch, res api.GetResourceResponse, ck crypto.ContentKey, id, dir string) error {
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Kind != api.KindFolder {
		return fmt.Errorf("%s is a single file, not a folder; `aqt pull` fetches it", meta.Name)
	}
	if meta.Packed || !meta.Tree {
		return errors.New("this folder's format cannot be read through a share; ask the owner to re-share it as a chunked folder")
	}
	// Decrypt the root before creating the destination, so a wrong password or
	// corrupt link fails without leaving an empty directory behind.
	root, err := syncengine.OpenTreeRoot(res.Blob, ck, id)
	if err != nil {
		return fmt.Errorf("decrypt folder root: %w", err)
	}
	if dir == "" {
		dir = id
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	manifest, err := syncengine.OpenTreeBatched(root, newPublicBatchFetcher(fetch))
	if err != nil {
		return fmt.Errorf("decrypt manifest: %w", err)
	}
	if err := materializeStaged(abs, func(staging string) error {
		prog := newProgressBar("downloading", entriesBytes(manifest.Entries))
		dlErr := runDownloadsFrom(newPublicEntrySource(fetch, manifest.Entries), staging, manifest.Entries, prog)
		prog.finish(dlErr == nil)
		if dlErr != nil {
			return dlErr
		}
		return materializeDirs(staging, manifest.Dirs)
	}); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"id": id, "dir": abs, "files": len(manifest.Entries), "tracked": false})
	}
	fmt.Printf("cloned %d files into %s (read-only share; not a tracked folder)\n", len(manifest.Entries), abs)
	return nil
}

// adoptClone binds an existing local directory to an already-tracked remote folder
// without re-downloading: it writes only the tracking metadata (no base.json), then
// runs a baseless reconcile so equal-hash files are reused and one-sided differences
// surface as conflicts, exactly like `sync --reconcile`. Tracking is written before
// the reconcile so it survives a conflict abort: the user can resolve and re-run
// `aqt sync --reconcile`.
func adoptClone(id, abs string, prof *identity.Profile, version int, meta api.Metadata) error {
	// Hash-level reconcile does not apply to a sealed pack (whole-folder last-writer-wins);
	// adopting one would compare an empty base against opaque segments.
	if meta.Packed {
		return errors.New("cannot adopt a pack-and-seal folder; use plain clone into a fresh directory")
	}
	if _, err := os.Stat(filepath.Join(abs, syncengine.ControlDir)); err == nil {
		return errors.New("already a tracked folder")
	}
	// .aqtconfig is itself synced content, so an adopted copy may carry one. A local
	// pack setting against this chunked remote would send runSync down the pack path
	// and fail on an unrelated decrypt error; refuse up front instead.
	cfg, err := syncengine.LoadConfig(abs)
	if err != nil {
		return err
	}
	if cfg.Pack {
		return errors.New("this directory's .aqtconfig selects pack-and-seal, but the remote is a chunked folder; remove the pack setting to adopt it")
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	// Deliberately no saveBase: an empty base would resurrect deletions; the reconcile
	// below writes base.json once local and remote agree.
	profileName, fingerprint := stateIdentity(prof)
	if err := saveState(abs, folderState{
		ID: id, Server: prof.Server,
		Profile: profileName, Fingerprint: fingerprint,
		RemoteVersion: version,
	}); err != nil {
		return err
	}
	// stderr under --json: the reconcile below emits the JSON summary on stdout.
	out := os.Stdout
	if flagJSON {
		out = os.Stderr
	}
	fmt.Fprintf(out, "adopted %s; reconciling with the remote\n", abs)
	if err := guardTrackedGit(abs, syncOptions{reconcile: true}); err != nil {
		return err
	}
	return runSync(abs, syncOptions{reconcile: true})
}

// validateCloneRoot confirms the resource's sealed root decrypts under ck, using the
// root type the metadata selects. The AAD is domain-separated per type, so a folder
// mis-flagged fails here rather than opening as an empty tree. A folder with neither
// flag predates the v2 tree format and is no longer supported.
func validateCloneRoot(blob crypto.SealedBlob, ck crypto.ContentKey, meta api.Metadata, resourceID string) error {
	var err error
	switch {
	case meta.Packed:
		_, err = syncengine.OpenPackRoot(blob, ck, resourceID)
	case meta.Tree:
		_, err = syncengine.OpenTreeRoot(blob, ck, resourceID)
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
		root, err := syncengine.OpenPackRoot(res.Blob, ck, res.ID)
		if err != nil {
			return syncengine.Manifest{}, fmt.Errorf("decrypt pack root: %w", err)
		}
		base, err := extractPack(cl, abs, root, ck, nil)
		if err != nil {
			return syncengine.Manifest{}, err
		}
		base.Version = res.Version
		return base, nil
	}
	manifest, err := openRemoteTree(cl, res.Blob, ck, res.ID)
	if err != nil {
		return syncengine.Manifest{}, fmt.Errorf("decrypt manifest: %w", err)
	}
	dlProg := newProgressBar("downloading", entriesBytes(manifest.Entries))
	dlErr := runDownloads(cl, abs, manifest.Entries, dlProg)
	dlProg.finish(dlErr == nil)
	if dlErr != nil {
		return syncengine.Manifest{}, dlErr
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
	prog     *progressBar
}

type candidate struct {
	id   string
	ct   []byte
	size int // plaintext length, for progress accounting
}

// uploadConcurrency bounds how many packs are checked-and-uploaded at once. Uploads
// are IO-bound (two round-trips plus server ingest), so a small fixed fan-out hides
// latency without a per-core thread; it also caps peak push memory at roughly this
// many packs (each in-flight upload holds a candidate buffer plus its assembled pack,
// both ~DefaultPackTarget).
const uploadConcurrency = 4

// syncTransferLimit is the errgroup concurrency for a transfer stage, normally the
// given fan-out. AQT_SYNC_SERIAL=1 forces it to 1 so the multi-device sim's crash-fault
// injection is seed-deterministic: with a single request in flight per stage, which
// request the injector aborts no longer depends on goroutine scheduling.
func syncTransferLimit(n int) int {
	if os.Getenv("AQT_SYNC_SERIAL") == "1" {
		return 1
	}
	return n
}

func newPackUploader(cl *client.Client, prog *progressBar) *packUploader {
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(syncTransferLimit(uploadConcurrency))
	return &packUploader{cl: cl, target: syncengine.DefaultPackTarget, seen: map[string]bool{}, group: g, ctx: ctx, prog: prog}
}

// Add buffers one sealed chunk, dispatching a pack once the buffer reaches the target.
func (u *packUploader) Add(ch crypto.Chunk, ciphertext []byte) error {
	if u.seen[ch.ID] {
		return nil
	}
	u.seen[ch.ID] = true
	u.cand = append(u.cand, candidate{id: ch.ID, ct: ciphertext, size: ch.Len})
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
	var batchBytes int64
	for i, c := range cand {
		ids[i] = c.id
		batchBytes += int64(c.size)
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
	// Count the batch's plaintext bytes as done once it is confirmed on the server,
	// whether it was uploaded or already present (dedup) — so the bar reflects content
	// committed, not bytes on the wire, and still reaches the total on a re-sync.
	if pb.Empty() {
		u.prog.add(batchBytes) // every candidate already on the server (a re-sync)
		return nil
	}
	packID, pack := pb.Finish()
	if err := u.cl.PutPack(packID, pack); err != nil {
		return err
	}
	u.prog.add(batchBytes)
	return nil
}

// downloadConcurrency bounds how many files a pull materializes at once. Downloads
// are IO-bound (each file range-fetches its packs, then writes them out), so a small
// fixed fan-out overlaps the network latency of independent files without a
// per-core thread. The shared packSource is concurrency-safe, and every file lands
// at a distinct path, so the content-addressed model makes the parallelism trivially
// correct — no file's bytes depend on another's.
const downloadConcurrency = 6

// runDownloads materializes each entry under root, streaming its chunks from the
// packs that hold them. A pack-backed chunk source range-fetches packs on demand
// and caches a few, so neither a whole file nor the whole tree is ever in memory.
// Files are materialized by a bounded worker pool; the first error wins and is
// returned, matching the upload pipeline's aggregation.
func runDownloads(cl *client.Client, root string, entries []syncengine.Entry, prog *progressBar) error {
	src, err := newPackSource(cl, distinctChunkIDs(entries))
	if err != nil {
		return err
	}
	return runDownloadsFrom(src.get, root, entries, prog)
}

// runDownloadsFrom is runDownloads with the chunk source already chosen, so the
// link-holder paths can materialize entries through the public object endpoint
// with the same worker pool the authed pack path uses.
func runDownloadsFrom(get func(id string) ([]byte, error), root string, entries []syncengine.Entry, prog *progressBar) error {
	var g errgroup.Group
	g.SetLimit(syncTransferLimit(downloadConcurrency))
	for _, e := range entries {
		e := e
		g.Go(func() error {
			if e.IsSymlink() {
				if err := syncengine.WriteSymlink(root, e); err != nil {
					return err
				}
			} else if err := syncengine.MaterializeFile(root, e, get); err != nil {
				return err
			}
			prog.add(e.Size)
			return nil
		})
	}
	return g.Wait()
}

// packSpan is a contiguous byte range of a pack covering a run of objects a download
// needs — fetched in one Range request. A pack may map to several spans when its
// needed objects are far apart (see spanSplitGap), so a few KiB at opposite ends of a
// large pack never drags the whole pack down.
type packSpan struct {
	base int64
	end  int64
}

// spanSplitGap bounds wasted read-ahead within a pack: two needed objects more than
// this many bytes apart are fetched as separate ranges rather than one span swallowing
// the dead bytes between them. Needing 2 objects at opposite ends of a 16 MiB pack thus
// costs two small ranges instead of the whole pack (3.5); below the gap, one range
// still wins (one request, and the skipped bytes are cheap).
const spanSplitGap = 256 << 10

// packSource resolves chunk ids to pack byte ranges (one locate up front) and
// serves their ciphertext, fetching each pack's covering span on demand and keeping
// a small LRU so a pack shared by several files is fetched once.
//
// It is safe for concurrent use by the download worker pool: locs and spans are
// immutable once concurrent gets begin (locate runs before, see its comment), the
// LRU is guarded by mu, and sf collapses a stampede of workers that all miss the
// same pack into one GetPackRange.
type packSource struct {
	cl   *client.Client
	locs map[string]api.ObjectLocation
	// objSpan maps each object to the covering span its bytes fall in. A pack with
	// widely-separated needed objects has several spans, so get fetches only the
	// window around each object rather than min..max across the whole pack.
	objSpan map[string]packSpan
	// spans records each pack's assigned spans so a later locate (the tree walk
	// locates level by level) reuses a span that already contains an object instead
	// of cutting a new one — the cache key is pack+span base, so reuse is what lets
	// a level-2 node inside a level-1 window come from the LRU, not the network.
	spans map[string][]packSpan
	mu    sync.Mutex // guards cache
	cache *packCache
	sf    singleflight.Group
}

func newPackSource(cl *client.Client, ids []string) (*packSource, error) {
	s := newEmptyPackSource(cl)
	if err := s.locate(ids); err != nil {
		return nil, err
	}
	return s, nil
}

// newEmptyPackSource returns a source with no located objects yet, for callers
// that locate incrementally (the level-batched tree walk) while keeping one LRU
// across all their fetches.
func newEmptyPackSource(cl *client.Client) *packSource {
	return &packSource{
		cl:      cl,
		locs:    map[string]api.ObjectLocation{},
		objSpan: map[string]packSpan{},
		spans:   map[string][]packSpan{},
		cache:   newPackCache(packCacheBytes),
	}
}

// locate resolves ids to pack spans and records them for get. It mutates locs and
// objSpan, so it must not run concurrently with get — callers either locate once
// up front (downloads) or interleave locate/get on a single goroutine (tree walk).
func (s *packSource) locate(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	located, err := s.cl.LocateChunks(ids)
	if err != nil {
		return err
	}
	byPack := map[string][]api.ObjectLocation{}
	for _, loc := range located {
		s.locs[loc.ID] = loc
		byPack[loc.PackID] = append(byPack[loc.PackID], loc)
	}
	for _, objs := range byPack {
		s.assignSpans(objs)
	}
	return nil
}

// assignSpans groups one pack's needed objects into covering spans, opening a new span
// whenever the gap to the next object exceeds spanSplitGap, and records each object's
// span so get range-fetches just that window. Objects within a pack never overlap.
// An object already contained in one of the pack's earlier spans (a prior locate — the
// tree walk locates level by level) adopts that span, so its bytes are served from the
// span already fetched rather than a fresh overlapping range.
func (s *packSource) assignSpans(objs []api.ObjectLocation) {
	packID := objs[0].PackID
	fresh := objs[:0]
	for _, o := range objs {
		if sp, ok := spanContaining(s.spans[packID], o); ok {
			s.objSpan[o.ID] = sp
			continue
		}
		fresh = append(fresh, o)
	}
	objs = fresh
	if len(objs) == 0 {
		return
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Off < objs[j].Off })
	start := 0
	base := objs[0].Off
	end := objs[0].Off + objs[0].Len
	flush := func(hi int) {
		span := packSpan{base: base, end: end}
		s.spans[packID] = append(s.spans[packID], span)
		for _, o := range objs[start:hi] {
			s.objSpan[o.ID] = span
		}
	}
	for i := 1; i < len(objs); i++ {
		o := objs[i]
		if o.Off-end > spanSplitGap {
			flush(i)
			start, base = i, o.Off
		}
		if o.Off+o.Len > end {
			end = o.Off + o.Len
		}
	}
	flush(len(objs))
}

func spanContaining(spans []packSpan, o api.ObjectLocation) (packSpan, bool) {
	for _, sp := range spans {
		if o.Off >= sp.base && o.Off+o.Len <= sp.end {
			return sp, true
		}
	}
	return packSpan{}, false
}

func (s *packSource) get(id string) ([]byte, error) {
	loc, ok := s.locs[id]
	if !ok {
		// The object was not in the locate response: the owner no longer stores it
		// (e.g. a concurrent sync superseded this version and GC reaped it). Surface
		// ErrNotFound so a manifest read can retry against the current version.
		return nil, fmt.Errorf("server could not locate chunk %s: %w", id, client.ErrNotFound)
	}
	span := s.objSpan[id]
	data, err := s.fetchSpan(loc.PackID, span)
	if err != nil {
		return nil, err
	}
	start := loc.Off - span.base
	return data[start : start+loc.Len], nil
}

// fetchSpan returns one span's bytes, fetching it at most once even under the
// concurrent download pool: the LRU is consulted under mu, and singleflight collapses
// concurrent misses of the same span into a single GetPackRange. The cache key is the
// pack plus the span base, since a pack now holds several spans. The returned bytes are
// never mutated after the fetch, so a later eviction cannot disturb a caller still
// slicing its object out of them.
func (s *packSource) fetchSpan(packID string, span packSpan) ([]byte, error) {
	key := fmt.Sprintf("%s@%d", packID, span.base)
	s.mu.Lock()
	data, ok := s.cache.get(key)
	s.mu.Unlock()
	if ok {
		return data, nil
	}
	v, err, _ := s.sf.Do(key, func() (any, error) {
		s.mu.Lock()
		if data, ok := s.cache.get(key); ok {
			s.mu.Unlock()
			return data, nil
		}
		s.mu.Unlock()
		data, err := s.cl.GetPackRange(packID, span.base, span.end-span.base)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) < span.end-span.base {
			return nil, fmt.Errorf("pack %s returned %d bytes, want %d", packID, len(data), span.end-span.base)
		}
		s.mu.Lock()
		s.cache.put(key, data)
		s.mu.Unlock()
		return data, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]byte), nil
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
	up := newPackUploader(cl, nil)
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
// the tiny root, then walks the DAG level by level, locating each level's directory
// nodes in one round-trip and range-fetching their packs grouped. The inverse of
// uploadTreeObjects.
func openRemoteTree(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string) (syncengine.Manifest, error) {
	root, err := syncengine.OpenTreeRoot(blob, ck, resourceID)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, nil))
}

// openRemoteTreeReusingBase is openRemoteTree seeded with the base tree's node
// ciphertexts (baseCT, sealed once by the caller and reused across retries). It serves
// any node the remote shares with the base from those bytes instead of the server:
// directory nodes are content-addressed, so a shared id is byte-identical, an unchanged
// subtree is reconstructed without a single fetch, and only nodes on a spine that
// changed since the base hit the network. The result is identical to openRemoteTree —
// OpenNode re-verifies every node against its address either way — so a stale base can
// only affect which nodes are fetched, never correctness.
func openRemoteTreeReusingBase(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string, baseCT map[string][]byte) (syncengine.Manifest, error) {
	root, err := syncengine.OpenTreeRoot(blob, ck, resourceID)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, baseCT))
}

// newBatchNodeFetcher returns a level-batch fetch for directory-node objects: it
// locates a whole level's ids in one call and range-fetches their packs grouped (via
// packSource), so a tree walk pays one locate per level instead of two round-trips per
// node. One packSource (and its LRU) is shared across every level of the walk, so a
// pack carrying nodes from several levels is fetched once, not once per level. seed
// carries node ciphertexts already in hand (the base tree in the reuse path), served
// from memory without a fetch; fetched nodes are cached across levels since the DAG
// may revisit a shared subtree id, and persist in the on-disk node cache, so a later
// command (find, diff, clone, a cold reconcile) re-fetches only nodes it has never
// seen — content addressing makes a disk hit exactly as trustworthy as a server fetch,
// since OpenNode verifies either against the id. A node the owner no longer stores —
// a concurrent sync superseded this version and GC reaped it — surfaces from
// packSource.get as client.ErrNotFound so a manifest read can retry against the
// current version.
func newBatchNodeFetcher(cl *client.Client, seed map[string][]byte) func([]string) (map[string][]byte, error) {
	cache := make(map[string][]byte, len(seed))
	for id, ct := range seed {
		cache[id] = ct
	}
	src := newEmptyPackSource(cl)
	disk := openNodeCache()
	return func(ids []string) (map[string][]byte, error) {
		var missing []string
		for _, id := range ids {
			if _, ok := cache[id]; ok {
				continue
			}
			if ct, ok := disk.get(id); ok {
				cache[id] = ct
				continue
			}
			missing = append(missing, id)
		}
		if len(missing) > 0 {
			if err := src.locate(missing); err != nil {
				return nil, err
			}
			for _, id := range missing {
				b, err := src.get(id)
				if err != nil {
					return nil, err
				}
				cache[id] = b
				disk.put(id, b)
			}
		}
		out := make(map[string][]byte, len(ids))
		for _, id := range ids {
			if ct, ok := cache[id]; ok {
				out[id] = ct
			}
		}
		return out, nil
	}
}

func putFolder(cl *client.Client, conv crypto.ConvergenceKey, id string, m syncengine.Manifest, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	root, refs, err := uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck, id)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: filepath.Base(dir), Kind: api.KindFolder, Tree: true})
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaBlob, err := crypto.SealBound(metaJSON, ck, crypto.AADMeta, id)
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
		// Both seals above bind iff id is non-empty, so the declaration follows the
		// same rule. In practice this is a create (callers pass id ""): the seals stay
		// unbound and the first putFolderUpdate re-seals them id-bound.
		MinClient: minClientForID(id),
	})
}

// putFolderUpdate replaces an existing folder's manifest, conditional on the
// resource still being at expectedVersion (else the server returns a conflict).
// The encrypted metadata (the folder name sealed at init) is carried forward
// unchanged, so a sync never clobbers it; metadata that predates id binding is
// re-sealed bound to the id once (init seals before the server assigns the id).
//
// vis is the resource's current visibility, carried forward for the same reason: a
// sync pushes content, it does not re-share or un-share. Hardcoding private here made
// the first sync after `aqt share` silently kill the link (the server takes visibility
// from every PUT). The link's lifecycle policy is preserved server-side, since this
// request carries none.
func putFolderUpdate(cl *client.Client, conv crypto.ConvergenceKey, id string, vis api.Visibility, m syncengine.Manifest, meta crypto.SealedBlob, ck crypto.ContentKey, mk crypto.MasterKey, expectedVersion int) (api.PutResourceResponse, error) {
	root, refs, err := uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck, id)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaBlob, err := resealMetaBound(meta, ck, id)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return cl.PutResource(api.PutResourceRequest{
		ID: id, Visibility: vis, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expectedVersion,
		MinClient: api.CapabilityIDBinding, // TreeRoot and meta are sealed id-bound (v2)
	})
}

// minClientForID reports the capability a folder write requires: a create (empty id)
// seals its root and metadata unbound and so stays baseline-readable, while an
// id-bound write needs the id-binding capability.
func minClientForID(id string) int {
	if id == "" {
		return api.CapabilityBaseline
	}
	return api.CapabilityIDBinding
}

// resealMetaBound upgrades carried-forward resource metadata that predates id
// binding: a blob already bound to the id passes through byte-identical, and only
// a legacy (unbound) blob is re-sealed. The raw plaintext is re-sealed (not
// re-marshaled), so fields a newer client wrote survive the round trip.
func resealMetaBound(meta crypto.SealedBlob, ck crypto.ContentKey, id string) (crypto.SealedBlob, error) {
	if _, err := crypto.Open(meta, ck, crypto.BoundAAD(crypto.AADMeta, id)); err == nil {
		return meta, nil
	}
	plain, err := crypto.Open(meta, ck, crypto.AADMeta)
	if err != nil {
		return crypto.SealedBlob{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	return crypto.SealBound(plain, ck, crypto.AADMeta, id)
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

// sealedBase is the at-rest envelope for the local base manifest. Its "sealed" key
// is disjoint from a plaintext Manifest's ("version"/"entries"), so a legacy
// unsealed base.json is detected and read transparently, then upgraded on the next
// save. base.json holds chunk decryption keys and inline file plaintext, so it is
// sealed under the profile's session sealing key rather than left in the clear.
type sealedBase struct {
	Sealed *crypto.SealedBlob `json:"sealed"`
}

func saveBase(root string, m syncengine.Manifest) error {
	plain, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sealed, err := identity.SealBase(flagProfile, plain)
	if err != nil {
		return err
	}
	b, err := json.Marshal(sealedBase{Sealed: &sealed})
	if err != nil {
		return err
	}
	return writeFileAtomic(controlPath(root, baseFile), b, 0o600)
}

// decodeBase unmarshals base.json bytes into m, transparently opening a sealed
// envelope (current format) or reading a legacy plaintext manifest (pre-seal,
// upgraded on the next save). The two forms have disjoint top-level keys, so the
// sealed probe is unambiguous.
func decodeBase(b []byte, m *syncengine.Manifest) error {
	var env sealedBase
	if err := json.Unmarshal(b, &env); err == nil && env.Sealed != nil {
		plain, err := identity.OpenBase(flagProfile, *env.Sealed)
		if err != nil {
			return err
		}
		b = plain
	}
	return json.Unmarshal(b, m)
}

// loadBaseForSync returns the last-synced manifest and whether a usable base
// exists. A missing, corrupt, or unopenable base reports exists=false so the caller
// can refuse the sync — reconciling against an empty base silently resurrects
// deletions — unless the user opts into --reconcile.
func loadBaseForSync(root string) (syncengine.Manifest, bool, error) {
	var m syncengine.Manifest
	b, err := os.ReadFile(controlPath(root, baseFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, false, nil
	}
	if err != nil {
		return m, false, err
	}
	if err := decodeBase(b, &m); err != nil {
		fmt.Fprintf(os.Stderr, "warning: .aqt/base.json is unreadable (%v)\n", err)
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
	return m, decodeBase(b, &m)
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

// defaultIgnoreBody is the build-artifact and cache exclude set every starter
// .aqtignore carries. These are regenerable outputs that otherwise dominate a
// sync (a Next.js .next/ measured ~915 MB, ~90% of one payload) and, being the
// largest packs, are the flakiest to transfer. Everything here is overridable:
// delete a line, or re-include a path with a trailing `!rule`. The ambiguous
// output dirs (dist/, build/, out/, bin/) sometimes hold committed assets, so
// they are called out for the user to prune.
const defaultIgnoreBody = `
# JS/TS / web
node_modules/
.next/
.nuxt/
.svelte-kit/
.astro/
.turbo/
.parcel-cache/
.cache/
.vite/
coverage/
*.tsbuildinfo

# Rust
target/

# Java / JVM (Gradle/Maven)
.gradle/
*.class

# Python
__pycache__/
*.pyc
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Build outputs (may hold committed assets; remove lines that do not apply)
dist/
build/
out/
bin/

# General
.DS_Store
Thumbs.db
*.log
`

const starterIgnore = `# aqt ignore patterns (gitignore syntax)
.git/
` + defaultIgnoreBody

// starterIgnoreWithGit re-includes .git for a user who chose to track their git
// history at init: aqt always ignores .git, and a leading ! overrides that.
const starterIgnoreWithGit = `# aqt ignore patterns (gitignore syntax)
# track the git repository (aqt ignores .git by default; ! re-includes it)
!.git/
` + defaultIgnoreBody

// writeStarterIgnore writes the starter .aqtignore, reporting whether it created
// the file so a failed init can remove exactly what it added.
func writeStarterIgnore(root string, syncGit bool) (created bool, err error) {
	path := filepath.Join(root, ".aqtignore")
	if _, err := os.Stat(path); err == nil {
		return false, nil // do not clobber an existing one
	}
	body := starterIgnore
	if syncGit {
		body = starterIgnoreWithGit
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return false, err
	}
	return true, nil
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

// materializeStaged fills dest by letting fn write into a staging directory that
// is renamed to dest only after fn succeeds, so a failed or interrupted
// materialization leaves dest exactly as it was (usually: absent) instead of
// half-populated. dest must not exist, or be an empty directory (the same
// contract ensureEmptyDir enforced); staging shares dest's parent so the commit
// rename never crosses filesystems.
func materializeStaged(dest string, fn func(staging string) error) error {
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	existedEmpty := false
	if fi, err := os.Stat(dest); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s already exists and is not a directory", dest)
		}
		entries, err := os.ReadDir(dest)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("%s already exists and is not empty", dest)
		}
		existedEmpty = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := os.MkdirTemp(parent, ".aqt-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging) // no-op once renamed; cleans up every failure path
	if err := fn(staging); err != nil {
		return err
	}
	// MkdirTemp creates 0700; the committed directory keeps the mode ensureEmptyDir
	// used to create.
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if existedEmpty {
		if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(staging, dest); err != nil {
		return fmt.Errorf("commit into %s (did something create it mid-transfer?): %w", dest, err)
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
	if flagJSON {
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

func printPlan(actions []syncengine.Action, dirActions []syncengine.DirAction, renames []syncengine.Rename) error {
	if flagJSON {
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
func printCopyPlan(root string, actions []syncengine.Action, dirActions []syncengine.DirAction, renames []syncengine.Rename, remote syncengine.Manifest, host string, now time.Time) error {
	if !flagJSON && len(actions) == 0 && len(dirActions) == 0 && len(renames) == 0 {
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
	if flagJSON {
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
func coalescePlanRenames(actions []syncengine.Action, dirActions []syncengine.DirAction, local, base, remote syncengine.Manifest) ([]syncengine.Action, []syncengine.DirAction, []syncengine.Rename) {
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

	covers := func(r syncengine.Rename, addPath, delPath string, add bool) bool {
		if r.Dir {
			if add {
				return strings.HasPrefix(addPath, r.To+"/")
			}
			return strings.HasPrefix(delPath, r.From+"/")
		}
		if add {
			return addPath == r.To
		}
		return delPath == r.From
	}
	keepActions := actions[:0:0]
	for _, a := range actions {
		match := func(r syncengine.Rename, add bool) bool {
			if add {
				return covers(r, a.Path, "", true)
			}
			return covers(r, "", a.Path, false)
		}
		if !renameCovers(a.Kind, localRen, remoteRen, match) {
			keepActions = append(keepActions, a)
		}
	}
	atOrUnder := func(path, dir string) bool {
		return path == dir || strings.HasPrefix(path, dir+"/")
	}
	keepDirs := dirActions[:0:0]
	for _, a := range dirActions {
		match := func(r syncengine.Rename, add bool) bool {
			if !r.Dir {
				return false
			}
			if add {
				return atOrUnder(a.Path, r.To)
			}
			return atOrUnder(a.Path, r.From)
		}
		if !renameCovers(a.Kind, localRen, remoteRen, match) {
			keepDirs = append(keepDirs, a)
		}
	}
	renames := append(localRen, remoteRen...)
	sort.Slice(renames, func(i, j int) bool { return renames[i].From < renames[j].From })
	return keepActions, keepDirs, renames
}

// renameCovers reports whether a detected rename subsumes an action of the given
// kind. match tests one rename against the action's path, distinguishing the added
// (To) side from the deleted (From) side. Local renames cover the push side of an
// action (Upload/DeleteRemote); remote renames cover the pull side
// (Download/DeleteLocal).
func renameCovers(kind syncengine.ActionKind, localRen, remoteRen []syncengine.Rename, match func(r syncengine.Rename, add bool) bool) bool {
	for _, r := range localRen {
		if (kind == syncengine.Upload && match(r, true)) ||
			(kind == syncengine.DeleteRemote && match(r, false)) {
			return true
		}
	}
	for _, r := range remoteRen {
		if (kind == syncengine.Download && match(r, true)) ||
			(kind == syncengine.DeleteLocal && match(r, false)) {
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

func summarize(uploads, downloads []syncengine.Entry, localDeletes []string) {
	if flagJSON {
		_ = printJSON(map[string]any{
			"uploaded": len(uploads), "uploadedBytes": entriesBytes(uploads),
			"downloaded": len(downloads), "downloadedBytes": entriesBytes(downloads),
			"removedLocally": len(localDeletes),
		})
		return
	}
	fmt.Printf("synced: %d up (%s), %d down (%s), %d removed locally\n",
		len(uploads), humanBytes(entriesBytes(uploads)),
		len(downloads), humanBytes(entriesBytes(downloads)), len(localDeletes))
}

// entriesBytes sums the plaintext size of a set of entries — the logical volume a
// transfer moves, used for the pre-transfer total and the summary.
func entriesBytes(entries []syncengine.Entry) int64 {
	var n int64
	for _, e := range entries {
		n += e.Size
	}
	return n
}

// uploadBytes estimates the plaintext bytes a push will credit to the progress bar:
// every new or content-changed local entry that is actually chunked into packs. Only
// chunked files reach the pack uploader that credits the bar, so symlinks and inline-
// sized files (kept in the manifest, never sent as packs) are excluded to keep the
// total close to what add() will report. Cross-file and base chunk dedup can still make
// the credited bytes smaller, so the bar is snapped to this total on completion.
func uploadBytes(local, base syncengine.Manifest, selector syncengine.ChunkSelector) int64 {
	baseByPath := base.ByPath()
	var n int64
	for _, e := range local.Entries {
		if e.IsSymlink() || e.Size <= int64(selector.ChunkerFor(e.Size).Min) {
			continue
		}
		if be, ok := baseByPath[e.Path]; !ok || be.Hash != e.Hash {
			n += e.Size
		}
	}
	return n
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
