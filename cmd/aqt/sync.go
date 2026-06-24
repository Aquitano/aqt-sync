package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// folderState is the per-folder pointer stored in .aqt/state.json: which resource
// on which server this directory tracks.
type folderState struct {
	ID     string `json:"id"`
	Server string `json:"server"`
}

const (
	stateFile = "state.json"
	baseFile  = "base.json"
	// uploadBatchBytes bounds a single chunk-upload request so it stays under the
	// server's body cap (base64 in JSON inflates ~33%, hence the conservative cap).
	uploadBatchBytes = 8 << 20
	fetchBatchCount  = 256
	// maxSyncAttempts bounds the optimistic-concurrency retry: if this many
	// reconcile passes each lose the race to a concurrent sync, give up and ask
	// the user to re-run rather than spin.
	maxSyncAttempts = 5
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

	// Register an empty private folder resource; the first `sync` fills it.
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	manifest := syncengine.Manifest{Version: 1}
	resp, err := putFolder(cl, "", manifest, ck, mk, abs)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	if err := writeStarterIgnore(abs); err != nil {
		return err
	}
	if err := saveState(abs, folderState{ID: resp.ID, Server: prof.Server}); err != nil {
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
	pushOnly  bool
	pullOnly  bool
	dryRun    bool
	force     bool
	reconcile bool
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
	if cfg, err := syncengine.LoadConfig(root); err != nil {
		return err
	} else if cfg.Pack {
		return errors.New("pack-and-seal folders (.aqtconfig pack=true) are not yet implemented; use chunked sync")
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

	// Snapshot the working tree once; it does not change between retries.
	snap, err := syncengine.Take(root, conv, syncengine.DefaultChunker(), &base)
	if err != nil {
		return err
	}
	local := snap.Manifest

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
		if res.WrappedKey == nil {
			return errors.New("folder resource has no owner key; cannot sync")
		}
		ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return fmt.Errorf("unwrap folder key: %w", err)
		}
		remote, err := syncengine.OpenManifest(res.Blob, ck)
		if err != nil {
			return fmt.Errorf("decrypt remote manifest: %w", err)
		}
		// With no trusted base, reconcile from scratch: one-sided differences are
		// ambiguous and become conflicts to review rather than silent adds/deletes.
		var actions []syncengine.Action
		if baseExists {
			actions = syncengine.Plan(local, base, remote)
		} else {
			actions = syncengine.PlanReconcile(local, remote)
		}
		if opts.dryRun {
			return printPlan(actions)
		}
		if err := abortOnConflicts(actions, opts.force); err != nil {
			return err
		}
		return applySync(applyCtx{
			root: root, cl: cl, opts: opts,
			base: base, local: local, remote: remote,
			snap: snap, ck: ck, mk: mk, meta: res.EncryptedMeta,
			version: res.Version, id: st.ID,
		}, actions)
	}

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
	snap    *syncengine.Snapshot
	ck      crypto.ContentKey
	mk      crypto.MasterKey
	meta    crypto.SealedBlob // the resource's existing sealed metadata, carried forward
	version int
	id      string
}

func applySync(c applyCtx, actions []syncengine.Action) error {
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

	// Fold paths that converged to identical content on both sides into the new
	// base. Plan emits no action for them (there is nothing to transfer), so without
	// this they stay "changed on both sides" forever: a later remote-only delete is
	// then misread as a local add, the file is re-pushed, and the deletion never
	// propagates.
	for p, le := range localByPath {
		if re, ok := remoteByPath[p]; ok && le.Hash == re.Hash {
			newBase[p] = re
		}
	}

	// Push the server-side change FIRST. Uploading chunks and PUTting the manifest
	// before any local file is touched means a version conflict (another sync
	// committed first) returns with nothing half-applied on disk, so the caller
	// can re-plan and retry cleanly.
	if push && remoteChanged {
		if err := uploadMissing(c.cl, c.snap.NewChunks, uploads); err != nil {
			return err
		}
		manifest := manifestFrom(merged, c.version+1)
		if _, err := putFolderUpdate(c.cl, c.id, manifest, c.meta, c.ck, c.mk, c.version); err != nil {
			return err // client.ErrConflict on a stale version: retried by the caller
		}
		// Reclaim chunks the superseded manifest version no longer references.
		// Best-effort: a sync that uploaded fine should not fail on cleanup, but a
		// failure is worth a line since GC is the one step that deletes blobs.
		if n, err := c.cl.GC(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: chunk GC failed: %v\n", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "reclaimed %d unreferenced chunks\n", n)
		}
	}

	// Server is updated; now bring the local tree in line. Downloads before
	// deletes, so local data is never removed before its replacement is on disk.
	if err := runDownloads(c.cl, c.root, downloads); err != nil {
		return err
	}
	for _, p := range localDeletes {
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return err
		}
	}

	if err := saveBase(c.root, manifestFrom(newBase, c.version+1)); err != nil {
		return err
	}
	summarize(uploads, downloads, localDeletes, remoteChanged)
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
	manifest, err := syncengine.OpenManifest(res.Blob, ck)
	if err != nil {
		return fmt.Errorf("decrypt manifest: %w", err)
	}

	if dir == "" {
		dir = id
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := ensureEmptyDir(abs); err != nil {
		return err
	}
	if err := runDownloads(cl, abs, manifest.Entries); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	if err := saveState(abs, folderState{ID: id, Server: prof.Server}); err != nil {
		return err
	}
	if err := saveBase(abs, manifest); err != nil {
		return err
	}
	fmt.Printf("cloned %d files into %s\n", len(manifest.Entries), abs)
	return nil
}

// --- chunk transfer ---

// uploadMissing uploads the chunks of the given entries that the server lacks,
// batched under the body cap. Ciphertext comes from the snapshot that sealed them.
func uploadMissing(cl *client.Client, sealed map[string][]byte, entries []syncengine.Entry) error {
	ids := distinctChunkIDs(entries)
	if len(ids) == 0 {
		return nil
	}
	missing, err := cl.CheckChunks(ids)
	if err != nil {
		return err
	}
	var batch []api.ChunkData
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := cl.PutChunks(batch); err != nil {
			return err
		}
		batch, size = nil, 0
		return nil
	}
	for _, id := range missing {
		ct, ok := sealed[id]
		if !ok {
			return fmt.Errorf("internal: no sealed ciphertext for chunk %s", id)
		}
		batch = append(batch, api.ChunkData{ID: id, Data: ct})
		size += len(ct)
		if size >= uploadBatchBytes {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// runDownloads fetches every chunk the entries reference, then reconstructs and
// writes each file under root.
func runDownloads(cl *client.Client, root string, entries []syncengine.Entry) error {
	fetched, err := fetchChunks(cl, distinctChunkIDs(entries))
	if err != nil {
		return err
	}
	get := func(id string) ([]byte, error) {
		ct, ok := fetched[id]
		if !ok {
			return nil, fmt.Errorf("server did not return chunk %s", id)
		}
		return ct, nil
	}
	for _, e := range entries {
		if e.IsSymlink() {
			if err := syncengine.WriteSymlink(root, e); err != nil {
				return err
			}
			continue
		}
		data, err := syncengine.FileBytes(e, get)
		if err != nil {
			return err
		}
		if err := syncengine.WriteFile(root, e, data); err != nil {
			return err
		}
	}
	return nil
}

func fetchChunks(cl *client.Client, ids []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(ids))
	for start := 0; start < len(ids); start += fetchBatchCount {
		end := start + fetchBatchCount
		if end > len(ids) {
			end = len(ids)
		}
		chunks, err := cl.FetchChunks(ids[start:end])
		if err != nil {
			return nil, err
		}
		for _, ch := range chunks {
			out[ch.ID] = ch.Data
		}
	}
	return out, nil
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

func putFolder(cl *client.Client, id string, m syncengine.Manifest, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	blob, err := syncengine.SealManifest(m, ck)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: filepath.Base(dir), Kind: api.KindFolder})
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
		WrappedKey: &wrapped, ChunkRefs: m.ChunkIDs(),
	})
}

// putFolderUpdate replaces an existing folder's manifest, conditional on the
// resource still being at expectedVersion (else the server returns a conflict).
// The encrypted metadata (the folder name sealed at init) is carried forward
// unchanged, so a sync never clobbers it.
func putFolderUpdate(cl *client.Client, id string, m syncengine.Manifest, meta crypto.SealedBlob, ck crypto.ContentKey, mk crypto.MasterKey, expectedVersion int) (api.PutResourceResponse, error) {
	blob, err := syncengine.SealManifest(m, ck)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return cl.PutResource(api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
		WrappedKey: &wrapped, ChunkRefs: m.ChunkIDs(), ExpectedVersion: expectedVersion,
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

// --- local state ---

func controlPath(root, name string) string {
	return filepath.Join(root, syncengine.ControlDir, name)
}

func saveState(root string, st folderState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(controlPath(root, stateFile), b, 0o600)
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
	return os.WriteFile(controlPath(root, baseFile), b, 0o600)
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

func writeStarterIgnore(root string) error {
	path := filepath.Join(root, ".aqtignore")
	if _, err := os.Stat(path); err == nil {
		return nil // do not clobber an existing one
	}
	return os.WriteFile(path, []byte(starterIgnore), 0o644)
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

func abortOnConflicts(actions []syncengine.Action, force bool) error {
	if force {
		return nil
	}
	var conflicts []string
	for _, a := range actions {
		if a.Kind == syncengine.Conflict {
			conflicts = append(conflicts, a.Path)
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	printPaths("conflict", conflicts)
	return errConflictsRemain
}

func printPlan(actions []syncengine.Action) error {
	if len(actions) == 0 {
		fmt.Println("already in sync")
		return nil
	}
	for _, a := range actions {
		fmt.Printf("%-13s %s\n", a.Kind, a.Path)
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
