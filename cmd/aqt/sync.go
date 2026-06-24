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
	// packCacheSize bounds how many recently-fetched pack byte-ranges a pull keeps,
	// so a pack shared by several files is not re-GET per file while download memory
	// stays O(pack), independent of tree size.
	packCacheSize = 4
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

	// aqt ignores .git by default; offer to track it when this tree holds a repo.
	syncGit := false
	if repo, ok := firstGitRepo(abs); ok {
		syncGit, err = promptSyncGit(repo)
		if err != nil {
			return err
		}
	}

	// Register an empty private folder resource; the first `sync` fills it.
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()
	manifest := syncengine.Manifest{Version: 1}
	resp, err := putFolder(cl, conv, "", manifest, ck, mk, abs)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	if err := writeStarterIgnore(abs, syncGit); err != nil {
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
		up := newPackUploader(cl)
		local, err = syncengine.Take(root, conv, syncengine.DefaultChunker(), &base, up)
		if err != nil {
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
		if res.WrappedKey == nil {
			return errors.New("folder resource has no owner key; cannot sync")
		}
		ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
		if err != nil {
			return fmt.Errorf("unwrap folder key: %w", err)
		}
		remote, err := openRemoteManifest(cl, res.Blob, ck)
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
			conv: conv, ck: ck, mk: mk, meta: res.EncryptedMeta,
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
	conv    crypto.ConvergenceKey
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

	// Push the server-side change FIRST, before any local file is touched, so a
	// version conflict (another sync committed first) returns with nothing
	// half-applied on disk and the caller can re-plan cleanly. The objects these
	// entries reference were already packed and uploaded during the snapshot pass;
	// here we only commit the merged manifest that roots them.
	if push && remoteChanged {
		manifest := manifestFrom(merged, c.version+1)
		if _, err := putFolderUpdate(c.cl, c.conv, c.id, manifest, c.meta, c.ck, c.mk, c.version); err != nil {
			return err // client.ErrConflict on a stale version: retried by the caller
		}
		// Reclaim packs the superseded manifest version no longer references.
		// Best-effort: a sync that uploaded fine should not fail on cleanup, but a
		// failure is worth a line since GC is the one step that deletes packs.
		if n, freed, err := c.cl.GC(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: pack GC failed: %v\n", err)
		} else if n > 0 {
			fmt.Fprintf(os.Stderr, "reclaimed %d packs (%d bytes)\n", n, freed)
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
	manifest, err := openRemoteManifest(cl, res.Blob, ck)
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

// packUploader is the ChunkSink Take feeds during a push. It buffers sealed chunks
// up to ~packTarget, then asks the server which it lacks, packs only those, and
// uploads the pack — so the have/want gate and packing fold into one streaming pass
// and memory stays bounded by the candidate buffer. A per-run seen set dedups a
// chunk shared by several files within the same sync.
type packUploader struct {
	cl       *client.Client
	target   int
	seen     map[string]bool
	cand     []candidate
	candSize int
}

type candidate struct {
	id string
	ct []byte
}

func newPackUploader(cl *client.Client) *packUploader {
	return &packUploader{cl: cl, target: syncengine.DefaultPackTarget, seen: map[string]bool{}}
}

// Add buffers one sealed chunk, flushing a pack once the buffer reaches the target.
func (u *packUploader) Add(ch crypto.Chunk, ciphertext []byte) error {
	if u.seen[ch.ID] {
		return nil
	}
	u.seen[ch.ID] = true
	u.cand = append(u.cand, candidate{id: ch.ID, ct: ciphertext})
	u.candSize += len(ciphertext)
	if u.candSize >= u.target {
		return u.flush()
	}
	return nil
}

// Flush uploads any buffered remainder; call once after the snapshot pass.
func (u *packUploader) Flush() error { return u.flush() }

func (u *packUploader) flush() error {
	if len(u.cand) == 0 {
		return nil
	}
	ids := make([]string, len(u.cand))
	for i, c := range u.cand {
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
	for _, c := range u.cand {
		if want[c.id] {
			pb.Add(c.id, c.ct)
		}
	}
	u.cand = u.cand[:0]
	u.candSize = 0
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
		cache: newPackCache(packCacheSize),
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
		return nil, fmt.Errorf("server could not locate chunk %s", id)
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

// packCache is a tiny count-bounded LRU of fetched pack byte-ranges, so download
// memory is O(packCacheSize packs) regardless of how many files a pack serves.
type packCache struct {
	cap   int
	data  map[string][]byte
	order []string // least-recently-used first
}

func newPackCache(capacity int) *packCache {
	return &packCache{cap: capacity, data: make(map[string][]byte, capacity)}
}

func (c *packCache) get(id string) ([]byte, bool) {
	b, ok := c.data[id]
	if ok {
		c.touch(id)
	}
	return b, ok
}

func (c *packCache) put(id string, b []byte) {
	if _, ok := c.data[id]; ok {
		c.data[id] = b
		c.touch(id)
		return
	}
	c.data[id] = b
	c.order = append(c.order, id)
	for len(c.order) > c.cap {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.data, evict)
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

// uploadManifestObjects chunks the manifest through the convergence key, uploads
// the objects the server lacks (via the same pack pipeline as file content), and
// returns the root pointer plus the resource's full GC roots: every file-chunk id
// the manifest references unioned with the manifest's own object ids. The manifest
// objects must be on the server before the resource PUT roots them, hence the flush.
func uploadManifestObjects(cl *client.Client, conv crypto.ConvergenceKey, m syncengine.Manifest) (syncengine.ManifestRoot, []string, error) {
	up := newPackUploader(cl)
	chunks, err := syncengine.ChunkManifest(m, conv, syncengine.DefaultChunker(), up)
	if err != nil {
		return syncengine.ManifestRoot{}, nil, err
	}
	if err := up.Flush(); err != nil {
		return syncengine.ManifestRoot{}, nil, err
	}
	refs := m.ChunkIDs()
	for _, ch := range chunks {
		refs = append(refs, ch.ID)
	}
	return syncengine.ManifestRoot{Version: m.Version, Chunks: chunks}, refs, nil
}

// openRemoteManifest reconstructs a folder's manifest from its root pointer: it
// decrypts the tiny root, then fetches and reassembles the manifest objects from
// their packs. The inverse of uploadManifestObjects.
func openRemoteManifest(cl *client.Client, blob crypto.SealedBlob, ck crypto.ContentKey) (syncengine.Manifest, error) {
	root, err := syncengine.OpenManifestRoot(blob, ck)
	if err != nil {
		return syncengine.Manifest{}, err
	}
	if len(root.Chunks) == 0 {
		return syncengine.Manifest{Version: root.Version}, nil
	}
	src, err := newPackSource(cl, manifestChunkIDs(root.Chunks))
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.OpenManifestFromRoot(root, src.get)
}

func manifestChunkIDs(chunks []crypto.Chunk) []string {
	ids := make([]string, len(chunks))
	for i, ch := range chunks {
		ids[i] = ch.ID
	}
	return ids
}

func putFolder(cl *client.Client, conv crypto.ConvergenceKey, id string, m syncengine.Manifest, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	root, refs, err := uploadManifestObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealManifestRoot(root, ck)
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
		WrappedKey: &wrapped, ChunkRefs: refs,
	})
}

// putFolderUpdate replaces an existing folder's manifest, conditional on the
// resource still being at expectedVersion (else the server returns a conflict).
// The encrypted metadata (the folder name sealed at init) is carried forward
// unchanged, so a sync never clobbers it.
func putFolderUpdate(cl *client.Client, conv crypto.ConvergenceKey, id string, m syncengine.Manifest, meta crypto.SealedBlob, ck crypto.ContentKey, mk crypto.MasterKey, expectedVersion int) (api.PutResourceResponse, error) {
	root, refs, err := uploadManifestObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealManifestRoot(root, ck)
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
