// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// runPackSync reconciles a pack-and-seal folder (.aqtconfig pack=true). The server
// holds one opaque blob, so there is nothing to merge per file: it is whole-folder
// last-writer-wins. Whichever side changed is pushed or pulled in full; a change on
// both is a folder-level conflict that --force resolves local-wins.
func runPackSync(root string, opts syncOptions) error {
	sess, err := openSyncSession(root, opts)
	if err != nil {
		return err
	}
	defer sess.Wipe()

	// A metadata+hash scan is all the local side needs to tell whether the tree
	// changed since the last sync; pack-and-seal never chunks per file.
	var scanBase *syncengine.Manifest
	if sess.baseExists {
		scanBase = &sess.base
	}
	local, err := syncengine.ScanReusing(root, scanBase, opts.rehash)
	if err != nil {
		return err
	}
	warnSkipped(local.Skipped)

	c := packCtx{syncSession: sess, opts: opts, local: local, push: &packPushArtifacts{}}
	// c's session holds a by-value copy of the master key that the deferred sess.Wipe
	// above does not reach.
	defer c.Wipe()
	return reconcileWithRetry(func() error { return reconcilePack(c) })
}

type packCtx struct {
	syncSession
	opts  syncOptions
	local syncengine.Manifest
	// resuming means a pull marker forced this pull: the fresh scan holds a torn
	// tree, so the overwrite guard must trust the last-synced base instead of it.
	resuming bool
	// push caches the tar+seal+upload across conflict retries (pointer so it persists
	// when packCtx is copied per reconcile pass).
	push *packPushArtifacts
}

// packPushArtifacts holds a push's sealed root and shipped manifest once built, so a
// conflict retry re-PUTs the root at the new version instead of re-tarring and
// re-uploading the whole tree. The segments are content-addressed and idempotent on
// the server, so they need uploading only once.
type packPushArtifacts struct {
	root    syncengine.PackRoot
	shipped syncengine.Manifest
	built   bool
}

func reconcilePack(c packCtx) error {
	rs, err := c.openRemote(c.opts, formatPacked)
	if err != nil {
		return err
	}
	defer rs.ck.Wipe()

	// Read on every pass rather than once per run: a retry after a lost race has not
	// completed a pull, so the marker it would clear is still the truth on disk.
	torn, err := loadPullMarker(c.root)
	if err != nil {
		return err
	}

	// No base to trust — either none was recorded (--reconcile) or an accepted
	// rollback invalidated it. Compare the actual trees instead: a rolled-back server
	// read as "remote changed" would have decidePack pull the old tree over newer
	// local files.
	if !rs.trustBase {
		return reconcilePackNoBase(c, rs.res, rs.ck, torn)
	}

	// Diff, not the file-only planner: a pack folder seals its tracked directories
	// too, so an empty-directory add/remove or a directory-mode edit is a real local
	// change. Gating on file actions alone reported those trees as already synced and
	// never pushed them.
	localChanged := !syncengine.Diff(c.base, c.local).Empty()
	remoteChanged := rs.res.Version != c.base.Version
	action := decidePack(localChanged, remoteChanged, c.opts)
	if torn.present {
		if action, err = resumeInterruptedPull(c.opts, torn); err != nil {
			return err
		}
		c.resuming = true
	}

	if c.opts.dryRun {
		printPackAction(action)
		return nil
	}
	switch action {
	case packPush:
		return pushPack(c, rs.res, rs.ck)
	case packPull:
		return pullPack(c, rs.res, rs.ck)
	case packConflict:
		fmt.Fprintln(os.Stderr, "conflict: the folder changed on both sides since the last sync")
		return errConflictsRemain
	default:
		recordRemoteVersion(c.root, rs.res.Version)
		if flagJSON {
			return printJSON(map[string]any{"uploaded": 0, "downloaded": 0})
		}
		fmt.Println("already in sync")
		return nil
	}
}

type packDecision int

const (
	packNoop packDecision = iota
	packPush
	packPull
	packConflict
)

// decidePack maps the two-sided change state to one whole-folder action under the
// last-writer-wins model. --push-only/--pull-only restrict the direction, but they
// do not waive the conflict guard: if the other side also moved, the restricted
// action would silently discard it, so it is a conflict unless --force resolves
// it local-wins (push, or skip the pull) — matching the chunked path and the
// printed hint, so --force means the same thing across every CLI path.
func decidePack(localChanged, remoteChanged bool, opts syncOptions) packDecision {
	switch {
	case opts.pushOnly:
		switch {
		case !localChanged:
			return packNoop
		case remoteChanged && !opts.force:
			return packConflict
		default:
			return packPush
		}
	case opts.pullOnly:
		switch {
		case !remoteChanged:
			return packNoop
		case localChanged && !opts.force:
			return packConflict
		case localChanged:
			// --force resolves local-wins: keep the local edit and skip the
			// pull, matching the chunked path (Conflict + !push skips) and
			// the printed hint. pullOnly won't push, so local-wins is a noop.
			return packNoop
		default:
			return packPull
		}
	case localChanged && remoteChanged:
		if opts.force {
			return packPush
		}
		return packConflict
	case localChanged:
		return packPush
	case remoteChanged:
		return packPull
	default:
		return packNoop
	}
}

func printPackAction(a packDecision) {
	if flagJSON {
		action := "none"
		switch a {
		case packPush:
			action = "push"
		case packPull:
			action = "pull"
		case packConflict:
			action = "conflict"
		}
		_ = printJSON([]planLine{{Action: action, Path: ".", Dir: true}})
		return
	}
	switch a {
	case packPush:
		fmt.Println("push     (whole folder, pack-and-seal)")
	case packPull:
		fmt.Println("pull     (whole folder, pack-and-seal)")
	case packConflict:
		fmt.Println("conflict (changed on both sides; --force resolves local-wins)")
	default:
		fmt.Println("already in sync")
	}
}

// reconcilePackNoBase handles --reconcile, where no last-synced state distinguishes
// an add from a delete. One empty side is unambiguous; otherwise the trees are
// compared and an actual difference is a conflict unless --force.
func reconcilePackNoBase(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey, torn pullMarker) error {
	root, err := syncengine.OpenPackRoot(res.Blob, ck, res.ID)
	if err != nil {
		return fmt.Errorf("decrypt remote pack root: %w", err)
	}
	// A torn tree is not evidence of anything the comparison below could read: half of
	// it is already the remote's, the rest is stale. Finish the pull instead.
	if torn.present {
		action, err := resumeInterruptedPull(c.opts, torn)
		if err != nil {
			return err
		}
		if c.opts.dryRun {
			printPackAction(action)
			return nil
		}
		return pullPackFromRoot(c, res, ck, root)
	}
	remoteEmpty := root.Size == 0 || len(root.Segments) == 0
	localEmpty := len(c.local.Entries) == 0
	push := !c.opts.pullOnly

	action := packNoop
	switch {
	case localEmpty && remoteEmpty:
		action = packNoop
	case remoteEmpty && push:
		action = packPush
	case localEmpty && !c.opts.pushOnly:
		action = packPull
	default:
		equal, err := remoteEqualsLocal(c, root, ck)
		if err != nil {
			return err
		}
		switch {
		case equal:
			action = packNoop
		case !c.opts.force:
			action = packConflict
		case push:
			action = packPush
		default:
			action = packPull
		}
	}

	if c.opts.dryRun {
		printPackAction(action)
		return nil
	}
	switch action {
	case packPush:
		return pushPack(c, res, ck)
	case packPull:
		return pullPackFromRoot(c, res, ck, root)
	case packConflict:
		fmt.Fprintln(os.Stderr, "conflict: local and remote differ and there is no base to reconcile against")
		return errConflictsRemain
	default:
		if err := savePackBase(c.root, c.local, res.Version); err != nil {
			return err
		}
		recordRemoteVersion(c.root, res.Version)
		return nil
	}
}

// pushPack tars the whole tree, seals it into fresh segments, uploads them, and commits
// the new root (version-checked, so a concurrent push is retried not lost). The
// tar+seal+upload runs once and is cached: a conflict retry re-PUTs the same root at
// the new version rather than re-shipping the tree, since the segments are already on
// the server.
func pushPack(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey) error {
	if err := refuseCaseCollisions(c.local.Entries, c.local.Dirs); err != nil {
		return err
	}
	if !c.push.built {
		var base *syncengine.Manifest
		if c.baseExists {
			base = &c.base
		}
		packer := newSegmentPacker(c.cl)
		root, shipped, err := syncengine.TarAndSeal(c.root, ck, base, packer)
		if err != nil {
			return err
		}
		if err := packer.Flush(); err != nil {
			return err
		}
		c.push.root, c.push.shipped, c.push.built = root, shipped, true
	}
	resp, err := putPackFolderUpdate(c.cl, c.st.ID, c.push.root, ck, c.mk, res.EncryptedMeta, res.Version)
	if err != nil {
		return err
	}
	reclaimPacks(c.root, c.cl)
	// Base off what was actually tarred, not the earlier c.local scan: a file changing
	// in between would leave a base disagreeing with the shipped bytes.
	if err := savePackBase(c.root, c.push.shipped, resp.Version); err != nil {
		return err
	}
	recordRemoteVersion(c.root, resp.Version)
	if flagJSON {
		return printJSON(map[string]any{"uploaded": len(c.push.shipped.Entries), "downloaded": 0})
	}
	fmt.Printf("synced: pushed %d files (pack-and-seal)\n", len(c.push.shipped.Entries))
	return nil
}

// extractPack range-fetches a pack-and-seal tree's segments and untars it under dir,
// returning the manifest of what it wrote. Shared by clone, pull, and reconcile so the
// fetch+extract wiring lives in one place. safe, when non-nil, vetoes individual
// entries just before they land (see ExtractToTree); clone passes nil.
func extractPack(cl *client.Client, dir string, root syncengine.PackRoot, ck crypto.ContentKey, safe func(path string) (bool, error)) (syncengine.Manifest, error) {
	src, err := newPackSource(cl, root.SegmentIDs())
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.ExtractToTree(dir, root, ck, src.get, safe)
}

// pullPack replaces the working tree with the remote one. It opens the root; callers
// that already decrypted it use pullPackFromRoot to avoid a second decrypt.
func pullPack(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey) error {
	root, err := syncengine.OpenPackRoot(res.Blob, ck, res.ID)
	if err != nil {
		return fmt.Errorf("decrypt remote pack root: %w", err)
	}
	return pullPackFromRoot(c, res, ck, root)
}

// pullPackFromRoot untars the remote tree over the working tree, then removes local
// files the new tree no longer contains. Both steps re-verify their target against a
// guard manifest first — the fresh scan, or the last-synced base when resuming an
// interrupted pull — so an edit the guard did not record keeps its local bytes and
// is reported as a conflict instead of being clobbered. The saved base still records
// the remote entry, so the next sync sees the kept edit as a pending local change
// and pack-mode last-writer-wins resolves it.
//
// The whole extract-and-prune runs under a pull marker. A pack pull writes in place —
// unlike clone, a directory pull, or a restore, which stage beside the destination
// and rename — because it must not disturb the ignored files (build output, caches)
// living alongside the tracked tree. That makes an interrupted pull a torn tree, and
// nothing in a scan distinguishes one from deliberate local edits; the marker is what
// tells the next run which it is.
func pullPackFromRoot(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey, root syncengine.PackRoot) error {
	if err := beginPullMarker(c.root, res.Version); err != nil {
		return err
	}
	// The overwrite guard trusts the manifest that still describes an untouched
	// file. A first pull trusts the fresh scan — decidePack chose packPull because
	// scan and base agree. A resumed pull cannot: the scan holds the half-applied
	// version and any edit made since the interruption, and cannot tell them apart,
	// so it trusts the last-synced base — an edit made in the torn tree is kept and
	// reported instead of being read as part of the interrupted pull.
	guard := c.local
	if c.resuming {
		guard = c.base
	}
	guardByPath := guard.ByPath()
	var conflicts []string
	// held maps a refused path to its on-disk hash at decision time. The incoming
	// entry's hash is only known once the archive streams past it, so the refusal is
	// re-checked afterward: bytes that already equal the entry (a file the
	// interrupted pull landed before dying) are no conflict at all.
	held := map[string]string{}
	safe := func(path string) (bool, error) {
		h, exists, isDir, err := syncengine.HashOnDisk(c.root, path)
		if err != nil {
			return false, err
		}
		if !exists || isDir {
			// Nothing to destroy, or a dir->file replacement the treeWriter handles.
			return true, nil
		}
		if prev, ok := guardByPath[path]; ok && h == prev.Hash {
			return true, nil // unchanged since the guard manifest
		}
		held[path] = h
		return false, nil
	}
	remote, err := extractPack(c.cl, c.root, root, ck, safe)
	if err != nil {
		// A located-but-missing segment means a concurrent push superseded this
		// version and GC reaped it; re-reconcile against the current version.
		if errors.Is(err, client.ErrNotFound) {
			return client.ErrConflict
		}
		return err
	}
	warnSkipped(remote.Skipped)
	remoteByPath := remote.ByPath()
	for p, h := range held {
		if e, ok := remoteByPath[p]; ok && e.Hash == h {
			continue
		}
		conflicts = append(conflicts, p)
	}
	// Prune whatever the remote no longer carries, but only paths the guard
	// manifest saw: a file created since it was recorded — while the pull ran, or
	// after an interruption — is a local add for the next sync, not this version's
	// garbage. A guarded path whose content drifted since is a conflict, same as
	// the extract guard above.
	postPull, err := syncengine.ListPaths(c.root)
	if err != nil {
		return err
	}
	for _, p := range postPull {
		if _, ok := remoteByPath[p]; ok {
			continue
		}
		le, ok := guardByPath[p]
		if !ok {
			continue // created since the guard manifest
		}
		h, exists, isDir, err := syncengine.HashOnDisk(c.root, p)
		if err != nil {
			return err
		}
		if exists && (isDir || h != le.Hash) {
			conflicts = append(conflicts, p)
			continue
		}
		if err := syncengine.RemoveFile(c.root, p); err != nil {
			return err
		}
	}
	// Tracked directories the remote dropped, pruned after their files so an emptied
	// directory can go. RemoveDir removes only an empty one, so a directory still
	// holding untracked content survives — the rule the chunked apply follows too.
	remoteDirs := remote.DirsByPath()
	var goneDirs []string
	for _, d := range c.local.Dirs {
		if _, ok := remoteDirs[d.Path]; !ok {
			goneDirs = append(goneDirs, d.Path)
		}
	}
	if err := removeDirs(c.root, goneDirs); err != nil {
		return err
	}
	// The prune above removes now-empty parents blind to the tracked set; recreate
	// any tracked directory it took (the chunked apply runs the same healing pass).
	if err := syncengine.EnsureDirs(c.root, remote.Dirs); err != nil {
		return err
	}
	if err := savePackBase(c.root, remote, res.Version); err != nil {
		return err
	}
	// Cleared before the conflict return below: a kept local edit is a completed pull
	// whose base records the remote entry, not a torn tree.
	if err := clearPullMarker(c.root); err != nil {
		return err
	}
	recordRemoteVersion(c.root, res.Version)
	sort.Strings(conflicts)
	if flagJSON {
		if err := printJSON(map[string]any{"uploaded": 0, "downloaded": len(remote.Entries), "conflicts": nonNil(conflicts)}); err != nil {
			return err
		}
	} else {
		fmt.Printf("synced: pulled %d files (pack-and-seal)\n", len(remote.Entries))
	}
	if len(conflicts) > 0 {
		if !flagJSON {
			printPaths("conflict", conflicts)
		}
		return errConflictsRemain
	}
	return nil
}

// remoteEqualsLocal reports whether the remote pack tree matches the working tree, so
// a baseless reconcile of two identical trees is not flagged as a conflict. It hashes
// the remote tree from its segments in memory rather than materializing it to a scratch
// dir and deleting it — no disk write, half the I/O.
func remoteEqualsLocal(c packCtx, root syncengine.PackRoot, ck crypto.ContentKey) (bool, error) {
	src, err := newPackSource(c.cl, root.SegmentIDs())
	if err != nil {
		return false, err
	}
	remote, err := syncengine.PackTreeManifest(root, ck, src.get)
	if err != nil {
		return false, err
	}
	return syncengine.Diff(remote, c.local).Empty(), nil
}

func savePackBase(root string, m syncengine.Manifest, version int) error {
	m.Version = version
	return saveBase(root, m)
}

// pullMarker is .aqt/pull-in-progress: the record that a pack-and-seal pull started
// writing into the working tree and has not finished. present is false when the file
// is absent, which is the ordinary state.
type pullMarker struct {
	present bool
	// Version names what the interrupted pull was landing; it goes in the message
	// so the user can see which state the tree is stuck between.
	Version int `json:"version"`
}

const pullMarkerFile = "pull-in-progress"

func beginPullMarker(root string, version int) error {
	b, err := json.MarshalIndent(pullMarker{Version: version}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(controlPath(root, pullMarkerFile), b, 0o600)
}

func clearPullMarker(root string) error {
	if err := os.Remove(controlPath(root, pullMarkerFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// loadPullMarker reports whether a pull was interrupted here. A marker that will not
// parse still counts as present: it was written by a pull that started, and the
// version it names is only used for the message.
func loadPullMarker(root string) (pullMarker, error) {
	b, err := os.ReadFile(controlPath(root, pullMarkerFile))
	if errors.Is(err, os.ErrNotExist) {
		return pullMarker{}, nil
	}
	if err != nil {
		return pullMarker{}, err
	}
	m := pullMarker{present: true}
	_ = json.Unmarshal(b, &m)
	return m, nil
}

// resumeInterruptedPull overrides the decision for a tree a previous pull left torn.
// Half of that tree is the remote's bytes and the rest is stale, and no scan can tell
// it from deliberate local edits — decidePack reads it as "changed on both sides" and
// offers `--force`, which maps to a push that would tar the torn tree and make it the
// authoritative version, destroying the intact remote folder. Finishing the pull is
// the only resolution that does not lose data, so --force cannot re-route it into a
// push and --push-only refuses outright.
func resumeInterruptedPull(opts syncOptions, m pullMarker) (packDecision, error) {
	if opts.pushOnly {
		return packNoop, fmt.Errorf("a pull of this folder was interrupted (version %d), so the "+
			"working tree holds part of the remote version and part of the old one; pushing it "+
			"would overwrite the intact remote folder with the torn tree. Run `aqt sync` to finish "+
			"the pull first", m.Version)
	}
	if !flagJSON {
		fmt.Fprintf(os.Stderr, "note: a previous pull was interrupted (version %d); "+
			"the working tree is incomplete, so this sync finishes the pull\n", m.Version)
	}
	return packPull, nil
}

func putPackFolderCreate(cl *client.Client, root syncengine.PackRoot, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	// A create's seals cannot bind the resource id (the server assigns it in the
	// response); the first putPackFolderUpdate re-seals both bound.
	blob, err := syncengine.SealPackRoot(root, ck, "")
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: filepath.Base(dir), Kind: api.KindFolder, Packed: true})
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
		Visibility: api.Private, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, ChunkRefs: root.SegmentIDs(),
		MinClient: api.CapabilityBaseline, // create seals unbound; the first update re-seals bound
	})
}

// putPackFolderUpdate commits a new root over an existing pack folder. The sealed
// metadata (the folder name and packed flag) is carried forward unchanged;
// metadata that predates id binding is re-sealed bound to the id once (create
// seals before the server assigns the id).
func putPackFolderUpdate(cl *client.Client, id string, root syncengine.PackRoot, ck crypto.ContentKey, mk crypto.MasterKey, meta crypto.SealedBlob, expectedVersion int) (api.PutResourceResponse, error) {
	blob, err := syncengine.SealPackRoot(root, ck, id)
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
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, ChunkRefs: root.SegmentIDs(), ExpectedVersion: expectedVersion,
		MinClient: api.CapabilityIDBinding, // root and meta are sealed id-bound (v2)
	})
}

// segmentPacker bundles pack-and-seal segments into packs and uploads them. Unlike
// packUploader it runs no have/want check: each segment is sealed with a fresh
// nonce, so it is always new and the gate would only cost a round-trip.
type segmentPacker struct {
	cl *client.Client
	pb *syncengine.PackBuilder
}

func newSegmentPacker(cl *client.Client) *segmentPacker {
	return &segmentPacker{cl: cl, pb: syncengine.NewPackBuilder()}
}

func (p *segmentPacker) Add(id string, object []byte) error {
	// Same dispatch-before-append rule as packUploader.Add: never assemble a pack
	// the server's body cap rejects.
	if !p.pb.Empty() && !syncengine.FitsInPack(p.pb.Size(), p.pb.Objects(), len(object)) {
		if err := p.flush(); err != nil {
			return err
		}
	}
	p.pb.Add(id, object)
	if p.pb.Size() >= syncengine.DefaultPackTarget {
		return p.flush()
	}
	return nil
}

func (p *segmentPacker) Flush() error { return p.flush() }

func (p *segmentPacker) flush() error {
	if p.pb.Empty() {
		return nil
	}
	packID, pack := p.pb.Finish()
	p.pb = syncengine.NewPackBuilder()
	return p.cl.PutPack(packID, pack)
}
