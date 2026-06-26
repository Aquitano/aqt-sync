package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	// A metadata+hash scan is all the local side needs to tell whether the tree
	// changed since the last sync; pack-and-seal never chunks per file.
	local, err := syncengine.Scan(root)
	if err != nil {
		return err
	}

	c := packCtx{root: root, cl: cl, opts: opts, st: st, base: base, baseExists: baseExists, local: local, mk: mk, push: &packPushArtifacts{}}
	return reconcileWithRetry(func() error { return reconcilePack(c) })
}

type packCtx struct {
	root       string
	cl         *client.Client
	opts       syncOptions
	st         folderState
	base       syncengine.Manifest
	baseExists bool
	local      syncengine.Manifest
	mk         crypto.MasterKey
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
	res, err := c.cl.GetResource(c.st.ID)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("folder resource %s not found on the server", c.st.ID)
	}
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("folder resource has no owner key; cannot sync")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(c.mk))
	if err != nil {
		return fmt.Errorf("unwrap folder key: %w", err)
	}
	meta, err := decodeMeta(res.EncryptedMeta, ck)
	if err != nil {
		return err
	}
	if !meta.Packed {
		return errors.New(".aqtconfig sets pack=true but this folder was created chunked; " +
			"remove pack=true, or re-init a fresh folder to use pack-and-seal")
	}

	if !c.baseExists {
		return reconcilePackNoBase(c, res, ck)
	}

	localChanged := len(syncengine.Plan(c.local, c.base, c.base)) > 0
	remoteChanged := res.Version != c.base.Version
	action := decidePack(localChanged, remoteChanged, c.opts)

	if c.opts.dryRun {
		printPackAction(action)
		return nil
	}
	switch action {
	case packPush:
		return pushPack(c, res, ck)
	case packPull:
		return pullPack(c, res, ck)
	case packConflict:
		fmt.Fprintln(os.Stderr, "conflict: the folder changed on both sides since the last sync")
		return errConflictsRemain
	default:
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
// action would silently discard it, so it is a conflict unless --force makes the
// discard explicit — the same protection the chunked path applies to every sync.
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
func reconcilePackNoBase(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey) error {
	root, err := syncengine.OpenPackRoot(res.Blob, ck)
	if err != nil {
		return fmt.Errorf("decrypt remote pack root: %w", err)
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
		return savePackBase(c.root, c.local, res.Version)
	}
}

// pushPack tars the whole tree, seals it into fresh segments, uploads them, and commits
// the new root (version-checked, so a concurrent push is retried not lost). The
// tar+seal+upload runs once and is cached: a conflict retry re-PUTs the same root at
// the new version rather than re-shipping the tree, since the segments are already on
// the server.
func pushPack(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey) error {
	if !c.push.built {
		packer := newSegmentPacker(c.cl)
		root, shipped, err := syncengine.TarAndSeal(c.root, ck, packer)
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
	fmt.Printf("synced: pushed %d files (pack-and-seal)\n", len(c.push.shipped.Entries))
	return nil
}

// extractPack range-fetches a pack-and-seal tree's segments and untars it under dir,
// returning the manifest of what it wrote. Shared by clone, pull, and reconcile so the
// fetch+extract wiring lives in one place.
func extractPack(cl *client.Client, dir string, root syncengine.PackRoot, ck crypto.ContentKey) (syncengine.Manifest, error) {
	src, err := newPackSource(cl, root.SegmentIDs())
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return syncengine.ExtractToTree(dir, root, ck, src.get)
}

// pullPack replaces the working tree with the remote one. It opens the root; callers
// that already decrypted it use pullPackFromRoot to avoid a second decrypt.
func pullPack(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey) error {
	root, err := syncengine.OpenPackRoot(res.Blob, ck)
	if err != nil {
		return fmt.Errorf("decrypt remote pack root: %w", err)
	}
	return pullPackFromRoot(c, res, ck, root)
}

// pullPackFromRoot untars the remote tree over the working tree, then removes local
// files the new tree no longer contains.
func pullPackFromRoot(c packCtx, res api.GetResourceResponse, ck crypto.ContentKey, root syncengine.PackRoot) error {
	remote, err := extractPack(c.cl, c.root, root, ck)
	if err != nil {
		// A located-but-missing segment means a concurrent push superseded this
		// version and GC reaped it; re-reconcile against the current version.
		if errors.Is(err, client.ErrNotFound) {
			return client.ErrConflict
		}
		return err
	}
	// Prune whatever the remote no longer carries, listing the tree as it is now: a
	// prior pull that aborted mid-stream can have left files in neither c.local nor the
	// new remote, and those must go too so the tree ends equal to the remote. Only the
	// paths are needed, so this is a hash-free walk.
	postPull, err := syncengine.ListPaths(c.root)
	if err != nil {
		return err
	}
	remoteByPath := remote.ByPath()
	for _, p := range postPull {
		if _, ok := remoteByPath[p]; !ok {
			if err := syncengine.RemoveFile(c.root, p); err != nil {
				return err
			}
		}
	}
	if err := savePackBase(c.root, remote, res.Version); err != nil {
		return err
	}
	fmt.Printf("synced: pulled %d files (pack-and-seal)\n", len(remote.Entries))
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
	return len(syncengine.Plan(c.local, remote, remote)) == 0, nil
}

func savePackBase(root string, m syncengine.Manifest, version int) error {
	m.Version = version
	return saveBase(root, m)
}

func putPackFolderCreate(cl *client.Client, root syncengine.PackRoot, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	blob, err := syncengine.SealPackRoot(root, ck)
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
	})
}

// putPackFolderUpdate commits a new root over an existing pack folder. The sealed
// metadata (the folder name and packed flag) is carried forward unchanged.
func putPackFolderUpdate(cl *client.Client, id string, root syncengine.PackRoot, ck crypto.ContentKey, mk crypto.MasterKey, meta crypto.SealedBlob, expectedVersion int) (api.PutResourceResponse, error) {
	blob, err := syncengine.SealPackRoot(root, ck)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return cl.PutResource(api.PutResourceRequest{
		ID: id, Visibility: api.Private, Blob: blob, EncryptedMeta: meta,
		WrappedKey: &wrapped, ChunkRefs: root.SegmentIDs(), ExpectedVersion: expectedVersion,
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
