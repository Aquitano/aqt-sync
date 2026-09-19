// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// uploadTreeObjects seals a folder's Merkle DAG, uploading the node objects the
// server lacks (via the same pack pipeline as file content), and returns the tree
// root plus the resource's full GC roots: every directory-node id unioned with every
// file-chunk id reachable from the root. The objects must be on the server before
// the resource PUT roots them, hence the flush.
func (app *application) uploadTreeObjects(cl *client.Client, conv crypto.ConvergenceKey, m syncengine.Manifest) (syncengine.TreeRoot, []string, error) {
	up := app.newUploader(cl, nil)
	defer func() { _ = up.Wait() }()
	root, refs, err := syncengine.SealTree(m, conv, up, openSealMemo())
	if err != nil {
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
// packio.Source), so a tree walk pays one locate per level instead of two round-trips per
// node. One packio.Source (and its LRU) is shared across every level of the walk, so a
// pack carrying nodes from several levels is fetched once, not once per level. seed
// carries node ciphertexts already in hand (the base tree in the reuse path), served
// from memory without a fetch; fetched nodes are cached across levels since the DAG
// may revisit a shared subtree id, and persist in the on-disk node cache, so a later
// command (find, diff, clone, a cold reconcile) re-fetches only nodes it has never
// seen — content addressing makes a disk hit exactly as trustworthy as a server fetch,
// since OpenNode verifies either against the id. A node the owner no longer stores —
// a concurrent sync superseded this version and GC reaped it — surfaces from
// packio.Source.Get as client.ErrNotFound so a manifest read can retry against the
// current version.
func newBatchNodeFetcher(cl *client.Client, seed map[string][]byte) func([]string) (map[string][]byte, error) {
	src := packio.NewEmptySource(cl)
	return cachedMetadataFetcher(seed, func(ids []string) (map[string][]byte, error) {
		if err := src.Locate(ids); err != nil {
			return nil, err
		}
		out := make(map[string][]byte, len(ids))
		for _, id := range ids {
			ct, err := src.Get(id)
			if err != nil {
				return nil, err
			}
			out[id] = ct
		}
		return out, nil
	})
}

// createFolder registers a new folder resource. The create seals unbound — the id
// does not exist yet — and bindCreated immediately re-seals root and metadata under
// the id the server assigned, which is the form every read expects.
func (app *application) createFolder(cl *client.Client, conv crypto.ConvergenceKey, m syncengine.Manifest, ck crypto.ContentKey, mk crypto.MasterKey, dir string) (api.PutResourceResponse, error) {
	root, _, err := app.uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck, "")
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: filepath.Base(dir), Kind: api.KindFolder, Tree: true})
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaBlob, err := crypto.SealBound(metaJSON, ck, crypto.AADMeta, "")
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	req := api.PutResourceRequest{
		Visibility: api.Private, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped,
		MinClient:  api.CapabilityIDBinding, // the bind below seals root and meta id-bound (v2)
	}
	resp, err := cl.PutResource(req)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	return bindCreated(cl, req, resp, ck, metaJSON, func(id string) (crypto.SealedBlob, error) {
		return syncengine.SealTreeRoot(root, ck, id)
	})
}

// gcRearmThreshold is how long a push may run before the pre-PUT chunk re-check
// fires. The server keeps an uploaded-but-unrooted pack alive for a fixed grace
// period (one hour); a push that has consumed a substantial fraction of it risks
// GC sweeping its earliest packs before the manifest PUT roots them.
const gcRearmThreshold = 15 * time.Minute

// rearmUploadedChunks re-checks a long push's chunk ids against the server just
// before the manifest PUT. The server-side check bumps the age guard of every pack
// still holding a present id, so packs uploaded early in a multi-hour push cannot
// be swept in the moments before the PUT roots them. Ids already swept mean GC won
// the race outright: fail with the recovery path (a re-run re-uploads exactly the
// missing chunks) instead of letting the PUT bounce off the server's foreign-key
// backstop. Short pushes — the overwhelmingly common case — skip the round trip.
func rearmUploadedChunks(check func([]string) ([]string, error), ids []string, started time.Time) error {
	if started.IsZero() || time.Since(started) < gcRearmThreshold {
		return nil
	}
	missing, err := check(ids)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("%d uploaded chunk(s) were garbage-collected before this push could commit; re-run `aqt sync` to re-upload them", len(missing))
	}
	return nil
}

// putFolderUpdate replaces an existing folder's manifest, conditional on the
// resource still being at expectedVersion (else the server returns a conflict).
// The encrypted metadata (the folder name sealed at init) is carried forward
// unchanged, so a sync never clobbers it; it is checked against the id first, since
// a write must not carry forward metadata this client cannot read.
//
// vis is the resource's current visibility, carried forward for the same reason: a
// sync pushes content, it does not re-share or un-share. Hardcoding private here made
// the first sync after `aqt share` silently kill the link (the server takes visibility
// from every PUT). The link's lifecycle policy is preserved server-side, since this
// request carries none.
// A private update omits ChunkRefs — reachability is the client's job, and the
// refs would otherwise cap folder size at the wire header. A public resource, and
// a private one carrying grants this device did not know about (the server
// refuses the refs-less write), send the full set as its readers' fetch scope.
func (app *application) putFolderUpdate(cl *client.Client, conv crypto.ConvergenceKey, id string, vis api.Visibility, m syncengine.Manifest, meta crypto.SealedBlob, ck crypto.ContentKey, mk crypto.MasterKey, expectedVersion int) (api.PutResourceResponse, error) {
	root, refs, err := app.uploadTreeObjects(cl, conv, m)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, ck, id)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	metaBlob, err := verifiedMetaBound(meta, ck, id)
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return api.PutResourceResponse{}, err
	}
	req := api.PutResourceRequest{
		ID: id, Visibility: vis, Blob: blob, EncryptedMeta: metaBlob,
		WrappedKey: &wrapped, ChunkRefs: refs, ExpectedVersion: expectedVersion,
		MinClient: api.CapabilityIDBinding, // TreeRoot and meta are sealed id-bound (v2)
	}
	if vis == api.Private {
		req.ChunkRefs = nil
		resp, err := cl.PutResource(req)
		if !errors.Is(err, client.ErrSharedNeedsRefs) {
			return resp, err
		}
		req.ChunkRefs = refs
	}
	return cl.PutResource(req)
}
