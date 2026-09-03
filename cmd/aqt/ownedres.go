// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// The shapes an owner-side open can refuse. They are sentinels because several
// callers route on them instead of reporting them: a resource read through a share
// link or a grant carries no owner key, and `aqt snapshot diff` falls back to
// materializing whatever is not a chunked tree folder.
var (
	errNoOwnerKey   = errors.New("not a private resource you own (no owner key)")
	errNotAFolder   = errors.New("not a folder")
	errLegacyFolder = errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
)

// ownedResource is a resource opened under its owner-wrapped content key: the key,
// and the metadata that key seals. The caller wipes ck.
type ownedResource struct {
	ck   crypto.ContentKey
	meta api.Metadata
}

// ownedFolder is an ownedResource that is a chunked tree folder, with its sealed
// root opened. The caller wipes ck.
type ownedFolder struct {
	ownedResource
	root syncengine.TreeRoot
}

// openOwnedResource unwraps res's owner-wrapped content key with the master key and
// decodes the metadata that key seals. Decoding doubles as a check that the unwrapped
// key is the right one, before a caller acts on it. The key is wiped if any step
// fails, so a caller only ever receives a key it owns.
func openOwnedResource(res api.GetResourceResponse, mk crypto.MasterKey) (ownedResource, error) {
	if res.WrappedKey == nil {
		return ownedResource{}, errNoOwnerKey
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return ownedResource{}, fmt.Errorf("unwrap key: %w", err)
	}
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		ck.Wipe()
		return ownedResource{}, err
	}
	return ownedResource{ck: ck, meta: meta}, nil
}

// openOwnedFolder is openOwnedResource narrowed to a chunked tree folder, with the
// sealed root opened.
func openOwnedFolder(res api.GetResourceResponse, mk crypto.MasterKey) (ownedFolder, error) {
	owned, err := openOwnedResource(res, mk)
	if err != nil {
		return ownedFolder{}, err
	}
	root, err := openTreeRoot(res, owned.ck, owned.meta)
	if err != nil {
		owned.ck.Wipe()
		return ownedFolder{}, err
	}
	return ownedFolder{ownedResource: owned, root: root}, nil
}

// openTreeRoot opens res's sealed tree root under ck, which may be an owner key or a
// key carried by a share link or a grant.
func openTreeRoot(res api.GetResourceResponse, ck crypto.ContentKey, meta api.Metadata) (syncengine.TreeRoot, error) {
	if err := requireTreeFolder(meta); err != nil {
		return syncengine.TreeRoot{}, err
	}
	root, err := syncengine.OpenTreeRoot(res.Blob, ck, res.ID)
	if err != nil {
		return syncengine.TreeRoot{}, fmt.Errorf("decrypt folder root: %w", err)
	}
	return root, nil
}

// requireTreeFolder rejects everything that is not a chunked tree folder. A pre-tree
// folder has no per-entry objects, so subpath reads, member listings and remote
// manifests are structurally impossible for it.
func requireTreeFolder(meta api.Metadata) error {
	if meta.Kind != api.KindFolder {
		return errNotAFolder
	}
	if !meta.Tree {
		return errLegacyFolder
	}
	return nil
}
