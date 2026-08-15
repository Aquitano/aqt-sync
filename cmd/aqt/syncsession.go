// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// syncFormat is the on-server folder format an adapter is prepared to reconcile.
// The format guard is parameterized by it rather than shared verbatim: a pack folder
// is created with Packed set and no Tree flag, so applying the chunked path's legacy
// !Tree check to one would reject every pack folder.
type syncFormat int

const (
	formatChunked syncFormat = iota
	formatPacked
)

// syncSession is the prologue both sync adapters run once, before any planning: the
// local state and base, an authenticated client, and the unlocked master key. Every
// step is a safety guard (a missing base resurrects deletions; the wrong account
// reconciles a stranger's tree), so it is defined here once instead of per adapter —
// a fix applied to one copy did not reach the other.
type syncSession struct {
	root       string
	st         folderState
	base       syncengine.Manifest
	baseExists bool
	cl         *client.Client
	mk         crypto.MasterKey
}

// openSyncSession loads the folder's state and last-synced base and acquires the
// credentials a sync needs. The caller owns the returned session's key material and
// must defer Wipe. An absent base is refused unless --reconcile: reconciling against
// an empty base silently resurrects deleted files.
func openSyncSession(root string, opts syncOptions) (syncSession, error) {
	st, err := loadState(root)
	if err != nil {
		return syncSession{}, err
	}
	base, baseExists, err := loadBaseForSync(root)
	if err != nil {
		return syncSession{}, err
	}
	if !baseExists && !opts.reconcile {
		return syncSession{}, errSyncNoBase
	}
	cl, prof, err := authedClient()
	if err != nil {
		return syncSession{}, err
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return syncSession{}, err
	}
	return syncSession{root: root, st: st, base: base, baseExists: baseExists, cl: cl, mk: mk}, nil
}

// Wipe zeroes the session's master key. A session copied by value (packCtx does)
// carries its own copy of the key, which this does not reach — wipe each copy.
func (s *syncSession) Wipe() { s.mk.Wipe() }

// remoteSync is one reconcile attempt's view of the remote folder: the resource as
// fetched, its unwrapped content key, decoded metadata, and whether the local base
// may be trusted for this pass. trustBase is false when there is no base at all
// (--reconcile) or when an accepted rollback invalidated it; each adapter acts on
// that in its own way, which is the part that stays per-adapter.
type remoteSync struct {
	res       api.GetResourceResponse
	ck        crypto.ContentKey
	meta      api.Metadata
	trustBase bool
}

// openRemote fetches the folder resource and runs the per-attempt guards shared by
// both adapters: rollback classification, key unwrap, metadata decode, and the
// format check for the caller's mode. The caller owns the returned content key and
// must defer Wipe; every error path here wipes it first.
//
// Rollback is classified before the metadata is decoded, so a server whose version
// regressed reports that rather than a cross-mode format mismatch: a rollback is a
// data-integrity signal about the server and must not be masked by a local
// .aqtconfig typo.
func (s *syncSession) openRemote(opts syncOptions, format syncFormat) (remoteSync, error) {
	res, err := s.cl.GetResource(s.st.ID)
	if errors.Is(err, client.ErrNotFound) {
		// Naming the recovery matters: this folder can never sync again, and nothing
		// else in the CLI reaches the state that fixes it (`aqt init` refuses a
		// directory that already has .aqt).
		return remoteSync{}, fmt.Errorf("folder resource %s not found on the server "+
			"(deleted here with `aqt rm`, from another device, or by an operator); "+
			"restore it from a snapshot with `aqt restore`, or stop tracking this folder "+
			"with `aqt untrack` — your local files are left alone either way", s.st.ID)
	}
	if err != nil {
		return remoteSync{}, err
	}
	// Freshness guard: a version below the recorded pin means the server rolled back.
	// Accepting it discards the base for this pass — the old remote state must not be
	// reconciled against a base that post-dates it, or one-sided regressions read as
	// remote edits/deletes and clobber local files. A baseless reconcile turns them
	// into conflicts to review instead.
	trustBase := s.baseExists
	if s.st.RemoteVersion > 0 && res.Version < s.st.RemoteVersion {
		if !opts.acceptRollback {
			return remoteSync{}, rollbackErr(res.Version, s.st.RemoteVersion)
		}
		fmt.Fprintf(os.Stderr, "accepting server rollback (version %d, previously %d); reconciling from scratch\n",
			res.Version, s.st.RemoteVersion)
		trustBase = false
	}
	if res.WrappedKey == nil {
		return remoteSync{}, errors.New("folder resource has no owner key; cannot sync")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(s.mk))
	if err != nil {
		return remoteSync{}, fmt.Errorf("unwrap folder key: %w", err)
	}
	meta, err := decodeMeta(res.EncryptedMeta, ck, s.st.ID)
	if err != nil {
		ck.Wipe()
		return remoteSync{}, err
	}
	if err := checkSyncFormat(meta, format); err != nil {
		ck.Wipe()
		return remoteSync{}, err
	}
	return remoteSync{res: res, ck: ck, meta: meta, trustBase: trustBase}, nil
}

// checkSyncFormat routes by the server's truth, not just local .aqtconfig: a
// pack-and-seal folder reconciled as chunked would read an empty manifest and delete
// the whole tree, and a chunked folder reconciled as a pack has no root to untar.
// (AAD domain separation also makes those reads fail, but this gives the actionable
// message.) Only the chunked side carries the legacy !Tree check — pack folders never
// set Tree.
func checkSyncFormat(meta api.Metadata, format syncFormat) error {
	if format == formatPacked {
		if !meta.Packed {
			return errors.New(".aqtconfig sets pack=true but this folder was created chunked; " +
				"remove pack=true, or re-init a fresh folder to use pack-and-seal")
		}
		return nil
	}
	if meta.Packed {
		return errors.New("this folder is pack-and-seal on the server but is being synced as chunked; " +
			"set pack=true in .aqtconfig, or re-clone it")
	}
	if !meta.Tree {
		return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
	}
	return nil
}
