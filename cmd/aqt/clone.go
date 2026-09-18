// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func (app *application) cloneCmd() *cobra.Command {
	var (
		adopt bool
		pw    passwordFlags
	)
	cmd := &cobra.Command{
		Use:   "clone <name-or-id|tracked-path|share-url> [dir]",
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
			return app.runClone(args[0], dir, adopt, password)
		},
	}
	cmd.Flags().BoolVar(&adopt, "adopt", false,
		"adopt an existing non-empty directory: write tracking, reuse matching local files by hash, and reconcile differences as conflicts")
	pw.bind(cmd, "password for a gated link")
	markJSONSupported(cmd)
	markProgressSupported(cmd)
	return cmd
}

func (app *application) runClone(ref, dir string, adopt bool, password string) error {
	id, fragment, origin := parseRef(ref)
	// A ref carrying a fragment is a share link: the key comes from the link, not
	// the master key, and the read path is the unauthenticated public endpoint.
	if fragment != "" {
		if adopt {
			return errors.New("--adopt binds a directory to a folder you own; a share link is read-only, so there is nothing to sync with")
		}
		return app.runCloneLink(id, fragment, origin, dir, password)
	}
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	// The master key unwraps the folder key below and resolves a name or tracked path
	// to its id here, so it is unlocked once up front: a second unlockMaster would ask
	// for the passphrase again whenever session caching is unavailable. A ref carrying
	// its own host is a link, not a name, and is left as it is.
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	if origin == "" {
		if id, err = resolveOwnedResourceID(cl, mk, ref); err != nil {
			return err
		}
	}
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("folder %s not found: pass a unique name, an id, or an aqt:// ref "+
			"(it may also be a folder you do not own)", id)
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
			ck, err := app.contentKeyWithMaster(res, "", "", prof, &mk)
			if err != nil {
				return err
			}
			defer ck.Wipe()
			return app.cloneReadOnly(grantFetch(cl, id), res, ck, id, dir)
		}
		return errNoOwnerKey
	}
	owned, err := openOwnedResource(res, mk)
	if err != nil {
		return err
	}
	defer owned.ck.Wipe()
	ck, meta := owned.ck, owned.meta

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
	if _, err := openTreeRoot(res, ck, meta); err != nil {
		return err
	}
	if adopt {
		return app.adoptClone(id, abs, prof, res.Version)
	}
	// Content and control state are staged together and committed with one rename,
	// so an interrupted clone leaves no destination at all rather than a partial
	// tree (or a complete tree that is not yet tracked).
	var base syncengine.Manifest
	profileName, account, fingerprint := stateIdentity(prof)
	if err := materializeStaged(abs, func(staging string) error {
		var mErr error
		base, mErr = app.materializeClone(cl, staging, res, ck)
		if mErr != nil {
			return mErr
		}
		if err := os.MkdirAll(filepath.Join(staging, syncengine.ControlDir), 0o700); err != nil {
			return err
		}
		if err := folderstate.SaveState(staging, folderstate.State{
			ID: id, Server: prof.Server,
			Profile: profileName, Account: account, Fingerprint: fingerprint,
			RemoteVersion: res.Version,
		}); err != nil {
			return err
		}
		return folderstate.SaveBase(staging, app.profile, base)
	}); err != nil {
		return err
	}
	if app.json {
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
func (app *application) runCloneLink(id, fragment, origin, dir, password string) error {
	prof := app.loadProfileOptional()
	cl, err := app.newLinkClient(origin, prof)
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
	ck, err := app.contentKey(res, fragment, password, prof)
	if err != nil {
		return err
	}
	defer ck.Wipe()
	return app.cloneReadOnly(publicFetch(cl, id), res, ck, id, dir)
}

// cloneReadOnly materializes a shared folder over an exact-slice transport — the
// common tail of a share-link clone and a grantee clone. The result is a plain
// directory, not a tracked folder: neither caller can write to the resource, so
// there is nothing to sync with.
func (app *application) cloneReadOnly(fetch sliceFetch, res api.GetResourceResponse, ck crypto.ContentKey, id, dir string) error {
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Kind != api.KindFolder {
		return fmt.Errorf("%s is a single file, not a folder; `aqt pull` fetches it", meta.Name)
	}
	if !meta.Tree {
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
		return app.materializeManifest(nil, fetch, staging, &manifest)
	}); err != nil {
		return err
	}
	if app.json {
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
func (app *application) adoptClone(id, abs string, prof *identity.Profile, version int) error {
	if _, err := os.Stat(filepath.Join(abs, syncengine.ControlDir)); err == nil {
		return errors.New("already a tracked folder")
	}
	// .aqtconfig is itself synced content, so an adopted copy may carry one; parse it
	// before any tracking is written, so a broken config fails without side effects.
	if _, err := syncengine.LoadConfig(abs); err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	// Deliberately no SaveBase: an empty base would resurrect deletions; the reconcile
	// below writes base.json once local and remote agree.
	profileName, account, fingerprint := stateIdentity(prof)
	if err := folderstate.SaveState(abs, folderstate.State{
		ID: id, Server: prof.Server,
		Profile: profileName, Account: account, Fingerprint: fingerprint,
		RemoteVersion: version,
	}); err != nil {
		return err
	}
	// stderr under --json: the reconcile below emits the JSON summary on stdout.
	out := os.Stdout
	if app.json {
		out = os.Stderr
	}
	fmt.Fprintf(out, "adopted %s; reconciling with the remote\n", abs)
	if err := guardTrackedGit(abs, syncOptions{reconcile: true}); err != nil {
		return err
	}
	// conflicts is pinned to block: the adopted tree's own .aqtconfig may select
	// copy or merge, which contradict --reconcile — a wedge the user never caused,
	// hit only after tracking metadata was already written.
	return app.runSync(abs, syncOptions{reconcile: true, conflicts: "block"})
}

// materializeClone writes a freshly cloned folder's content under abs and returns
// the manifest to record as its base: it reassembles the Merkle DAG, streams each
// file from its packs, and materializes (empty) directories with their modes.
func (app *application) materializeClone(cl *client.Client, abs string, res api.GetResourceResponse, ck crypto.ContentKey) (syncengine.Manifest, error) {
	manifest, err := openRemoteTree(cl, res.Blob, ck, res.ID)
	if err != nil {
		return syncengine.Manifest{}, fmt.Errorf("decrypt manifest: %w", err)
	}
	err = app.materializeManifest(cl, nil, abs, &manifest)
	return manifest, err
}

// materializeStaged fills dest by letting fn write into a staging directory that
// is renamed to dest only after fn succeeds, so a failed or interrupted
// materialization leaves dest exactly as it was (usually: absent) instead of
// half-populated. dest must not exist, or be an empty directory; staging shares
// dest's parent so the commit rename never crosses filesystems.
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
	defer func() { _ = os.RemoveAll(staging) }()
	if err := fn(staging); err != nil {
		return err
	}
	// MkdirTemp creates 0700; the committed directory takes the mode a plain
	// MkdirAll would have produced here — 0755 filtered through the umask, so
	// `umask 077; aqt clone <id> ~/secrets` still lands 0700 rather than 0755.
	// An existing (empty) destination keeps the mode it already had.
	mode := os.FileMode(0o755) &^ currentUmask()
	if existedEmpty {
		if fi, err := os.Stat(dest); err == nil {
			mode = fi.Mode().Perm()
		}
	}
	if err := os.Chmod(staging, mode); err != nil {
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
