// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// splitRefPath splits a folder ref into its base ref and the path inside the
// folder. Two forms carry a subpath: aqt://<id>/<sub/path>, and a share URL with
// segments after its /x/<id> route (.../x/<id>/<sub/path>#<frag>). A subpath
// naively appended to a whole share link lands inside the fragment
// (...#k.<key>/<sub/path>), so a slash-bearing fragment is peeled the same way.
func splitRefPath(ref string) (baseRef, subpath string) {
	frag := ""
	if i := strings.Index(ref, "#"); i >= 0 {
		frag, ref = ref[i:], ref[:i]
	}
	fragPath := ""
	if i := strings.IndexByte(frag, '/'); i >= 0 {
		frag, fragPath = frag[:i], strings.Trim(frag[i+1:], "/")
	}
	if rest, ok := strings.CutPrefix(ref, "aqt://"); ok {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			return "aqt://" + rest[:i] + frag, joinSubpath(strings.Trim(rest[i+1:], "/"), fragPath)
		}
		return ref + frag, fragPath
	}
	// The route is the FIRST /x/ segment. A later one belongs to the subpath — a
	// directory named x is ordinary (src/x/util.go) — and splitting there would take
	// the last path segment for the resource id.
	if i := strings.Index(ref, "/x/"); i >= 0 {
		tail := ref[i+len("/x/"):]
		if j := strings.IndexByte(tail, '/'); j >= 0 {
			return ref[:i+len("/x/")] + tail[:j] + frag, joinSubpath(strings.Trim(tail[j+1:], "/"), fragPath)
		}
	}
	return ref + frag, fragPath
}

// joinSubpath combines the URL-path and fragment-appended subpath forms; a ref
// pathologically using both still yields one well-formed relative path.
func joinSubpath(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "/" + b
}

// openFolderRoot opens the sealed tree root of a folder read under a key that is not
// the owner's — a share link's or a grant's — where the metadata is sealed under that
// same key.
func openFolderRoot(res api.GetResourceResponse, ck crypto.ContentKey) (syncengine.TreeRoot, error) {
	meta, err := decodeMeta(res.EncryptedMeta, ck, res.ID)
	if err != nil {
		return syncengine.TreeRoot{}, err
	}
	return openTreeRoot(res, ck, meta)
}

// pullSubpath fetches one entry (or one subtree) out of a chunked folder without
// downloading anything else: only the directory nodes on the path's spine, then
// just that entry's content chunks. A non-nil slices selects the exact-slice
// transport (share link or grant) for both, instead of the owner's pack path.
func pullSubpath(cl *client.Client, id string, res api.GetResourceResponse, ck crypto.ContentKey, subpath, out string, toStdout, force bool, slices sliceFetch) error {
	root, err := openFolderRoot(res, ck)
	if errors.Is(err, errNotAFolder) {
		return fmt.Errorf("resource %s is not a folder; drop the /%s suffix", id, subpath)
	}
	if err != nil {
		return err
	}
	fetch := newBatchNodeFetcher(cl, nil)
	if slices != nil {
		fetch = newPublicBatchFetcher(slices)
	}
	child, err := syncengine.ResolveTreePath(root, subpath, fetch)
	if errors.Is(err, syncengine.ErrPathNotFound) {
		return fmt.Errorf("%w %s", err, id)
	}
	if err != nil {
		return err
	}

	switch child.Type {
	case syncengine.ChildDir:
		if toStdout {
			return fmt.Errorf("%s is a directory: `aqt ls aqt://%s/%s` lists it, `aqt pull` materializes it", subpath, id, subpath)
		}
		return pullSubtree(cl, id, root.Version, child, fetch, subpath, out, slices)
	case syncengine.ChildSymlink:
		if toStdout {
			return fmt.Errorf("%s is a symlink to %s; use `aqt pull` to recreate the link", subpath, child.Link)
		}
		dest := out
		if dest == "" {
			dest = safeOutputName(child.Name)
		}
		if !force {
			if _, err := os.Lstat(dest); err == nil {
				return fmt.Errorf("%s already exists (use --force to overwrite)", dest)
			}
		}
		if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Symlink(child.Link, dest); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote symlink %s -> %s\n", dest, child.Link)
		return nil
	}

	fetchOne := func(oid string) ([]byte, error) {
		got, err := fetch([]string{oid})
		if err != nil {
			return nil, err
		}
		b, ok := got[oid]
		if !ok {
			return nil, fmt.Errorf("fetch chunk-list object %s: not returned", oid)
		}
		return b, nil
	}
	e, err := syncengine.EntryFromChild(child.Name, child, fetchOne)
	if err != nil {
		return err
	}
	var get func(string) ([]byte, error)
	if slices != nil {
		get = newPublicEntrySource(slices, []syncengine.Entry{e}, packio.NewCache(packio.DefaultCacheBytes))
	} else {
		src, err := packio.NewSource(cl, distinctChunkIDs([]syncengine.Entry{e}))
		if err != nil {
			return err
		}
		get = src.Get
	}
	if toStdout {
		return syncengine.WriteEntry(os.Stdout, e, get)
	}
	dest := out
	if dest == "" {
		dest = safeOutputName(child.Name)
	}
	if !force {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", dest)
		}
	}
	perm := os.FileMode(child.Mode).Perm()
	if perm == 0 {
		perm = 0o600
	}
	if err := fsatomic.WriteStream(dest, perm, func(f *os.File) error {
		return syncengine.WriteEntry(f, e, get)
	}); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"path": dest, "bytes": e.Size})
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", dest, e.Size)
	return nil
}

// pullSubtree materializes one directory subtree into a fresh destination: the
// subtree's own node is a complete content-addressed root, so the rest of the
// folder is never fetched.
func pullSubtree(cl *client.Client, id string, version int, child syncengine.TreeChild, fetch func(ids []string) (map[string][]byte, error), subpath, out string, slices sliceFetch) error {
	sub := syncengine.TreeRoot{Version: version, Root: *child.Node}
	m, err := syncengine.OpenTreeBatched(sub, fetch)
	if err != nil {
		return err
	}
	dest := out
	if dest == "" {
		dest = safeOutputName(path.Base(subpath))
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	var get func(string) ([]byte, error)
	if slices == nil {
		src, err := packio.NewSource(cl, distinctChunkIDs(m.Entries))
		if err != nil {
			return err
		}
		get = src.Get
	}
	if err := materializeStaged(abs, func(staging string) error {
		prog := newProgressBar("downloading", entriesBytes(m.Entries))
		// A subpath pull writes into a plain directory, not a tracked folder, so there
		// is no base manifest for its mtimes to feed.
		var dlErr error
		if slices != nil {
			// Batched: the object index stays O(batch), not O(subtree).
			_, dlErr = runPublicDownloads(slices, staging, m.Entries, prog)
		} else {
			_, dlErr = runDownloadsFrom(get, staging, m.Entries, prog)
		}
		prog.finish(dlErr == nil)
		if dlErr != nil {
			return dlErr
		}
		return syncengine.MaterializeDirs(staging, m.Dirs)
	}); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"path": abs, "files": len(m.Entries)})
	}
	fmt.Fprintf(os.Stderr, "pulled %d files into %s\n", len(m.Entries), abs)
	return nil
}

// folderLsRow is one entry of `aqt ls <folder>[/<path>]`.
type folderLsRow struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// collectFolderRows lists the entries at a path inside a folder by walking only
// that path's spine plus the one listed node — never the whole tree. A path that
// names a file or symlink yields that single entry.
func collectFolderRows(cl *client.Client, mk crypto.MasterKey, ref string) ([]folderLsRow, error) {
	baseRef, sub := splitRefPath(ref)
	// The listing this reads back is keyed by name, so the argument accepts one too
	// (plus an id, a tracked path, or an aqt:// ref); the caller's master key is
	// already unlocked, so the lookup costs one listing and no prompt.
	id, err := resolveOwnedResourceID(cl, mk, baseRef)
	if err != nil {
		return nil, err
	}
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return nil, fmt.Errorf("folder %s not found: pass a unique name, an id, or an aqt:// ref "+
			"(it may also be a folder you do not own)", id)
	}
	if err != nil {
		return nil, err
	}
	folder, err := openOwnedFolder(res, mk)
	if errors.Is(err, errNotAFolder) {
		return nil, fmt.Errorf("resource %s is not a folder; `aqt ls` with no arguments lists resources", id)
	}
	if err != nil {
		return nil, err
	}
	defer folder.ck.Wipe()
	fetch := newBatchNodeFetcher(cl, nil)
	child, err := syncengine.ResolveTreePath(folder.root, sub, fetch)
	if errors.Is(err, syncengine.ErrPathNotFound) {
		return nil, fmt.Errorf("%w %s", err, id)
	}
	if err != nil {
		return nil, err
	}
	if child.Type != syncengine.ChildDir {
		return []folderLsRow{{Name: child.Name, Type: string(child.Type), Size: child.Size}}, nil
	}
	children, err := syncengine.TreeChildren(*child.Node, fetch)
	if err != nil {
		return nil, err
	}
	rows := make([]folderLsRow, 0, len(children))
	for _, c := range children {
		rows = append(rows, folderLsRow{Name: c.Name, Type: string(c.Type), Size: c.Size})
	}
	return rows, nil
}

func runLsFolder(cl *client.Client, mk crypto.MasterKey, ref string) error {
	rows, err := collectFolderRows(cl, mk, ref)
	if err != nil {
		return err
	}
	if flagJSON {
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "empty directory")
		return nil
	}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		name, size := r.Name, cliutil.HumanBytes(r.Size)
		if r.Type == string(syncengine.ChildDir) {
			name, size = name+"/", "-"
		}
		cells = append(cells, []string{name, r.Type, size})
	}
	return printTable(os.Stdout, []string{"NAME", "TYPE", "SIZE"}, cells)
}
