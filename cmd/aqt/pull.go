// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func pullCmd() *cobra.Command {
	var (
		out   string
		pw    passwordFlags
		force bool
	)
	cmd := &cobra.Command{
		Use:   "pull <name-or-id|tracked-path|url>[/path]",
		Short: "Fetch and decrypt a resource, or a single entry inside a folder",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runPull(args[0], out, password, false, force)
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write to this path")
	pw.bind(cmd, "password for a gated link")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the destination if it exists")
	markJSONSupported(cmd)
	// Only a subtree pull (aqt://<id>/<dir>) transfers enough entries to draw a bar,
	// but that is this command's own path, so --progress belongs here.
	markProgressSupported(cmd)
	return cmd
}

func catCmd() *cobra.Command {
	var pw passwordFlags
	cmd := &cobra.Command{
		Use:   "cat <name-or-id|tracked-path|url>[/path]",
		Short: "Decrypt a resource (or one file inside a folder) to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runPull(args[0], "", password, true, false)
		},
	}
	pw.bind(cmd, "password for a gated link")
	return cmd
}

func runPull(ref, out, password string, toStdout, force bool) error {
	baseRef, subpath := splitRefPath(ref)
	id, fragment, origin := parseRef(baseRef)

	// A public link decrypts from its fragment and needs no profile; a private
	// ref needs the account token (to fetch) and passphrase (to unwrap). Honor a
	// host embedded in the ref so a share link is self-contained, but never attach
	// the token to a foreign host (see newLinkClient).
	prof := loadProfileOptional()
	cl, err := newLinkClient(origin, prof)
	if err != nil {
		return err
	}
	// An owned ref may be a name or a tracked path, which only the account can
	// resolve; a link (fragment or foreign host) is opaque and stays untouched.
	// Unlock the master key at most once per invocation: resolving by name and
	// unwrapping the owner key below both need it, and a second unlockMaster would
	// prompt for the passphrase again whenever session caching is unavailable.
	var master *crypto.MasterKey
	if origin == "" && fragment == "" && prof != nil {
		mk, err := unlockMaster(prof)
		if err != nil {
			return err
		}
		defer mk.Wipe()
		master = &mk
		if id, err = resolveOwnedResourceID(cl, mk, baseRef); err != nil {
			return err
		}
	}

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found: pass a unique name, an id, or an aqt:// ref "+
			"(it may also be private and not yours)", id)
	}
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("this link has expired or reached its read limit: %w", err)
	}
	if err != nil {
		return err
	}

	ck, err := contentKeyWithMaster(res, fragment, password, prof, master)
	if err != nil {
		return err
	}
	defer ck.Wipe()

	// An aqt://<id>/<path> ref (or a share URL with segments after /x/<id>)
	// addresses one entry inside a folder: only the path's spine nodes and that
	// entry's chunks are fetched, never the tree.
	if subpath != "" {
		return pullSubpath(cl, id, res, ck, subpath, out, toStdout, force, remoteFetch(cl, res, fragment))
	}

	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Kind == api.KindFolder {
		// The name is the link author's plaintext, not ours: sanitize before it reaches
		// the terminal, or an escape sequence in it forges the rest of this line.
		name := foreignText(meta.Name)
		if fragment != "" {
			return fmt.Errorf("%s is a folder: `aqt clone '<link>'` materializes it, and '<link>/<path>' pulls a single entry", name)
		}
		return fmt.Errorf("%s is a folder: `aqt clone aqt://%s` materializes it, `aqt ls aqt://%s` lists it, "+
			"and aqt://%s/<path> pulls a single entry", name, id, id, id)
	}
	if meta.Streamed {
		// A share link has no account token for the authed pack-locate path, and a
		// grantee has a token but no pack access; both read exact object slices.
		return pullStream(cl, res, ck, out, meta, remoteFetch(cl, res, fragment), toStdout, force)
	}

	plaintext, err := crypto.OpenBound(res.Blob, ck, crypto.AADBlob, id)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	return writeOutput(plaintext, out, meta, toStdout, force)
}

// pullStream reconstructs a streamed file from its objects, writing chunks to the
// destination as they are fetched so the whole file is never held in memory.
func pullStream(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, out string, meta api.Metadata, slices sliceFetch, toStdout, force bool) error {
	root, err := syncengine.OpenFileRoot(res.Blob, ck, res.ID)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	// A large file stores its chunk list indirectly as sealed segments; locate and
	// open those first (they sit behind their own locate) to recover the content
	// chunk records, then locate the content objects themselves. A link holder reads
	// both through the unauthenticated public object endpoint; the owner uses the
	// authed pack-locate path.
	get := func(chunks []crypto.Chunk) (func(id string) ([]byte, error), error) {
		if slices != nil {
			return newPublicChunkSource(slices, chunks, newPackCache(packCacheBytes)).get, nil
		}
		src, err := newPackSource(cl, distinctChunkIDs([]syncengine.Entry{{Chunks: chunks}}))
		if err != nil {
			return nil, err
		}
		return src.get, nil
	}
	chunks := root.Chunks
	if root.Indirect() {
		segFetch, err := get(root.ChunkList)
		if err != nil {
			return err
		}
		chunks, err = root.Resolve(segFetch)
		if err != nil {
			return err
		}
	}
	fetch, err := get(chunks)
	if err != nil {
		return err
	}
	if toStdout {
		return syncengine.WriteFileRoot(os.Stdout, chunks, fetch)
	}
	dest := out
	if dest == "" {
		dest = safeOutputName(meta.Name)
	}
	if !force {
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", dest)
		}
	}
	if err := writeStreamAtomic(dest, 0o600, func(f *os.File) error {
		return syncengine.WriteFileRoot(f, chunks, fetch)
	}); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"path": dest, "bytes": root.Size})
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", dest, root.Size)
	return nil
}

// contentKey recovers the content key either from the share fragment (public/
// gated) or by unwrapping with the master key (private).
func contentKey(res api.GetResourceResponse, fragment, password string, prof *identity.Profile) (crypto.ContentKey, error) {
	return contentKeyWithMaster(res, fragment, password, prof, nil)
}

// contentKeyWithMaster is contentKey given an already-unlocked master key to reuse.
// A caller that has unlocked once (e.g. info resolving an owned ref by name) passes it
// so unwrapping the owner or grant key does not prompt for the passphrase a second time
// when session caching is unavailable. A nil master is unlocked on demand.
func contentKeyWithMaster(res api.GetResourceResponse, fragment, password string, prof *identity.Profile, master *crypto.MasterKey) (crypto.ContentKey, error) {
	if fragment != "" {
		if strings.HasPrefix(fragment, "p.") && password == "" {
			p, err := promptPassphrase("Share password: ")
			if err != nil {
				return crypto.ContentKey{}, err
			}
			password = p
		}
		return crypto.DecodeFragment(fragment, password)
	}
	// A grant read carries the content key HPKE-wrapped to this account instead of
	// the owner's wrap; the info binding pins it to (resource, owner, this handle),
	// so a hostile server cannot splice another grant's wrap onto this resource.
	if res.WrappedKey == nil && res.GrantKey != nil {
		if prof == nil {
			return crypto.ContentKey{}, errors.New("granted resource: run `aqt login` to decrypt it")
		}
		mk, owned, err := borrowMaster(prof, master)
		if err != nil {
			return crypto.ContentKey{}, err
		}
		if owned {
			defer mk.Wipe()
		}
		return crypto.UnwrapGrant(res.GrantKey, mk, res.ID, res.Owner, prof.OwnerHandle)
	}
	if res.WrappedKey == nil {
		return crypto.ContentKey{}, errors.New("no decryption key: this looks like a public resource but the link had no #key")
	}
	if prof == nil {
		return crypto.ContentKey{}, errors.New("private resource: run `aqt login` to decrypt it")
	}
	mk, owned, err := borrowMaster(prof, master)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	if owned {
		defer mk.Wipe()
	}
	return crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
}

// borrowMaster returns the caller's already-unlocked master key when non-nil (owned is
// false; the caller wipes it), otherwise unlocks a fresh key the caller must wipe.
func borrowMaster(prof *identity.Profile, shared *crypto.MasterKey) (mk crypto.MasterKey, owned bool, err error) {
	if shared != nil {
		return *shared, false, nil
	}
	mk, err = unlockMaster(prof)
	if err != nil {
		return crypto.MasterKey{}, false, err
	}
	return mk, true, nil
}

// safeOutputName reduces an attacker-controlled metadata name to a bare basename
// inside the current directory, so a malicious link cannot steer a default
// destination to "../" or an absolute path and write outside CWD. The name is
// also the link author's plaintext and gets echoed in "wrote %s" and "%s already
// exists": sanitize it (see foreignText) so no control byte reaches the terminal
// or lands in the on-disk filename.
func safeOutputName(name string) string {
	base := filepath.Base(foreignText(name))
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) || base == "stdin" {
		return "aqt-download"
	}
	return base
}

func writeOutput(plaintext []byte, out string, meta api.Metadata, toStdout, force bool) error {
	if toStdout {
		_, err := os.Stdout.Write(plaintext)
		return err
	}
	if out == "" {
		out = safeOutputName(meta.Name)
	}
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", out)
		}
	}
	if err := writeFileAtomic(out, plaintext, 0o600); err != nil {
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"path": out, "bytes": len(plaintext)})
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", out, len(plaintext))
	return nil
}

// writeStreamAtomic writes to a sibling temp file via fn, fsyncs it, then renames
// it over dest, so a failure or crash mid-write leaves any existing dest untouched
// rather than truncating it. fn gets the open temp file and may stream into it
// without holding the whole payload in memory (pullStream); writeFileAtomic wraps
// this for the in-memory case.
func writeStreamAtomic(dest string, perm os.FileMode, fn func(*os.File) error) error {
	f, err := os.CreateTemp(filepath.Dir(dest), ".aqt-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once renamed; cleans up every failure path
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := fn(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// parseRef extracts the resource id, optional fragment, and origin (scheme://host)
// from any ref form: a full http(s) URL (.../x/<id>#<frag>), an aqt://<id> ref, or
// a bare id. origin is set only for an absolute http/https URL so a share link's
// own host can be honored; aqt:// refs and bare ids yield an empty origin.
func parseRef(ref string) (id, fragment, origin string) {
	if i := strings.Index(ref, "#"); i >= 0 {
		fragment = ref[i+1:]
		ref = ref[:i]
	}
	// Only an absolute http(s) URL carries a usable host; guarding on the scheme
	// keeps aqt://<id> (which parses to scheme=aqt, host=<id>) and bare ids from
	// yielding a spurious origin.
	if u, err := url.Parse(ref); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	ref = strings.TrimPrefix(ref, "aqt://")
	if i := strings.LastIndex(ref, "/x/"); i >= 0 {
		ref = ref[i+len("/x/"):]
	} else if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref, fragment, origin
}

// decodeMeta decrypts and parses a resource's sealed metadata. A decrypt or parse
// failure is returned rather than swallowed: in an owner flow the content key is
// correct, so a failure means corruption (or a blob/meta mix-up), and treating it as
// a default (unpacked, unstreamed) resource silently misroutes the resource — e.g.
// cloning a pack-and-seal folder through the chunked path and writing nothing.
func decodeMeta(blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string) (api.Metadata, error) {
	plain, err := crypto.OpenBound(blob, ck, crypto.AADMeta, resourceID)
	if err != nil {
		return api.Metadata{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	var m api.Metadata
	if err := json.Unmarshal(plain, &m); err != nil {
		return api.Metadata{}, fmt.Errorf("parse metadata: %w", err)
	}
	return m, nil
}
