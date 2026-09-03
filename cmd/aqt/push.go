// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// streamThreshold is the size at or above which a push streams through the
// chunk/pack pipeline rather than sealing the whole file in one inline blob. This
// now covers public and gated pushes too — a link holder reads a public streamed
// file's objects through the per-resource public object endpoint. Stdin stays inline
// (it has no size to threshold on).
const streamThreshold = 8 << 20

type pushOptions struct {
	public   bool
	password string
	name     string
	noClip   bool
	policy   linkPolicy
}

func pushCmd() *cobra.Command {
	var (
		opts     pushOptions
		pw       passwordFlags
		expire   string
		maxReads int64
		burn     bool
	)
	cmd := &cobra.Command{
		Use:   "push <path|->",
		Short: "Encrypt and upload a file (private by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// `push -` streams the content itself from stdin, so stdin cannot also
			// carry the password.
			if pw.fromStdin && args[0] == "-" {
				return errors.New("--password-stdin cannot be used with `push -` (stdin carries the content)")
			}
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			opts.password = password
			// A password gate only makes sense on a shareable link.
			if opts.password != "" {
				opts.public = true
			}
			// A push mints the resource and its link together, so the link's expiry is
			// the resource's: reclaiming the ciphertext is the point of --burn.
			policy, err := resolveLinkPolicy(expire, maxReads, burn, api.ExpiryReclaim)
			if err != nil {
				return err
			}
			// Lifecycle is a property of a public link; require an explicit --public/-P
			// rather than silently minting one.
			if policy.requested() && !opts.public {
				return errors.New("--expire/--max-reads/--burn require --public (or -P)")
			}
			opts.policy = policy
			return runPush(args[0], opts)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.public, "public", false, "mint a shareable public link instead of a private ref")
	pw.bind(cmd, "password-gate a public link (implies --public)")
	// No backticks in the usage string: cobra renders backticked text as the flag's
	// value type, which turned this into `-n, --name aqt ls`.
	f.StringVarP(&opts.name, "name", "n", "", "label shown in aqt ls listings (encrypted)")
	f.BoolVar(&opts.noClip, "no-clip", false, "do not copy the result to the clipboard")
	f.StringVar(&expire, "expire", "", "expire the public link after a duration (e.g. 30m, 24h, 7d)")
	f.Int64Var(&maxReads, "max-reads", 0, "expire the public link after this many downloads")
	f.BoolVar(&burn, "burn", false, "burn after reading (shorthand for --max-reads 1)")
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}

func runPush(path string, opts pushOptions) error {
	// A directory would only die later with a raw `read ...: is a directory`;
	// point at the folder workflow instead.
	if path != "-" {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return fmt.Errorf("%s is a directory: push uploads single files. Track and sync a folder with "+
				"`aqt init %s` + `aqt sync %s`, or materialize it elsewhere with `aqt clone`", path, path, path)
		}
	}
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}

	// Large regular files stream (private, public, or gated); stdin stays inline.
	if path != "-" {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() >= streamThreshold {
			return runPushStream(cl, prof, path, opts)
		}
	}

	data, name, err := readInput(path, opts.name)
	if err != nil {
		return err
	}

	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer ck.Wipe()
	// A create's seals cannot bind the resource id: the server assigns it only in
	// the PutResource response below, after which bindCreated re-seals both bound.
	blob, err := crypto.Seal(data, ck, crypto.AADBlob)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: name, Size: int64(len(data)), Kind: api.KindFile})
	if err != nil {
		return err
	}
	metaBlob, err := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	if err != nil {
		return err
	}

	req := api.PutResourceRequest{
		Blob: blob, EncryptedMeta: metaBlob,
		MinClient: api.CapabilityIDBinding, // the bind below seals body and meta id-bound (v2)
	}
	if opts.public || opts.password != "" {
		req.Visibility = api.Public
		req.ExpireSeconds = opts.policy.expireSeconds
		req.MaxReads = opts.policy.maxReads
		req.OnExpiry = opts.policy.onExpiry
	} else {
		req.Visibility = api.Private
	}

	// Always wrap the content key under the master key so the owner can manage
	// the resource later (share/private). For public resources the server strips
	// this wrapped key from non-owner reads.
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	mk.Wipe()
	if err != nil {
		return err
	}
	req.WrappedKey = &wrapped

	resp, err := cl.PutResource(req)
	if err != nil {
		return err
	}
	// The policy echo is the create's own answer, so it is checked before the bind
	// write replaces the version confirmPolicy would delete.
	if err := confirmPolicy(cl, resp, opts.policy); err != nil {
		return err
	}
	if _, err := bindCreated(cl, req, resp, ck, metaJSON, func(id string) (crypto.SealedBlob, error) {
		return crypto.SealBound(data, ck, crypto.AADBlob, id)
	}); err != nil {
		return err
	}

	ref, err := buildRef(prof.Server, resp.ID, req.Visibility, ck, opts.password)
	if err != nil {
		// The blob is already uploaded; surface the id so it is recoverable
		// (and, for public pushes, deletable — its key lived only in the link).
		return fmt.Errorf("uploaded as id %s, but building the share link failed: %w", resp.ID, err)
	}
	return printResult(resp.ID, ref, name, int64(len(data)), req.Visibility, opts)
}

// runPushStream uploads a large private file as convergent chunk objects under a
// sealed FileRoot, so the file is never held whole in memory.
func runPushStream(cl *client.Client, prof *identity.Profile, path string, opts pushOptions) error {
	name := opts.name
	if name == "" {
		name = filepath.Base(path)
	}

	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()

	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer ck.Wipe()

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	up := newUploader(cl, nil)
	chunker := syncengine.DefaultChunkSelector().ChunkerFor(info.Size())
	chunks, size, err := syncengine.ChunkFile(f, conv, chunker, up)
	if err != nil {
		_ = up.Wait() // drain in-flight uploads before returning the chunking error
		return err
	}
	// A large file's chunk list would itself overflow the resource blob, so above a
	// threshold BuildFileRoot seals it as convergent segments (uploaded via up) and
	// refs carries both the content chunks and those segments as GC roots.
	root, refs, err := syncengine.BuildFileRoot(chunks, size, conv, up)
	if err != nil {
		_ = up.Wait()
		return err
	}
	if err := up.Flush(); err != nil {
		return err
	}

	// The create seals unbound (the id is assigned by the PUT below) and bindCreated
	// re-seals root and metadata under it, which is the form every read expects.
	blob, err := syncengine.SealFileRoot(root, ck, "")
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: name, Size: size, Kind: api.KindFile, Streamed: true})
	if err != nil {
		return err
	}
	metaBlob, err := crypto.Seal(metaJSON, ck, crypto.AADMeta)
	if err != nil {
		return err
	}
	// Always wrap the content key under the master key for owner recovery; the server
	// strips it from non-owner reads of a public resource.
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}

	visibility := api.Private
	var (
		expireSeconds, maxReads int64
		onExpiry                api.OnExpiry
	)
	if opts.public || opts.password != "" {
		visibility = api.Public
		expireSeconds = opts.policy.expireSeconds
		maxReads = opts.policy.maxReads
		onExpiry = opts.policy.onExpiry
	}

	req := api.PutResourceRequest{
		Visibility:    visibility,
		Blob:          blob,
		EncryptedMeta: metaBlob,
		WrappedKey:    &wrapped,
		ChunkRefs:     refs,
		MinClient:     api.CapabilityIDBinding, // the bind below seals the FileRoot and meta id-bound (v2)
		ExpireSeconds: expireSeconds,
		MaxReads:      maxReads,
		OnExpiry:      onExpiry,
	}
	resp, err := cl.PutResource(req)
	if err != nil {
		return err
	}
	// The policy echo is the create's own answer, so it is checked before the bind
	// write replaces the version confirmPolicy would delete.
	if err := confirmPolicy(cl, resp, opts.policy); err != nil {
		return err
	}
	if _, err := bindCreated(cl, req, resp, ck, metaJSON, func(id string) (crypto.SealedBlob, error) {
		return syncengine.SealFileRoot(root, ck, id)
	}); err != nil {
		return err
	}
	ref, err := buildRef(prof.Server, resp.ID, visibility, ck, opts.password)
	if err != nil {
		return fmt.Errorf("uploaded as id %s, but building the share link failed: %w", resp.ID, err)
	}
	return printResult(resp.ID, ref, name, size, visibility, opts)
}

// confirmPolicy fails closed when a requested lifecycle policy was not enforced by the
// server, deleting the just-created resource so a link is never handed out for content
// the server will not actually expire. A no-policy push is a no-op.
func confirmPolicy(cl *client.Client, resp api.PutResourceResponse, policy linkPolicy) error {
	if err := verifyPolicyEcho(policy, resp); err != nil {
		_ = cl.DeleteResourceVersion(resp.ID, resp.Version)
		return err
	}
	return nil
}

func readInput(path, name string) (data []byte, resolvedName string, err error) {
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
		if name == "" {
			name = "stdin"
		}
		return data, name, err
	}
	data, err = os.ReadFile(path)
	if name == "" {
		name = filepath.Base(path)
	}
	return data, name, err
}

func buildRef(server, id string, vis api.Visibility, ck crypto.ContentKey, password string) (string, error) {
	if vis == api.Private {
		return "aqt://" + id, nil
	}
	frag, err := crypto.EncodeFragment(ck, password)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/x/%s#%s", strings.TrimRight(server, "/"), id, frag), nil
}

type pushJSON struct {
	ID         string `json:"id"`
	Ref        string `json:"ref"`
	URL        string `json:"url,omitempty"`
	Name       string `json:"name,omitempty"`
	Bytes      int64  `json:"bytes"`
	Visibility string `json:"visibility"`
}

// buildPushJSON assembles the documented push result. link is the share link from
// buildRef; URL is set only for public pushes, since a private link is just the
// aqt:// ref already carried by Ref.
func buildPushJSON(id, link, name string, size int64, vis api.Visibility) pushJSON {
	out := pushJSON{
		ID:         id,
		Ref:        "aqt://" + id,
		Name:       name,
		Bytes:      size,
		Visibility: string(vis),
	}
	if vis == api.Public {
		out.URL = link
	}
	return out
}

func printResult(id, ref, name string, size int64, vis api.Visibility, opts pushOptions) error {
	if flagJSON {
		return printJSON(buildPushJSON(id, ref, name, size, vis))
	}
	if flagQuiet {
		fmt.Println(ref)
		return nil
	}
	copied := !opts.noClip && copyToClipboard(ref)
	fmt.Println(ref)
	if copied {
		fmt.Fprintln(os.Stderr, "(copied to clipboard)")
	}
	visLabel := string(vis)
	if opts.password != "" {
		visLabel += " · password-gated"
	}
	fmt.Fprintf(os.Stderr, "%s · %d B · %s\n", name, size, visLabel)
	return nil
}
