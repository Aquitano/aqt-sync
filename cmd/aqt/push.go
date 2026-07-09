package main

import (
	"encoding/json"
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

// streamThreshold is the size at or above which a private push streams through the
// chunk/pack pipeline rather than sealing the whole file in one inline blob. Public
// files and stdin stay inline (public streaming needs the deferred publicly-readable
// object store; stdin has no size to threshold on).
const streamThreshold = 8 << 20

type pushOptions struct {
	public   bool
	password string
	name     string
	noClip   bool
	quiet    bool
	json     bool
}

func pushCmd() *cobra.Command {
	var opts pushOptions
	cmd := &cobra.Command{
		Use:   "push <path|->",
		Short: "Encrypt and upload a file (private by default)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A password gate only makes sense on a shareable link.
			if opts.password != "" {
				opts.public = true
			}
			return runPush(args[0], opts)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.public, "public", false, "mint a shareable public link instead of a private ref")
	f.StringVarP(&opts.password, "password", "P", "", "password-gate a public link (implies --public)")
	f.StringVarP(&opts.name, "name", "n", "", "label shown in `aqt ls` (encrypted)")
	f.BoolVar(&opts.noClip, "no-clip", false, "do not copy the result to the clipboard")
	return cmd
}

func runPush(path string, opts pushOptions) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}

	// Large private files stream; everything else takes the inline path below.
	if path != "-" && !opts.public && opts.password == "" {
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
	// the PutResource response below. OpenBound's v1 fallback reads them.
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

	// Inline push seals unbound (AADBlob, no id): a create has no server-assigned id
	// to bind yet, so it stays baseline-readable.
	req := api.PutResourceRequest{Blob: blob, EncryptedMeta: metaBlob, MinClient: api.CapabilityBaseline}
	if opts.public || opts.password != "" {
		req.Visibility = api.Public
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

	ref, err := buildRef(prof.Server, resp.ID, req.Visibility, ck, opts.password)
	if err != nil {
		// The blob is already uploaded; surface the id so it is recoverable
		// (and, for public pushes, deletable — its key lived only in the link).
		return fmt.Errorf("uploaded as id %s, but building the share link failed: %w", resp.ID, err)
	}
	printResult(resp.ID, ref, name, int64(len(data)), req.Visibility, opts)
	return nil
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
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	up := newPackUploader(cl, nil)
	chunker := syncengine.DefaultChunkSelector().ChunkerFor(info.Size())
	chunks, size, err := syncengine.ChunkFile(f, conv, chunker, up)
	if err != nil {
		up.Wait() // drain in-flight uploads before returning the chunking error
		return err
	}
	// A large file's chunk list would itself overflow the resource blob, so above a
	// threshold BuildFileRoot seals it as convergent segments (uploaded via up) and
	// refs carries both the content chunks and those segments as GC roots.
	root, refs, err := syncengine.BuildFileRoot(chunks, size, conv, up)
	if err != nil {
		up.Wait()
		return err
	}
	if err := up.Flush(); err != nil {
		return err
	}

	blob, err := syncengine.SealFileRoot(root, ck, "") // create: id not assigned yet
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
	wrapped, err := crypto.WrapKey(ck, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}

	resp, err := cl.PutResource(api.PutResourceRequest{
		Visibility:    api.Private,
		Blob:          blob,
		EncryptedMeta: metaBlob,
		WrappedKey:    &wrapped,
		ChunkRefs:     refs,
		MinClient:     api.CapabilityBaseline, // create seals the FileRoot unbound (id not assigned yet)
	})
	if err != nil {
		return err
	}
	printResult(resp.ID, "aqt://"+resp.ID, name, size, api.Private, opts)
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

func printResult(id, ref, name string, size int64, vis api.Visibility, opts pushOptions) {
	// The global --json/-q drive the CLI; the opts fields keep programmatic callers
	// (the bare-path push, tests) able to request them directly.
	if flagJSON || opts.json {
		printJSON(buildPushJSON(id, ref, name, size, vis))
		return
	}
	if flagQuiet || opts.quiet {
		fmt.Println(ref)
		return
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
}
