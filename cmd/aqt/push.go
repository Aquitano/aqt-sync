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
	"github.com/aquitano/aqt-sync/internal/crypto"
)

type pushOptions struct {
	public   bool
	password string
	name     string
	noClip   bool
	quiet    bool
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
	f.BoolVarP(&opts.quiet, "quiet", "q", false, "print only the resulting ref/URL")
	return cmd
}

func runPush(path string, opts pushOptions) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}

	data, name, err := readInput(path, opts.name)
	if err != nil {
		return err
	}

	ck, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	blob, err := crypto.Seal(data, ck)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(api.Metadata{Name: name, Size: int64(len(data))})
	if err != nil {
		return err
	}
	metaBlob, err := crypto.Seal(metaJSON, ck)
	if err != nil {
		return err
	}

	req := api.PutResourceRequest{Blob: blob, EncryptedMeta: metaBlob}
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
	printResult(ref, name, len(data), req.Visibility, opts)
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

func printResult(ref, name string, size int, vis api.Visibility, opts pushOptions) {
	if opts.quiet {
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
