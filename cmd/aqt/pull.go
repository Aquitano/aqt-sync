package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
		out      string
		password string
		toStdout bool
		force    bool
	)
	cmd := &cobra.Command{
		Use:   "pull <url|id|aqt://ref>",
		Short: "Fetch and decrypt a resource",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPull(args[0], out, password, toStdout, force)
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write to this path")
	cmd.Flags().StringVarP(&password, "password", "P", "", "password for a gated link")
	cmd.Flags().BoolVar(&toStdout, "stdout", false, "write decrypted content to stdout")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the destination if it exists")
	return cmd
}

func catCmd() *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "cat <url|id|aqt://ref>",
		Short: "Decrypt a resource to stdout without writing to disk",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPull(args[0], "", password, true, false)
		},
	}
	cmd.Flags().StringVarP(&password, "password", "P", "", "password for a gated link")
	return cmd
}

func runPull(ref, out, password string, toStdout, force bool) error {
	id, fragment := parseRef(ref)

	// A public link decrypts from its fragment and needs no profile; a private
	// ref needs the account token (to fetch) and passphrase (to unwrap).
	prof := loadProfileOptional()
	token := ""
	if prof != nil {
		token = prof.Token
	}
	cl, err := client.New(serverURL(), token)
	if err != nil {
		return err
	}

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found (or private and you're not its owner)", id)
	}
	if err != nil {
		return err
	}

	ck, err := contentKey(res, fragment, password, prof)
	if err != nil {
		return err
	}
	defer ck.Wipe()

	meta, err := decodeMeta(res.EncryptedMeta, ck)
	if err != nil {
		return err
	}
	if meta.Streamed {
		return pullStream(cl, res, ck, out, meta, toStdout, force)
	}

	plaintext, err := crypto.Open(res.Blob, ck, crypto.AADBlob)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	return writeOutput(plaintext, out, meta, toStdout, force)
}

// pullStream reconstructs a streamed file from its objects, writing chunks to the
// destination as they are fetched so the whole file is never held in memory.
func pullStream(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, out string, meta api.Metadata, toStdout, force bool) error {
	root, err := syncengine.OpenFileRoot(res.Blob, ck)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	src, err := newPackSource(cl, root.ChunkIDs())
	if err != nil {
		return err
	}
	if toStdout {
		return syncengine.WriteFileRoot(os.Stdout, root, src.get)
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
		return syncengine.WriteFileRoot(f, root, src.get)
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", dest, root.Size)
	return nil
}

// contentKey recovers the content key either from the share fragment (public/
// gated) or by unwrapping with the master key (private).
func contentKey(res api.GetResourceResponse, fragment, password string, prof *identity.Profile) (crypto.ContentKey, error) {
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
	if res.WrappedKey == nil {
		return crypto.ContentKey{}, errors.New("no decryption key: this looks like a public resource but the link had no #key")
	}
	if prof == nil {
		return crypto.ContentKey{}, errors.New("private resource: run `aqt login` to decrypt it")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	defer mk.Wipe()
	return crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
}

// safeOutputName reduces an attacker-controlled metadata name to a bare basename
// inside the current directory, so a malicious link cannot steer a default
// destination to "../" or an absolute path and write outside CWD.
func safeOutputName(name string) string {
	base := filepath.Base(name)
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

// parseRef extracts the resource id and optional fragment from any ref form:
// a full https URL (.../x/<id>#<frag>), an aqt://<id> ref, or a bare id.
func parseRef(ref string) (id, fragment string) {
	if i := strings.Index(ref, "#"); i >= 0 {
		fragment = ref[i+1:]
		ref = ref[:i]
	}
	ref = strings.TrimPrefix(ref, "aqt://")
	if i := strings.LastIndex(ref, "/x/"); i >= 0 {
		ref = ref[i+len("/x/"):]
	} else if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref, fragment
}

// decodeMeta decrypts and parses a resource's sealed metadata. A decrypt or parse
// failure is returned rather than swallowed: in an owner flow the content key is
// correct, so a failure means corruption (or a blob/meta mix-up), and treating it as
// a default (unpacked, unstreamed) resource silently misroutes the resource — e.g.
// cloning a pack-and-seal folder through the chunked path and writing nothing.
func decodeMeta(blob crypto.SealedBlob, ck crypto.ContentKey) (api.Metadata, error) {
	plain, err := crypto.Open(blob, ck, crypto.AADMeta)
	if err != nil {
		return api.Metadata{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	var m api.Metadata
	if err := json.Unmarshal(plain, &m); err != nil {
		return api.Metadata{}, fmt.Errorf("parse metadata: %w", err)
	}
	return m, nil
}
