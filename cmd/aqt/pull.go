package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
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

func runPull(ref, out, password string, toStdout, force bool) error {
	id, fragment := parseRef(ref)

	// A public link decrypts from its fragment and needs no profile; a private
	// ref needs the account token (to fetch) and passphrase (to unwrap).
	prof := loadProfileOptional()
	token := ""
	if prof != nil {
		token = prof.Token
	}
	cl := client.New(serverURL(), token)

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

	plaintext, err := crypto.Open(res.Blob, ck, crypto.AADBlob)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key or corrupted): %w", err)
	}
	meta := decodeMeta(res.EncryptedMeta, ck)

	return writeOutput(plaintext, out, meta, toStdout, force)
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

func writeOutput(plaintext []byte, out string, meta api.Metadata, toStdout, force bool) error {
	if toStdout {
		_, err := os.Stdout.Write(plaintext)
		return err
	}
	if out == "" {
		out = meta.Name
		if out == "" || out == "stdin" {
			out = "aqt-download"
		}
	}
	if !force {
		if _, err := os.Stat(out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", out)
		}
	}
	if err := os.WriteFile(out, plaintext, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d B)\n", out, len(plaintext))
	return nil
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

func decodeMeta(blob crypto.SealedBlob, ck crypto.ContentKey) api.Metadata {
	var m api.Metadata
	if plain, err := crypto.Open(blob, ck, crypto.AADMeta); err == nil {
		_ = json.Unmarshal(plain, &m)
	}
	return m
}
