package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

func shareCmd() *cobra.Command {
	var (
		password string
		noClip   bool
	)
	cmd := &cobra.Command{
		Use:   "share <id>",
		Short: "Make a private resource public and print a share link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShare(args[0], password, noClip)
		},
	}
	cmd.Flags().StringVarP(&password, "password", "P", "", "password-gate the share link")
	cmd.Flags().BoolVar(&noClip, "no-clip", false, "do not copy the link to the clipboard")
	return cmd
}

func runShare(idArg, password string, noClip bool) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	id, _, _ := parseRef(idArg)

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found", id)
	}
	if err != nil {
		return err
	}
	// Sharing exposes the existing content key in the link; it does not
	// re-encrypt. Recovering that key needs the owner's wrapped key.
	if res.WrappedKey == nil {
		return errors.New("no owner key stored for this resource (it was pushed --public); use the share link from that push")
	}

	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap key: %w", err)
	}
	defer ck.Wipe()
	// A streamed file's objects live in the owner-only pack store, so a public reader
	// could not fetch them even with the link key.
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Streamed {
		return errors.New("this is a streamed private file; public sharing of streamed files is not supported yet")
	}
	if res.Visibility != api.Public {
		if _, err := cl.SetVisibility(id, api.Public); err != nil {
			return err
		}
	}
	ref, err := buildRef(prof.Server, id, api.Public, ck, password)
	if err != nil {
		return err
	}

	fmt.Println(ref)
	if !noClip && copyToClipboard(ref) {
		fmt.Fprintln(os.Stderr, "(copied to clipboard)")
	}
	return nil
}

func privateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "private <id>",
		Short: "Make a resource private again, rotating its key so old links die",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPrivate(args[0])
		},
	}
}

func runPrivate(idArg string) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	id, _, _ := parseRef(idArg)

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found", id)
	}
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("no owner key stored for this resource; cannot rotate it")
	}

	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	oldCK, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		return fmt.Errorf("unwrap key: %w", err)
	}
	defer oldCK.Wipe()
	// A streamed file or tracked folder is object-backed: its blob is a root pointer
	// over chunk objects, and the resource's ChunkRefs are the sole GC liveness roots
	// for those objects. Rotating re-seals the blob and re-PUTs it; carrying no
	// ChunkRefs would drop those roots, so the next GC unlinks the still-referenced
	// objects — unrecoverable loss. Such resources are private-only anyway (their
	// objects are never publicly fetchable, and `share` already refuses streamed
	// files), so there is no public link to rotate. Refuse rather than destroy.
	meta, err := decodeMeta(res.EncryptedMeta, oldCK, id)
	if err != nil {
		return err
	}
	if meta.Streamed || meta.Kind == api.KindFolder {
		return errors.New("cannot rotate the key of a streamed file or tracked folder; it is private-only and has no public link to rotate")
	}
	plaintext, err := crypto.OpenBound(res.Blob, oldCK, crypto.AADBlob, id)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		return fmt.Errorf("decrypt metadata: %w", err)
	}

	// Rotate: a fresh content key re-encrypts the body and metadata, so any link
	// carrying the old key can no longer decrypt the resource.
	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer newCK.Wipe()
	blob, err := crypto.SealBound(plaintext, newCK, crypto.AADBlob, id)
	if err != nil {
		return err
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}
	// Optimistic concurrency: the rotate is a read-modify-write, so pin it to the
	// version we just fetched. A concurrent sync committing between the GET and this
	// PUT would otherwise be silently overwritten with stale content.
	if _, err := cl.PutResource(api.PutResourceRequest{
		ID:              id,
		Visibility:      api.Private,
		Blob:            blob,
		EncryptedMeta:   metaBlob,
		WrappedKey:      &wrapped,
		ExpectedVersion: res.Version,
		MinClient:       api.CapabilityIDBinding, // rotate re-seals blob and meta id-bound (v2)
	}); err != nil {
		if errors.Is(err, client.ErrConflict) {
			return errors.New("resource changed while rotating its key; re-run `aqt private`")
		}
		return err
	}

	fmt.Println("aqt://" + id)
	fmt.Fprintln(os.Stderr, "rotated content key — any previous public link no longer decrypts")
	return nil
}
