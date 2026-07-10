package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/syncengine"
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
	// Sanity-check the unwrapped key before flipping visibility.
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Kind == api.KindFolder {
		return errors.New("sharing a whole folder publicly is not supported yet")
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
	meta, err := decodeMeta(res.EncryptedMeta, oldCK, id)
	if err != nil {
		return err
	}
	// A tracked folder is private-only and has no public link to rotate; rotating it
	// would also have to re-root its whole object graph. Refuse it.
	if meta.Kind == api.KindFolder {
		return errors.New("cannot rotate the key of a tracked folder; it is private-only and has no public link to rotate")
	}
	if meta.Streamed {
		return rotateStreamed(cl, id, res, oldCK, mk)
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

// rotateStreamed rotates a streamed file's key by re-wrapping the ROOT under a fresh
// content key and flipping visibility back to private. The convergent chunk objects
// and their per-chunk keys are untouched: re-sealing the content would break dedup and
// re-upload the whole file, and an old link holder could have saved the plaintext
// anyway. Access revocation is enforced server-side by the visibility flip. The re-PUT
// must carry the resource's full ChunkRefs, since the server refuses a re-PUT that
// drops the GC roots of an object-backed resource.
func rotateStreamed(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey) error {
	root, err := syncengine.OpenFileRoot(res.Blob, oldCK, id)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	// Recover the full content chunk records so ChunkRefs mirrors what BuildFileRoot
	// produced at push time; an indirect root's list segments sit behind their own
	// locate, so fetch them through the authed path first.
	chunks := root.Chunks
	if root.Indirect() {
		segSrc, err := newPackSource(cl, root.ChunkIDs())
		if err != nil {
			return err
		}
		chunks, err = root.Resolve(segSrc.get)
		if err != nil {
			return err
		}
	}
	refs := root.Refs(chunks)

	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer newCK.Wipe()
	// SealFileRoot binds the root to the id even if the original create was unbound.
	blob, err := syncengine.SealFileRoot(root, newCK, id)
	if err != nil {
		return err
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		return fmt.Errorf("decrypt metadata: %w", err)
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		return err
	}
	if _, err := cl.PutResource(api.PutResourceRequest{
		ID:              id,
		Visibility:      api.Private,
		Blob:            blob,
		EncryptedMeta:   metaBlob,
		WrappedKey:      &wrapped,
		ChunkRefs:       refs,
		ExpectedVersion: res.Version,
		MinClient:       api.CapabilityIDBinding, // SealFileRoot re-seals the root id-bound (v2)
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
