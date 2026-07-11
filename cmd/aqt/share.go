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
		pw       passwordFlags
		noClip   bool
		expire   string
		maxReads int64
		burn     bool
	)
	cmd := &cobra.Command{
		Use:   "share <id>",
		Short: "Make a private resource public and print a share link",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, err := resolveLinkPolicy(expire, maxReads, burn)
			if err != nil {
				return err
			}
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return runShare(args[0], password, noClip, policy)
		},
	}
	pw.bind(cmd, "password-gate the share link")
	cmd.Flags().BoolVar(&noClip, "no-clip", false, "do not copy the link to the clipboard")
	cmd.Flags().StringVar(&expire, "expire", "", "expire the link after a duration (e.g. 30m, 24h, 7d)")
	cmd.Flags().Int64Var(&maxReads, "max-reads", 0, "expire the link after this many downloads")
	cmd.Flags().BoolVar(&burn, "burn", false, "burn after reading (shorthand for --max-reads 1)")
	return cmd
}

func runShare(idArg, password string, noClip bool, policy linkPolicy) error {
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
	// A chunked folder shares like a streamed file: its nodes and chunks are already
	// the resource's referenced object set, so the public endpoint serves them and
	// the fragment key opens the tree root. Pack-and-seal folders store one opaque
	// pack with no per-entry objects, so a link holder could never walk them.
	if meta.Kind == api.KindFolder {
		if meta.Packed {
			return errors.New("cannot share a pack-and-seal folder; re-create it as a chunked folder to share it")
		}
		if !meta.Tree {
			return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
		}
	}
	// Always call SetVisibility when a policy is requested, even if the resource is
	// already public, so the policy is applied (and the read counter reset). A plain
	// re-share of an already-public resource still skips the call.
	wasPublic := res.Visibility == api.Public
	if !wasPublic || policy.requested() {
		resp, err := cl.SetVisibility(id, api.Public, policy.expireSeconds, policy.maxReads)
		if err != nil {
			return err
		}
		if err := verifyPolicyEcho(policy, resp); err != nil {
			// Fail closed: undo the flip only if this call made it public, so a
			// previously-public link is not silently revoked by a failed policy add.
			if !wasPublic {
				_, _ = cl.SetVisibility(id, api.Private, 0, 0)
			}
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
	if meta.Kind == api.KindFolder {
		if meta.Packed {
			return errors.New("a pack-and-seal folder cannot be shared, so it has no public link to rotate")
		}
		if !meta.Tree {
			return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
		}
		return rotateTree(cl, id, res, oldCK, mk)
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
// rotateTree rotates a chunked folder's key the way rotateStreamed rotates a file's:
// only the TreeRoot blob and metadata are re-sealed under a fresh content key. The
// convergent directory nodes and chunk objects stay — their per-object keys derive
// from the account convergence key, which a link never carried — so the visibility
// flip plus a root the old key cannot open is what kills the link. The re-PUT must
// carry the resource's full GC roots; they are recomputed by re-sealing the tree in
// memory, which is deterministic under the convergence key.
func rotateTree(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey) error {
	root, err := syncengine.OpenTreeRoot(res.Blob, oldCK, id)
	if err != nil {
		return fmt.Errorf("decrypt folder root: %w", err)
	}
	manifest, err := syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, nil))
	if err != nil {
		return err
	}
	sealed, refs, err := syncengine.SealTree(manifest, crypto.DeriveConvergenceKey(mk), nil)
	if err != nil {
		return err
	}
	// The recomputed root must reproduce the stored one: a mismatch means the walk
	// and the sealer disagree, and PUTting the recomputed refs could orphan live
	// objects. Refuse rather than risk the folder's object graph.
	if sealed.Root.ID != root.Root.ID {
		return fmt.Errorf("recomputed tree root %s does not match stored root %s; not rotating", sealed.Root.ID, root.Root.ID)
	}

	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return err
	}
	defer newCK.Wipe()
	blob, err := syncengine.SealTreeRoot(root, newCK, id)
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
		MinClient:       api.CapabilityIDBinding, // SealTreeRoot re-seals the root id-bound (v2)
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
