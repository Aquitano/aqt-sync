package main

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func shareCmd() *cobra.Command {
	var (
		pw       passwordFlags
		noClip   bool
		expire   string
		maxReads int64
		burn     bool
		with     string
		revoke   string
	)
	cmd := &cobra.Command{
		Use:   "share <id>",
		Short: "Share a resource: publicly via a link, or read-only with a specific account (--with)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The resource existed before the link and outlives it: expiry takes the link
			// down (private again, policy cleared) and never touches the content. A
			// shared folder is still the copy every other device syncs against.
			policy, err := resolveLinkPolicy(expire, maxReads, burn, api.ExpiryRetire)
			if err != nil {
				return err
			}
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			if with != "" || revoke != "" {
				if with != "" && revoke != "" {
					return errors.New("--with and --revoke are mutually exclusive")
				}
				if policy.requested() || password != "" {
					return errors.New("link flags (--password/--expire/--max-reads/--burn) do not apply to account grants")
				}
				if revoke != "" {
					return runShareRevoke(args[0], revoke)
				}
				return runShareWith(args[0], with)
			}
			return runShare(args[0], password, noClip, policy)
		},
	}
	pw.bind(cmd, "password-gate the share link")
	cmd.Flags().BoolVar(&noClip, "no-clip", false, "do not copy the link to the clipboard")
	cmd.Flags().StringVar(&expire, "expire", "", "expire the link after a duration (e.g. 30m, 24h, 7d)")
	cmd.Flags().Int64Var(&maxReads, "max-reads", 0, "expire the link after this many downloads")
	cmd.Flags().BoolVar(&burn, "burn", false, "burn after reading (shorthand for --max-reads 1)")
	cmd.Flags().StringVar(&with, "with", "", "grant read-only access to a specific account by email (no public link)")
	cmd.Flags().StringVar(&revoke, "revoke", "", "revoke an account's grant by email and rotate the content key")
	return cmd
}

// checkShareableFolder rejects the folder formats no non-owner transport can serve.
// A link holder and a grantee both read exact object slices, so they need a folder
// whose entries ARE objects: a pack-and-seal folder stores one opaque pack with no
// per-entry objects, and a legacy folder predates the tree format entirely. Neither
// can be walked with only the content key, and both are equally unrotatable. A
// non-folder passes untouched.
func checkShareableFolder(meta api.Metadata) error {
	if meta.Kind != api.KindFolder {
		return nil
	}
	if meta.Packed {
		return errors.New("cannot share a pack-and-seal folder: it stores no per-file objects, " +
			"so a link holder or grantee could never walk it; re-create it as a chunked folder")
	}
	if !meta.Tree {
		return errors.New("this folder uses an unsupported legacy format; re-create it with a current client")
	}
	return nil
}

// runShareWith grants one account read-only access: the resource's content key is
// HPKE-wrapped to the grantee's published enc key, bound to (resource, owner,
// grantee), and stored server-side as an opaque blob. Visibility is untouched —
// a grant is not a link.
func runShareWith(idArg, email string) error {
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
		return errors.New("no owner key stored for this resource; only resources you own can be granted")
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
	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if err := checkShareableFolder(meta); err != nil {
		return err
	}
	contact, err := lookupGrantee(cl, prof, email)
	if err != nil {
		return err
	}
	if contact.Handle == prof.OwnerHandle {
		return errors.New("cannot grant a resource to your own account")
	}
	wrap, err := crypto.WrapGrant(ck, contact.EncPublicKey, id, prof.OwnerHandle, contact.Handle)
	if err != nil {
		return err
	}
	if err := cl.CreateGrant(id, api.CreateGrantRequest{GranteeHandle: contact.Handle, WrappedKey: wrap}); err != nil {
		return err
	}
	fmt.Printf("granted %s read-only access to aqt://%s\n", email, id)
	fmt.Fprintln(os.Stderr, "they will see it under `aqt shares` and can pull or clone it; they cannot modify it")
	return nil
}

// runShareRevoke rotates the content key so the revoked wrap opens nothing that changes
// from here on, dropping the grant in the same transaction, then re-wraps for the
// remaining grantees. A public resource skips rotation: its key is in a link anyway, and
// rotating would kill that link as a side effect.
//
// The rotation and the delete are one server-side write because every way of splitting
// them fails badly. Deleting first and then failing to rotate strands the revoked account
// with a working key and destroys the retry's only evidence that anything is left to do —
// the re-run reports "no grant" and stops, with forward secrecy quietly broken. Rotating
// first and then failing to delete leaves the revoked account listed as a grantee holding
// a stale wrap, and the next rotation's re-wrap hands it the new key. Together, they
// either both land or neither does, and a failure is a clean no-op the user can re-run.
func runShareRevoke(idArg, email string) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	id, _, _ := parseRef(idArg)

	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return err
	}
	handle := ""
	if pin, ok := pins[email]; ok {
		handle = pin.Handle
	} else {
		keys, err := fetchAccountKeys(cl, email)
		if err != nil {
			return err
		}
		handle = keys.Handle
	}
	grants, err := cl.ListGrants(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found", id)
	}
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(grants, func(g api.GrantEntry) bool { return g.GranteeHandle == handle }) {
		return fmt.Errorf("no grant for %s on aqt://%s", email, id)
	}

	res, err := cl.GetResource(id)
	if err != nil {
		return err
	}
	revoke := func() error {
		if err := cl.RevokeGrant(id, handle); err != nil {
			return fmt.Errorf("deleting the grant for %s failed: %w", email, err)
		}
		return nil
	}
	if res.Visibility == api.Public {
		if err := revoke(); err != nil {
			return err
		}
		fmt.Printf("revoked %s from aqt://%s\n", email, id)
		fmt.Fprintln(os.Stderr, "the resource is public, so its content key was not rotated; `aqt private` rotates it")
		return nil
	}
	if res.WrappedKey == nil {
		if err := revoke(); err != nil {
			return err
		}
		fmt.Printf("revoked %s from aqt://%s (no owner key; content key not rotated)\n", email, id)
		return nil
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
	newCK, err := rotateResourceKey(cl, id, res, oldCK, mk, meta, handle)
	if err != nil {
		// The rotate+revoke is one PUT, but a lost response leaves its outcome unknown:
		// it may have committed. Do not claim it did not. Forward secrecy is safe either
		// way — a committed write cut the grantee off, a failed one never rotated — but a
		// committed-then-lost write can leave the surviving grantees split across two
		// keys. `aqt private` re-rotates and re-wraps every remaining grant, so it
		// reconciles them whatever happened here.
		return fmt.Errorf("revoking %s failed (%w); the revoke may not have taken effect — run `aqt private %s` to rotate the key and bring the remaining shares onto it", email, err, id)
	}
	defer newCK.Wipe()
	// The same write that rotated the key dropped the grant, but re-wrap from a fresh
	// list and skip the revoked handle anyway: a hostile server that ignored the delete
	// and keeps listing it would otherwise get us to hand it a wrap of the NEW key,
	// undoing the revocation the rotation just enforced.
	rewrapGrants(cl, prof, id, newCK, handle)
	fmt.Printf("revoked %s from aqt://%s and rotated the content key\n", email, id)
	return nil
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
	// the fragment key opens the tree root.
	if err := checkShareableFolder(meta); err != nil {
		return err
	}
	// Always call SetVisibility when a policy is requested, even if the resource is
	// already public, so the policy is applied (and the read counter reset). A plain
	// re-share of an already-public resource still skips the call.
	wasPublic := res.Visibility == api.Public
	if !wasPublic || policy.requested() {
		resp, err := cl.SetVisibility(id, api.SetVisibilityRequest{
			Visibility:    api.Public,
			ExpireSeconds: policy.expireSeconds,
			MaxReads:      policy.maxReads,
			OnExpiry:      policy.onExpiry,
		})
		if err != nil {
			return err
		}
		if err := verifyPolicyEcho(policy, resp); err != nil {
			// Fail closed AND roll the resource back to its pre-share state — the flip
			// above already stored the policy this server cannot honor, so erroring
			// without undoing it would leave a live reclaim policy that destroys the
			// resource on expiry. A resource this call made public goes private again; a
			// resource that was already public is re-flipped public with no policy, which
			// clears expires_at/max_reads on every server generation and so disarms the
			// bad policy without taking the pre-existing link down.
			var undo error
			if wasPublic {
				_, undo = cl.SetVisibility(id, api.SetVisibilityRequest{Visibility: api.Public})
			} else {
				_, undo = cl.SetVisibility(id, api.SetVisibilityRequest{Visibility: api.Private})
			}
			if undo != nil {
				return fmt.Errorf("%w; additionally, clearing the policy this attempt stored failed (%v) — the link may still expire destructively, so run `aqt private %s` to rotate the key and drop the policy", err, undo, id)
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
	if policy.requested() {
		// Expiry takes the link down without rotating the content key (the server has no
		// key to rotate with), so the fragment above still opens the resource if it is
		// ever made public again. Only a rotation kills a link for good.
		fmt.Fprintln(os.Stderr, "when this link expires the resource stays and only the link goes down; `aqt private "+id+"` rotates the key, which kills every link ever issued for it")
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
	if err := checkShareableFolder(meta); err != nil {
		return err
	}
	newCK, err := rotateResourceKey(cl, id, res, oldCK, mk, meta, "")
	if err != nil {
		return err
	}
	defer newCK.Wipe()
	rewrapGrants(cl, prof, id, newCK, "")

	fmt.Println("aqt://" + id)
	fmt.Fprintln(os.Stderr, "rotated content key — any previous public link no longer decrypts")
	return nil
}

// rotateResourceKey re-seals a resource's root (and, inline, its body) under a
// fresh content key and flips it private, returning the new key so the caller can
// re-wrap surviving grants. The caller wipes the returned key.
//
// revoke, when set, is a grantee handle the server drops in the same transaction as the
// rotation. Revocation is exactly those two things, and they must commit together: a
// rotation whose grant delete is lost would leave the revoked account listed as a
// grantee, and the next rotation would re-wrap the new key straight back to it.
func rotateResourceKey(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, meta api.Metadata, revoke string) (crypto.ContentKey, error) {
	if meta.Kind == api.KindFolder {
		if meta.Packed || !meta.Tree {
			return crypto.ContentKey{}, errors.New("this folder format cannot rotate its key")
		}
		return rotateTree(cl, id, res, oldCK, mk, revoke)
	}
	if meta.Streamed {
		return rotateStreamed(cl, id, res, oldCK, mk, revoke)
	}
	return rotateInline(cl, id, res, oldCK, mk, revoke)
}

// rewrapGrants re-wraps a just-rotated content key for the resource's surviving
// grantees, so a rotation (privatize, or revoking someone else) does not silently
// break them. Best effort: a grantee pinned on another device cannot be re-wrapped
// here — warn, since only a device that has looked the grantee up holds their key.
//
// exclude is a grantee handle to never re-wrap, even if the server lists it: a revoke's
// rotation drops the grant server-side, but a hostile server that ignores the delete and
// keeps returning the handle would otherwise get us to hand it a wrap of the new key,
// undoing the revocation. Empty excludes nobody (a plain privatize revokes no one).
func rewrapGrants(cl *client.Client, prof *identity.Profile, id string, newCK crypto.ContentKey, exclude string) {
	grants, err := cl.ListGrants(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot list grants to re-wrap them for the new key: %v\n", err)
		fmt.Fprintf(os.Stderr, "warning: any grantee of %s now holds a wrap of the old key; re-run `aqt share %s --with <email>` for each\n", id, id)
		return
	}
	if len(grants) == 0 {
		return
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot load contacts to re-wrap grants: %v\n", err)
		return
	}
	byHandle := make(map[string]identity.Contact, len(pins))
	for _, c := range pins {
		byHandle[c.Handle] = c
	}
	for _, g := range grants {
		if g.GranteeHandle == exclude {
			continue
		}
		pin, ok := byHandle[g.GranteeHandle]
		if !ok {
			fmt.Fprintf(os.Stderr, "warning: grant for %s cannot be re-wrapped from this device (no pinned contact); re-run `aqt share --with` where it was granted\n", g.GranteeHandle)
			continue
		}
		wrap, err := crypto.WrapGrant(newCK, pin.EncPublicKey, id, prof.OwnerHandle, pin.Handle)
		if err == nil {
			err = cl.CreateGrant(id, api.CreateGrantRequest{GranteeHandle: pin.Handle, WrappedKey: wrap})
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: re-wrapping the grant for %s failed: %v\n", pin.Email, err)
		}
	}
}

// rotateInline rotates a small (inline) resource by re-encrypting body and
// metadata under a fresh content key.
func rotateInline(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	plaintext, err := crypto.OpenBound(res.Blob, oldCK, crypto.AADBlob, id)
	if err != nil {
		return crypto.ContentKey{}, fmt.Errorf("decrypt: %w", err)
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		return crypto.ContentKey{}, fmt.Errorf("decrypt metadata: %w", err)
	}

	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return crypto.ContentKey{}, err
	}
	blob, err := crypto.SealBound(plaintext, newCK, crypto.AADBlob, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
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
		RevokeGrantee:   revoke,
		MinClient:       api.CapabilityIDBinding, // rotate re-seals blob and meta id-bound (v2)
	}); err != nil {
		newCK.Wipe()
		if errors.Is(err, client.ErrConflict) {
			return crypto.ContentKey{}, errors.New("resource changed while rotating its key; re-run `aqt private`")
		}
		return crypto.ContentKey{}, err
	}
	return newCK, nil
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
func rotateTree(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	root, err := syncengine.OpenTreeRoot(res.Blob, oldCK, id)
	if err != nil {
		return crypto.ContentKey{}, fmt.Errorf("decrypt folder root: %w", err)
	}
	manifest, err := syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, nil))
	if err != nil {
		return crypto.ContentKey{}, err
	}
	sealed, refs, err := syncengine.SealTree(manifest, crypto.DeriveConvergenceKey(mk), nil)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	// The recomputed root must reproduce the stored one: a mismatch means the walk
	// and the sealer disagree, and PUTting the recomputed refs could orphan live
	// objects. Refuse rather than risk the folder's object graph.
	if sealed.Root.ID != root.Root.ID {
		return crypto.ContentKey{}, fmt.Errorf("recomputed tree root %s does not match stored root %s; not rotating", sealed.Root.ID, root.Root.ID)
	}

	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return crypto.ContentKey{}, err
	}
	blob, err := syncengine.SealTreeRoot(root, newCK, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	if _, err := cl.PutResource(api.PutResourceRequest{
		ID:              id,
		Visibility:      api.Private,
		Blob:            blob,
		EncryptedMeta:   metaBlob,
		WrappedKey:      &wrapped,
		ChunkRefs:       refs,
		ExpectedVersion: res.Version,
		RevokeGrantee:   revoke,
		MinClient:       api.CapabilityIDBinding, // SealTreeRoot re-seals the root id-bound (v2)
	}); err != nil {
		newCK.Wipe()
		if errors.Is(err, client.ErrConflict) {
			return crypto.ContentKey{}, errors.New("resource changed while rotating its key; re-run `aqt private`")
		}
		return crypto.ContentKey{}, err
	}
	return newCK, nil
}

func rotateStreamed(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	root, err := syncengine.OpenFileRoot(res.Blob, oldCK, id)
	if err != nil {
		return crypto.ContentKey{}, fmt.Errorf("decrypt: %w", err)
	}
	// Recover the full content chunk records so ChunkRefs mirrors what BuildFileRoot
	// produced at push time; an indirect root's list segments sit behind their own
	// locate, so fetch them through the authed path first.
	chunks := root.Chunks
	if root.Indirect() {
		segSrc, err := newPackSource(cl, root.ChunkIDs())
		if err != nil {
			return crypto.ContentKey{}, err
		}
		chunks, err = root.Resolve(segSrc.get)
		if err != nil {
			return crypto.ContentKey{}, err
		}
	}
	refs := root.Refs(chunks)

	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return crypto.ContentKey{}, err
	}
	// SealFileRoot binds the root to the id even if the original create was unbound.
	blob, err := syncengine.SealFileRoot(root, newCK, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		newCK.Wipe()
		return crypto.ContentKey{}, err
	}
	if _, err := cl.PutResource(api.PutResourceRequest{
		ID:              id,
		Visibility:      api.Private,
		Blob:            blob,
		EncryptedMeta:   metaBlob,
		WrappedKey:      &wrapped,
		ChunkRefs:       refs,
		ExpectedVersion: res.Version,
		RevokeGrantee:   revoke,
		MinClient:       api.CapabilityIDBinding, // SealFileRoot re-seals the root id-bound (v2)
	}); err != nil {
		newCK.Wipe()
		if errors.Is(err, client.ErrConflict) {
			return crypto.ContentKey{}, errors.New("resource changed while rotating its key; re-run `aqt private`")
		}
		return crypto.ContentKey{}, err
	}
	return newCK, nil
}
