// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/packio"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func (app *application) shareCmd() *cobra.Command {
	var (
		pw       passwordFlags
		noClip   bool
		expire   string
		maxReads int64
		burn     bool
		with     string
	)
	cmd := &cobra.Command{
		Use:   "share <name-or-id|tracked-path>",
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
			if with != "" {
				if policy.requested() || password != "" {
					return errors.New("link flags (--password/--expire/--max-reads/--burn) do not apply to account grants")
				}
				return app.runShareWith(args[0], with)
			}
			return app.runShare(args[0], password, noClip, policy)
		},
	}
	pw.bind(cmd, "password-gate the share link")
	cmd.Flags().BoolVar(&noClip, "no-clip", false, "do not copy the link to the clipboard")
	cmd.Flags().StringVar(&expire, "expire", "", "expire the link after a duration (e.g. 30m, 24h, 7d)")
	cmd.Flags().Int64Var(&maxReads, "max-reads", 0, "expire the link after this many downloads")
	cmd.Flags().BoolVar(&burn, "burn", false, "burn after reading (shorthand for --max-reads 1)")
	cmd.Flags().StringVar(&with, "with", "", "grant read-only access to a specific account by email (no public link)")
	cmd.AddCommand(app.shareLsCmd())
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}

// shareLsCmd answers "who has access?": every public link and outgoing grant, per
// resource, with the lifecycle policy the server reports for the link.
func (app *application) shareLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls [<id>]",
		Short: "List outgoing access: public links and account grants, per resource",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := ""
			if len(args) == 1 {
				ref = args[0]
			}
			return app.runShareList(ref)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

// shareListRow is one resource with outgoing access, as shown by `aqt share ls`.
type shareListRow struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Kind     string   `json:"kind,omitempty"`
	Public   bool     `json:"public"`
	Policy   string   `json:"policy,omitempty"` // human summary of the link lifecycle
	Grantees []string `json:"grantees,omitempty"`
}

func (app *application) runShareList(ref string) error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	items, err := cl.ListResources()
	if err != nil {
		return err
	}
	if ref != "" {
		id, _, _ := parseRef(ref)
		filtered := items[:0]
		for _, it := range items {
			if it.ID == id {
				filtered = append(filtered, it)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("resource %s not found (or not yours)", id)
		}
		items = filtered
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	self := crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey)
	// Grantee handles are opaque; the contact pins map them back to emails where
	// this device knows them.
	emailByHandle := map[string]string{}
	if pins, err := identity.LoadContacts(prof.Name); err == nil {
		for _, c := range pins {
			emailByHandle[c.Handle] = c.Email
		}
	}

	var rows []shareListRow
	anyUnsigned := false
	for _, it := range items {
		// The list endpoint echoes each resource's grant count, so the common
		// case — a private resource never shared — costs no grant fetch.
		if it.Visibility != api.Public && it.GrantCount == 0 {
			continue
		}
		var grants []api.GrantEntry
		if it.GrantCount > 0 {
			grants, err = cl.ListGrants(it.ID)
			if err != nil {
				return fmt.Errorf("list grants of %s: %w", it.ID, err)
			}
		}
		if it.Visibility != api.Public && len(grants) == 0 {
			continue
		}
		name := "(unreadable)"
		kind := ""
		if m, ok := openMetadata(it, mk); ok {
			name, kind = m.Name, m.Kind
		}
		row := shareListRow{ID: it.ID, Name: name, Kind: kind, Public: it.Visibility == api.Public}
		if row.Public {
			row.Policy = linkPolicySummary(it)
		}
		var ck crypto.ContentKey
		if it.WrappedKey != nil {
			ck, _ = crypto.UnwrapKey(*it.WrappedKey, [crypto.KeySize]byte(mk))
		}
		for _, g := range grants {
			label := g.GranteeHandle
			if email, ok := emailByHandle[g.GranteeHandle]; ok {
				label = email
			}
			if !crypto.VerifyGrant(self, g.Signature, ck, it.ID, prof.OwnerHandle, g.GranteeHandle) {
				label += " (unsigned)"
				anyUnsigned = true
			}
			row.Grantees = append(row.Grantees, label)
		}
		ck.Wipe()
		rows = append(rows, row)
	}
	if app.json {
		if rows == nil {
			rows = []shareListRow{}
		}
		return printJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Println("nothing shared; `aqt share <id>` mints a link, `aqt share <id> --with <email>` grants an account")
		return nil
	}
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		access := "grant-only"
		if r.Public {
			access = "public link"
			if r.Policy != "" {
				access += " (" + r.Policy + ")"
			}
		}
		grantees := "-"
		if len(r.Grantees) > 0 {
			grantees = strings.Join(r.Grantees, ", ")
		}
		cells = append(cells, []string{r.Name, access, grantees, r.ID})
	}
	if err := printTable(os.Stdout, []string{"NAME", "ACCESS", "GRANTED-TO", "ID"}, cells); err != nil {
		return err
	}
	if anyUnsigned {
		fmt.Fprintln(os.Stderr, "an (unsigned) grantee holds no grant you signed for the current key: a share from before grants were signed, one left on an older key, or a row the server added. "+
			"It does not open for them; if you meant to share it, run `aqt share <id> --with <email>` again")
	}
	return nil
}

// linkPolicySummary renders the server-reported link lifecycle for one listed
// resource ("expires 2026-07-20 14:00, 3/10 reads"), or "" when the link has none.
func linkPolicySummary(it api.ResourceListItem) string {
	var parts []string
	if it.ExpiresAt > 0 {
		parts = append(parts, "expires "+cliutil.FormatUnix(it.ExpiresAt))
	}
	if it.MaxReads > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d reads", it.Reads, it.MaxReads))
	}
	return strings.Join(parts, ", ")
}

func (app *application) unshareCmd() *cobra.Command {
	var (
		with string
		yes  bool
	)
	cmd := &cobra.Command{
		Use:   "unshare <name-or-id|tracked-path>",
		Short: "Take back access: kill the public link (rotates the key), or revoke one grant (--with)",
		Long: "Bare `aqt unshare <id>` makes the resource private again and ROTATES its content\n" +
			"key, so every link ever issued for it stops decrypting. With --with <email> it\n" +
			"revokes that account's grant instead, and rotates the key the same way, so the\n" +
			"revoked wrap opens nothing that changes from here on. Either way it lists the\n" +
			"grantees the new key is re-wrapped for, and the grants it leaves behind, before\n" +
			"asking.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireConfirmable(yes); err != nil {
				return err
			}
			if with != "" {
				return app.runShareRevoke(args[0], with, yes)
			}
			return app.runPrivate(args[0], yes)
		},
	}
	cmd.Flags().StringVar(&with, "with", "", "revoke this account's grant (by email) instead of the public link")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
	return cmd
}

// shareScopeRefs recomputes the read scope the share operation must carry: the
// stored refs are stale or absent (private pushes omit them), so the operation
// that mints a reader supplies the current set. A scope that cannot be recomputed
// fails the share — minting a reader against a stale scope would hand them a
// folder they cannot fetch.
func shareScopeRefs(cl *client.Client, res api.GetResourceResponse, keys *resourceKeys, id string) ([]string, error) {
	conv := crypto.DeriveConvergenceKey(keys.mk)
	defer conv.Wipe()
	refs, err := closureRefs(cl, res.Blob, keys.ck, id, keys.meta, conv)
	if err != nil {
		return nil, fmt.Errorf("recomputing the folder's object set failed (%w); run `aqt sync` in the folder, then retry", err)
	}
	return refs, nil
}

// checkShareableFolder rejects the folder format no non-owner transport can serve.
// A link holder and a grantee both read exact object slices, so they need a folder
// whose entries ARE objects: a legacy folder predates the tree format entirely, so
// it can neither be walked with only the content key nor rotated. A non-folder
// passes untouched.
func checkShareableFolder(meta api.Metadata) error {
	if meta.Kind != api.KindFolder {
		return nil
	}
	return requireTreeFolder(meta)
}

// runShareWith grants one account read-only access: the resource's content key is
// HPKE-wrapped to the grantee's published enc key, bound to (resource, owner,
// grantee), and stored server-side as an opaque blob. Visibility is untouched —
// a grant is not a link.
func (app *application) runShareWith(idArg, email string) error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	id, err := app.resolveOwnedResourceIDWithProfile(cl, prof, idArg)
	if err != nil {
		return err
	}

	res, err := fetchResource(cl, id)
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("no owner key stored for this resource; only resources you own can be granted")
	}
	keys, err := app.openResourceKeys(prof, res)
	if err != nil {
		return err
	}
	defer keys.close()
	if err := checkShareableFolder(keys.meta); err != nil {
		return err
	}
	contact, repair, err := lookupGrantee(cl, prof, keys.mk, email)
	if err != nil {
		return err
	}
	if contact.Handle == prof.OwnerHandle {
		return errors.New("cannot grant a resource to your own account")
	}
	if err := grantResource(cl, prof, id, res, keys, contact); err != nil {
		return err
	}
	if err := identity.ClearRevokedGrant(prof.Name, id, contact.Handle); err != nil {
		return fmt.Errorf("granted %s access to aqt://%s, but forgetting the earlier revoke on this device failed, so its rotations still leave them behind: %w", email, id, err)
	}
	if repair != nil {
		if err := repin(cl, prof, keys.mk, *repair, contact, id); err != nil {
			return err
		}
	}
	if app.json {
		return printJSON(map[string]any{"id": id, "granted": email})
	}
	if app.quiet {
		fmt.Printf("aqt://%s\n", id)
		return nil
	}
	fmt.Printf("granted %s read-only access to aqt://%s\n", email, id)
	fmt.Fprintln(os.Stderr, "they will see it under `aqt shares` and can pull or clone it; they cannot modify it")
	return nil
}

// grantResource wraps a resource's content key to one contact, bound to (resource,
// owner, grantee), signs the grant, and stores both with the read scope the grantee
// will fetch through. keys must be the resource's own, opened from res.
func grantResource(cl *client.Client, prof *identity.Profile, id string, res api.GetResourceResponse, keys *resourceKeys, contact identity.Contact) error {
	wrap, err := crypto.WrapGrant(keys.ck, contact.EncPublicKey, id, prof.OwnerHandle, contact.Handle)
	if err != nil {
		return err
	}
	scope, err := shareScopeRefs(cl, res, keys, id)
	if err != nil {
		return err
	}
	err = cl.CreateGrant(id, api.CreateGrantRequest{
		GranteeHandle: contact.Handle, WrappedKey: wrap, ChunkRefs: scope, ExpectedVersion: res.Version,
		Signature:    crypto.SignGrant(crypto.DeriveSigningKey(keys.mk), keys.ck, id, prof.OwnerHandle, contact.Handle),
		GranteeEmail: contact.Email, GranteeEncPublicKey: contact.EncPublicKey,
	})
	if errors.Is(err, client.ErrSenderBlocked) {
		// A recipient-side block. Nothing about the grant can be fixed to get past it,
		// so say who declined rather than leaving it as a bare 403.
		return fmt.Errorf("%s is not accepting shares from your account: %w", contact.Email, err)
	}
	return err
}

// regrantOwned is grantResource for a resource the caller has not opened yet, under
// a master key it already holds.
func regrantOwned(cl *client.Client, prof *identity.Profile, mk crypto.MasterKey, id string, contact identity.Contact) error {
	res, err := fetchResource(cl, id)
	if err != nil {
		return err
	}
	owned, err := openOwnedResource(res, mk)
	if err != nil {
		return err
	}
	defer owned.ck.Wipe()
	if err := checkShareableFolder(owned.meta); err != nil {
		return err
	}
	// Not closed: mk belongs to the caller.
	keys := &resourceKeys{mk: mk, ck: owned.ck, meta: owned.meta}
	return grantResource(cl, prof, id, res, keys, contact)
}

// runShareRevoke rotates the content key so the revoked wrap opens nothing that changes
// from here on, dropping the grant in the same transaction, then re-wraps for the
// remaining grantees. Every revoke rotates, a public resource's included, which makes it
// private: the revoked grant's signature covers the key it was made over, so a revoke
// that left that key in place would leave the grant valid for it, and the next rotation,
// from any device, would follow it and hand the revoked account the new key. Only a
// public resource with no owner key revokes without rotating, since nothing can ever
// rotate it.
//
// The rotation and the delete are one server-side write because every way of splitting
// them fails badly. Deleting first and then failing to rotate strands the revoked account
// with a working key and destroys the retry's only evidence that anything is left to do —
// the re-run reports "no grant" and stops, with forward secrecy quietly broken. Rotating
// first and then failing to delete leaves the revoked account listed as a grantee holding
// a stale wrap, and the next rotation's re-wrap hands it the new key. Together, they
// either both land or neither does, and a failure is a clean no-op the user can re-run.
func (app *application) runShareRevoke(idArg, email string, yes bool) error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	id, err := app.resolveOwnedResourceIDWithProfile(cl, prof, idArg)
	if err != nil {
		return err
	}

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
	if res.WrappedKey == nil {
		// Only a public resource can lack an owner key: the server refuses a private
		// write without one. A private resource reported without one would have the
		// revoke delete the grant row and leave its signature valid for the key the
		// resource still has, for the next rotation to follow.
		if res.Visibility != api.Public {
			return fmt.Errorf("the server reports no owner key for the private resource aqt://%s, which it never stores, so %s was not revoked: "+
				"deleting the grant without rotating the key would leave it valid for a later rotation to follow. Run the revoke again; if this persists, the server is misreporting the resource", id, email)
		}
		if err := confirmDestructive(fmt.Sprintf("Revoke %s's access to aqt://%s? It has no owner key, so its key cannot be rotated. [y/N] ", email, id), yes); err != nil {
			return err
		}
		if err := recordRevoke(prof, id, handle, email); err != nil {
			return err
		}
		if err := cl.RevokeGrant(id, handle); err != nil {
			return fmt.Errorf("deleting the grant for %s failed: %w", email, err)
		}
		if app.json {
			return printJSON(map[string]any{"id": id, "revoked": email, "rotated": false, "accessRemoved": false})
		}
		fmt.Printf("revoked %s from aqt://%s (no owner key; content key not rotated)\n", email, id)
		fmt.Fprintln(os.Stderr, "the resource is public, so anyone with its link, them included, can still read it")
		return nil
	}
	keys, err := app.openResourceKeys(prof, res)
	if err != nil {
		return err
	}
	defer keys.close()
	plan, err := planRewrap(cl, prof, id, keys, grants, handle)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, plan.describe())
	question := fmt.Sprintf("Revoke %s's access to %s and rotate its key? [y/N] ", email, keys.label(id))
	if res.Visibility == api.Public {
		question = fmt.Sprintf("Revoke %s's access to %s? It is public, so this also makes it private and rotates its key: every link ever issued for it stops working. [y/N] ", email, keys.label(id))
	}
	if err := confirmDestructive(question, yes); err != nil {
		return err
	}
	if err := recordRevoke(prof, id, handle, email); err != nil {
		return err
	}
	newCK, err := rotateResourceKey(cl, id, res, keys.ck, keys.mk, keys.meta, handle)
	if errors.Is(err, errTreeRootDrift) {
		if clearErr := identity.ClearRevokedGrant(prof.Name, id, handle); clearErr != nil {
			err = errors.Join(err, fmt.Errorf("forgetting the revoke this device recorded failed, so its rotations leave %s behind until you share with them again: %w", email, clearErr))
		}
		return fmt.Errorf("revoking %s needs the key of aqt://%s rotated, and it cannot be yet (%w). "+
			"Deleting the grant without rotating would leave it valid for the current key, so a later rotation could hand %s the new one. "+
			"Nothing was changed: run `aqt sync` in the folder to re-seal it under your current account key, then revoke again", email, id, err, email)
	}
	if err != nil {
		// The rotate+revoke is one PUT, but a lost response leaves its outcome unknown:
		// it may have committed. Do not claim it did not. Forward secrecy is safe either
		// way: a committed write cut the grantee off, a failed one never rotated. A
		// committed-then-lost write leaves the remaining grantees on the old key, though,
		// and no later rotation re-wraps them, since their signatures cover that key.
		return fmt.Errorf("revoking %s failed (%w), and the server may have applied it anyway. "+
			"Run `aqt unshare %s --with %s` again: if it finds no grant for them, the revoke went through, and `aqt share ls` marks each grant it did not re-wrap (unsigned); "+
			"share each of those again with `aqt share %s --with <email>`", email, err, id, email, id)
	}
	defer newCK.Wipe()
	reportUnfollowed(id, append(plan.left, plan.rewrap(cl, prof, id, keys, newCK)...))
	if app.json {
		return printJSON(map[string]any{"id": id, "revoked": email, "rotated": true})
	}
	if res.Visibility == api.Public {
		fmt.Printf("revoked %s from aqt://%s, made it private, and rotated the content key\n", email, id)
		return nil
	}
	fmt.Printf("revoked %s from aqt://%s and rotated the content key\n", email, id)
	return nil
}

// recordRevoke notes the revoke on this device before anything reaches the server, so
// a lost response or a later rollback never leaves a grant this device's rotations
// would follow again.
func recordRevoke(prof *identity.Profile, id, handle, email string) error {
	if err := identity.RecordRevokedGrant(prof.Name, id, handle); err != nil {
		return fmt.Errorf("recording the revoke of %s on this device failed, so nothing was revoked: %w", email, err)
	}
	return nil
}

func (app *application) runShare(idArg, password string, noClip bool, policy linkPolicy) error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	id, err := app.resolveOwnedResourceIDWithProfile(cl, prof, idArg)
	if err != nil {
		return err
	}

	res, err := fetchResource(cl, id)
	if err != nil {
		return err
	}
	// Sharing exposes the existing content key in the link; it does not
	// re-encrypt. Recovering that key needs the owner's wrapped key.
	if res.WrappedKey == nil {
		return errors.New("no owner key stored for this resource (it was pushed --public); use the share link from that push")
	}
	// Opening the keys sanity-checks the unwrapped key before flipping visibility.
	keys, err := app.openResourceKeys(prof, res)
	if err != nil {
		return err
	}
	defer keys.close()
	// A chunked folder shares like a streamed file: its nodes and chunks are already
	// the resource's referenced object set, so the public endpoint serves them and
	// the fragment key opens the tree root.
	if err := checkShareableFolder(keys.meta); err != nil {
		return err
	}
	// Always call SetVisibility when a policy is requested, even if the resource is
	// already public, so the policy is applied (and the read counter reset). A plain
	// re-share of an already-public resource still skips the call.
	wasPublic := res.Visibility == api.Public
	if !wasPublic || policy.requested() {
		scope, err := shareScopeRefs(cl, res, keys, id)
		if err != nil {
			return err
		}
		resp, err := cl.SetVisibility(id, api.SetVisibilityRequest{
			Visibility:    api.Public,
			ExpireSeconds: policy.expireSeconds,
			MaxReads:      policy.maxReads,
			OnExpiry:      policy.onExpiry,
			ChunkRefs:     scope,
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
				//nolint:errorlint // secondary cleanup error must not reach exitCode
				return fmt.Errorf("%w; additionally, clearing the policy this attempt stored failed (%v) — the link may still expire destructively, so run `aqt unshare %s` to rotate the key and drop the policy", err, undo, id)
			}
			return err
		}
	}
	ref, err := buildRef(prof.Server, id, api.Public, keys.ck, password)
	if err != nil {
		return err
	}

	if app.json {
		out := map[string]any{"id": id, "url": ref, "visibility": string(api.Public)}
		if policy.expireSeconds > 0 {
			out["expireSeconds"] = policy.expireSeconds
		}
		if policy.maxReads > 0 {
			out["maxReads"] = policy.maxReads
		}
		return printJSON(out)
	}
	fmt.Println(ref)
	// -q leaves the link as the only output, the way push's quiet path does: no
	// clipboard detour, no lifecycle note.
	if app.quiet {
		return nil
	}
	if !noClip && copyToClipboard(ref) {
		fmt.Fprintln(os.Stderr, "(copied to clipboard)")
	}
	if policy.requested() {
		// Expiry takes the link down without rotating the content key (the server has no
		// key to rotate with), so the fragment above still opens the resource if it is
		// ever made public again. Only a rotation kills a link for good.
		fmt.Fprintln(os.Stderr, "when this link expires the resource stays and only the link goes down; `aqt unshare "+id+"` rotates the key, which kills every link ever issued for it")
	}
	return nil
}

func (app *application) runPrivate(idArg string, yes bool) error {
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	id, err := app.resolveOwnedResourceIDWithProfile(cl, prof, idArg)
	if err != nil {
		return err
	}

	res, err := fetchResource(cl, id)
	if err != nil {
		return err
	}
	if res.WrappedKey == nil {
		return errors.New("no owner key stored for this resource; cannot rotate it")
	}
	keys, err := app.openResourceKeys(prof, res)
	if err != nil {
		return err
	}
	defer keys.close()
	if err := checkShareableFolder(keys.meta); err != nil {
		return err
	}
	grants, err := cl.ListGrants(id)
	if err != nil {
		return fmt.Errorf("list the grants of aqt://%s to re-wrap them: %w", id, err)
	}
	plan, err := planRewrap(cl, prof, id, keys, grants, "")
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, plan.describe())
	if err := confirmDestructive(fmt.Sprintf("Make %s private and rotate its key? Every link ever issued for it stops working. [y/N] ", keys.label(id)), yes); err != nil {
		return err
	}
	newCK, err := rotateResourceKey(cl, id, res, keys.ck, keys.mk, keys.meta, "")
	if errors.Is(err, errTreeRootDrift) {
		// Killing the link must not depend on being able to re-seal the tree.
		if visErr := revokeWithoutRotation(cl, id, res.Version); visErr != nil {
			return visErr
		}
		if app.json {
			return printJSON(map[string]any{"id": id, "ref": "aqt://" + id, "rotated": false})
		}
		fmt.Println("aqt://" + id)
		fmt.Fprintf(os.Stderr, "link revoked: %s is private again and no longer serves to link holders\n", id)
		fmt.Fprintf(os.Stderr, "warning: its content key was NOT rotated (%v); anyone who saved the old link can still decrypt bytes they already fetched\n", err)
		fmt.Fprintf(os.Stderr, "run `aqt sync` in the folder to re-seal it under the current account key, then re-run `aqt unshare %s` to rotate\n", id)
		return nil
	}
	if err != nil {
		// As in a revoke, a lost response leaves the rotation's outcome unknown, and a
		// committed one left every grant on the old key, where no later rotation finds it.
		return fmt.Errorf("rotating the key of aqt://%s failed (%w), and the server may have applied it anyway. "+
			"Run `aqt unshare %s` again, which is safe either way. If the first rotation went through, it left its grants on the old key, and `aqt share ls %s` marks them (unsigned): "+
			"share each one you meant to keep again with `aqt share %s --with <email>`", id, err, id, id, id)
	}
	defer newCK.Wipe()
	reportUnfollowed(id, append(plan.left, plan.rewrap(cl, prof, id, keys, newCK)...))

	if app.json {
		return printJSON(map[string]any{"id": id, "ref": "aqt://" + id, "rotated": true})
	}
	fmt.Println("aqt://" + id)
	fmt.Fprintln(os.Stderr, "rotated content key — any previous public link no longer decrypts")
	return nil
}

// errTreeRootDrift means a folder's directory nodes can no longer be reproduced
// from the account's current convergence key, so its root cannot be re-sealed. The
// ordinary cause is `aqt passphrase rotate-root`: the convergence key derives from
// the root key, so every node id a pre-rotation folder stored is unreachable until
// the next sync re-seals the tree. Killing a link must not depend on that having
// happened (see revokeWithoutRotation); revoking a grant does, since only a rotation
// stops a later one from following the revoked grant.
var errTreeRootDrift = errors.New("folder tree cannot be re-sealed under the current account key")

// revokeWithoutRotation is the fallback when the content key cannot be rotated: flip
// the resource private, which is what actually severs an unauthenticated link. It
// leaves anyone who saved the old fragment key able to decrypt bytes they already
// fetched, so callers say so, but a link that still serves is strictly worse, and
// refusing outright left one live.
func revokeWithoutRotation(cl *client.Client, id string, version int) error {
	_, err := cl.SetVisibility(id, api.SetVisibilityRequest{
		Visibility: api.Private, ExpectedVersion: version,
	})
	return err
}

// fetchResource gets a resource by id, reporting a miss in terms of the id the caller
// resolved rather than as a bare transport error.
func fetchResource(cl *client.Client, id string) (api.GetResourceResponse, error) {
	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return res, fmt.Errorf("resource %s not found", id)
	}
	return res, err
}

// resourceKeys holds the unlocked keys and the metadata they open for one resource.
// close wipes both keys; callers defer it.
type resourceKeys struct {
	mk   crypto.MasterKey
	ck   crypto.ContentKey
	meta api.Metadata
}

func (k *resourceKeys) close() {
	k.ck.Wipe()
	k.mk.Wipe()
}

// label names the resource the keys open the way a prompt shows it.
func (k *resourceKeys) label(id string) string {
	if k.meta.Name == "" {
		return id
	}
	return fmt.Sprintf("%s (%s)", k.meta.Name, id)
}

// openResourceKeys unlocks the profile's master key and opens the resource under it —
// the prologue every owner-side share operation runs.
//
// Callers report a missing owner key themselves before calling: what its absence means
// differs per command, and for a revoke it is not an error at all.
//
// Both keys are wiped if any step fails, so a caller only ever receives keys it owns.
func (app *application) openResourceKeys(prof *identity.Profile, res api.GetResourceResponse) (_ *resourceKeys, err error) {
	k := &resourceKeys{}
	defer func() {
		if err != nil {
			k.close()
		}
	}()
	if k.mk, err = app.unlockMaster(prof); err != nil {
		return nil, err
	}
	owned, err := openOwnedResource(res, k.mk)
	if err != nil {
		return nil, err
	}
	k.ck, k.meta = owned.ck, owned.meta
	return k, nil
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
		if !meta.Tree {
			return crypto.ContentKey{}, errors.New("this folder format cannot rotate its key")
		}
		return rotateTree(cl, id, res, oldCK, mk, revoke)
	}
	if meta.Streamed {
		return rotateStreamed(cl, id, res, oldCK, mk, revoke)
	}
	return rotateInline(cl, id, res, oldCK, mk, revoke)
}

// rewrapPlan is who a rotation re-wraps the new key for, worked out before the key is
// replaced so the owner sees it first. follow holds the grantees this account signed a
// grant to over the key being replaced, pinned on this device with keys the server
// still publishes; left holds every other listed grant, with why it is not followed.
//
// The server chooses which grants it lists, so a signature over the replaced key is
// what lets one through. Otherwise a hostile server could list any pinned contact on
// any resource and have the new key handed to them. A signature over an earlier key
// does not count either: that grant was revoked, or an earlier rotation could not
// re-wrap it, and both cases are left for the owner to share again.
type rewrapPlan struct {
	follow []identity.Contact
	left   []unfollowedGrant
}

// unfollowedGrant is a listed grant a rotation leaves on the old key, so that it stops
// opening, and why.
type unfollowedGrant struct{ grantee, reason string }

// planRewrap sorts a resource's listed grants into the ones a rotation away from
// old.ck re-wraps and the ones it leaves. exclude is a handle being revoked in the same
// rotation, left out entirely. A grantee pinned on another device is left: only a
// device that looked them up holds their key. So is one this device revoked, even when
// the key the server served is the one that grant was signed over.
func planRewrap(cl *client.Client, prof *identity.Profile, id string, old *resourceKeys, grants []api.GrantEntry, exclude string) (rewrapPlan, error) {
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return rewrapPlan{}, fmt.Errorf("load contacts to re-wrap grants: %w", err)
	}
	revoked, err := identity.LoadRevokedGrants(prof.Name)
	if err != nil {
		return rewrapPlan{}, fmt.Errorf("load the grants this device revoked: %w", err)
	}
	byHandle := make(map[string]identity.Contact, len(pins))
	for _, c := range pins {
		byHandle[c.Handle] = c
	}
	self := crypto.DeriveSigningKey(old.mk).Public().(ed25519.PublicKey)
	var plan rewrapPlan
	for _, g := range grants {
		if g.GranteeHandle == exclude {
			continue
		}
		pin, pinned := byHandle[g.GranteeHandle]
		label := foreignText(g.GranteeHandle)
		if pinned {
			label = pinnedLabel(pin.Email, crypto.KeyFingerprint(pin.PublicKey), pin.Verified)
		}
		if slices.Contains(revoked, identity.RevokedGrant{ResourceID: id, GranteeHandle: g.GranteeHandle}) {
			plan.left = append(plan.left, unfollowedGrant{label, "revoked from this device"})
			continue
		}
		if !crypto.VerifyGrant(self, g.Signature, old.ck, id, prof.OwnerHandle, g.GranteeHandle) {
			plan.left = append(plan.left, unfollowedGrant{label, "holds no grant you signed over the current key (made before grants were signed, left on an older key, or added by the server)"})
			continue
		}
		if !pinned {
			plan.left = append(plan.left, unfollowedGrant{label, "not pinned on this device"})
			continue
		}
		// Re-verify the pin against the server's current keys, exactly as a fresh
		// share does. Wrapping to the stored pin blindly means a grantee who rotated
		// their own root key gets their working wrap silently overwritten with a dead
		// one by an unrelated revocation — permanently, since nothing re-checks later.
		current, err := confirmPinnedKeys(cl, prof.Name, pin)
		if err != nil {
			plan.left = append(plan.left, unfollowedGrant{label, err.Error()})
			continue
		}
		plan.follow = append(plan.follow, current)
	}
	return plan, nil
}

// describe lists who the plan re-wraps the new key for and which grants it leaves, for
// the owner to read before confirming the rotation.
func (p rewrapPlan) describe() string {
	var b strings.Builder
	if len(p.follow) > 0 {
		b.WriteString("the new key will be re-wrapped for:\n")
		for _, c := range p.follow {
			fmt.Fprintf(&b, "  %s\n", pinnedLabel(c.Email, crypto.KeyFingerprint(c.PublicKey), c.Verified))
		}
	}
	if len(p.left) > 0 {
		b.WriteString("these grants stay on the old key and stop opening:\n")
		for _, g := range p.left {
			fmt.Fprintf(&b, "  %s: %s\n", g.grantee, g.reason)
		}
	}
	return b.String()
}

// rewrap wraps newCK to every grantee the plan follows and signs each grant over it,
// returning the ones it could not write.
func (p rewrapPlan) rewrap(cl *client.Client, prof *identity.Profile, id string, old *resourceKeys, newCK crypto.ContentKey) []unfollowedGrant {
	signing := crypto.DeriveSigningKey(old.mk)
	var failed []unfollowedGrant
	for _, pin := range p.follow {
		wrap, err := crypto.WrapGrant(newCK, pin.EncPublicKey, id, prof.OwnerHandle, pin.Handle)
		if err == nil {
			err = cl.CreateGrant(id, api.CreateGrantRequest{
				GranteeHandle: pin.Handle, WrappedKey: wrap,
				Signature:    crypto.SignGrant(signing, newCK, id, prof.OwnerHandle, pin.Handle),
				GranteeEmail: pin.Email, GranteeEncPublicKey: pin.EncPublicKey,
			})
		}
		if err != nil {
			label := pinnedLabel(pin.Email, crypto.KeyFingerprint(pin.PublicKey), pin.Verified)
			failed = append(failed, unfollowedGrant{label, fmt.Sprintf("re-wrapping failed: %v", err)})
		}
	}
	return failed
}

// reportUnfollowed names each grant a rotation left on the old key. Nothing re-wraps
// one later: its signature covers the replaced key, so the next rotation does not
// follow it either, and only sharing again puts its grantee on the new key.
func reportUnfollowed(id string, left []unfollowedGrant) {
	if len(left) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: these grants on aqt://%s were not re-wrapped and no longer open it:\n", id)
	for _, g := range left {
		fmt.Fprintf(os.Stderr, "  %s: %s\n", g.grantee, g.reason)
	}
	fmt.Fprintf(os.Stderr, "no later rotation re-wraps them; for each you meant to keep, run `aqt share %s --with <email>`\n", id)
}

// resealed is a resource's root re-sealed under a fresh content key, plus the GC
// roots that must accompany it on the re-PUT. refs is nil for an inline resource,
// which references no objects.
type resealed struct {
	blob crypto.SealedBlob
	refs []string
}

// rotateResource re-seals a resource under a fresh content key and flips it private,
// returning the new key for the caller to wipe. reseal supplies the format-specific
// part — the new root blob and GC roots; the metadata re-seal, the key wrap and the
// version-pinned PUT that follow are the same for every format.
//
// The new key is wiped on every failure path, so a caller only ever receives a key it
// owns. Optimistic concurrency: the rotate is a read-modify-write, so it pins the
// version fetched by the caller. A concurrent sync committing between that GET and
// this PUT would otherwise be silently overwritten with stale content.
func rotateResource(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string, reseal func(newCK crypto.ContentKey) (resealed, error)) (_ crypto.ContentKey, err error) {
	newCK, err := crypto.GenerateContentKey()
	if err != nil {
		return crypto.ContentKey{}, err
	}
	defer func() {
		if err != nil {
			newCK.Wipe()
		}
	}()

	sealed, err := reseal(newCK)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	metaPlain, err := crypto.OpenBound(res.EncryptedMeta, oldCK, crypto.AADMeta, id)
	if err != nil {
		return crypto.ContentKey{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	metaBlob, err := crypto.SealBound(metaPlain, newCK, crypto.AADMeta, id)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	wrapped, err := crypto.WrapKey(newCK, [crypto.KeySize]byte(mk))
	if err != nil {
		return crypto.ContentKey{}, err
	}
	if _, err = cl.PutResource(api.PutResourceRequest{
		ID:              id,
		Visibility:      api.Private,
		Blob:            sealed.blob,
		EncryptedMeta:   metaBlob,
		WrappedKey:      &wrapped,
		ChunkRefs:       sealed.refs,
		ExpectedVersion: res.Version,
		RevokeGrantee:   revoke,
		MinClient:       api.CapabilityIDBinding, // the reseal binds root and meta to the id (v2)
	}); err != nil {
		if errors.Is(err, client.ErrConflict) {
			err = errors.New("resource changed while rotating its key; re-run `aqt unshare`")
		}
		return crypto.ContentKey{}, err
	}
	return newCK, nil
}

// rotateInline rotates a small (inline) resource by re-encrypting body and
// metadata under a fresh content key.
func rotateInline(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	return rotateResource(cl, id, res, oldCK, mk, revoke, func(newCK crypto.ContentKey) (resealed, error) {
		plaintext, err := crypto.OpenBound(res.Blob, oldCK, crypto.AADBlob, id)
		if err != nil {
			return resealed{}, fmt.Errorf("decrypt: %w", err)
		}
		blob, err := crypto.SealBound(plaintext, newCK, crypto.AADBlob, id)
		if err != nil {
			return resealed{}, err
		}
		return resealed{blob: blob}, nil
	})
}

// rotateTree rotates a chunked folder's key the way rotateStreamed rotates a file's:
// only the TreeRoot blob and metadata are re-sealed under a fresh content key. The
// convergent directory nodes and chunk objects stay — their per-object keys derive
// from the account convergence key, which a link never carried — so the visibility
// flip plus a root the old key cannot open is what kills the link. The re-PUT must
// carry the resource's full GC roots; they are recomputed by re-sealing the tree in
// memory, which is deterministic under the convergence key.
func rotateTree(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	return rotateResource(cl, id, res, oldCK, mk, revoke, func(newCK crypto.ContentKey) (resealed, error) {
		root, err := syncengine.OpenTreeRoot(res.Blob, oldCK, id)
		if err != nil {
			return resealed{}, fmt.Errorf("decrypt folder root: %w", err)
		}
		manifest, err := syncengine.OpenTreeBatched(root, newBatchNodeFetcher(cl, nil))
		if err != nil {
			return resealed{}, err
		}
		sealedTree, refs, err := syncengine.SealTree(manifest, crypto.DeriveConvergenceKey(mk), nil, openSealMemo())
		if err != nil {
			return resealed{}, err
		}
		// The recomputed root must reproduce the stored one: a mismatch means the walk
		// and the sealer disagree, and PUTting the recomputed refs could orphan live
		// objects. Refuse rather than risk the folder's object graph.
		if sealedTree.Root.ID != root.Root.ID {
			return resealed{}, fmt.Errorf("%w: recomputed tree root %s does not match stored root %s", errTreeRootDrift, sealedTree.Root.ID, root.Root.ID)
		}
		blob, err := syncengine.SealTreeRoot(root, newCK, id)
		if err != nil {
			return resealed{}, err
		}
		return resealed{blob: blob, refs: refs}, nil
	})
}

// rotateStreamed rotates a streamed file's key by re-wrapping the ROOT under a fresh
// content key and flipping visibility back to private. The convergent chunk objects
// and their per-chunk keys are untouched: re-sealing the content would break dedup and
// re-upload the whole file, and an old link holder could have saved the plaintext
// anyway. Access revocation is enforced server-side by the visibility flip. The re-PUT
// must carry the resource's full ChunkRefs, since the server refuses a re-PUT that
// drops the GC roots of an object-backed resource.
func rotateStreamed(cl *client.Client, id string, res api.GetResourceResponse, oldCK crypto.ContentKey, mk crypto.MasterKey, revoke string) (crypto.ContentKey, error) {
	return rotateResource(cl, id, res, oldCK, mk, revoke, func(newCK crypto.ContentKey) (resealed, error) {
		root, err := syncengine.OpenFileRoot(res.Blob, oldCK, id)
		if err != nil {
			return resealed{}, fmt.Errorf("decrypt: %w", err)
		}
		// Recover the full content chunk records so ChunkRefs mirrors what BuildFileRoot
		// produced at push time; an indirect root's list segments sit behind their own
		// locate, so fetch them through the authed path first.
		chunks := root.Chunks
		if root.Indirect() {
			segSrc, err := packio.NewSource(cl, root.ChunkIDs())
			if err != nil {
				return resealed{}, err
			}
			chunks, err = root.Resolve(segSrc.Get)
			if err != nil {
				return resealed{}, err
			}
		}
		blob, err := syncengine.SealFileRoot(root, newCK, id)
		if err != nil {
			return resealed{}, err
		}
		return resealed{blob: blob, refs: root.Refs(chunks)}, nil
	})
}
