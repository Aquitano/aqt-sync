// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
	cmd.AddCommand(shareLsCmd())
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}

// shareLsCmd answers "who has access?": every public link and outgoing grant, per
// resource, with the lifecycle policy the server reports for the link.
func shareLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls [<id>]",
		Short: "List outgoing access: public links and account grants, per resource",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := ""
			if len(args) == 1 {
				ref = args[0]
			}
			return runShareList(ref)
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

func runShareList(ref string) error {
	cl, prof, err := authedClient()
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
	mk, err := unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()
	// Grantee handles are opaque; the contact pins map them back to emails where
	// this device knows them.
	emailByHandle := map[string]string{}
	if pins, err := identity.LoadContacts(prof.Name); err == nil {
		for _, c := range pins {
			emailByHandle[c.Handle] = c.Email
		}
	}

	var rows []shareListRow
	for _, it := range items {
		grants, err := cl.ListGrants(it.ID)
		if err != nil {
			return fmt.Errorf("list grants of %s: %w", it.ID, err)
		}
		if it.Visibility != api.Public && len(grants) == 0 {
			continue
		}
		name := "(unreadable)"
		kind := ""
		if m, ok := openMetadata(it, mk); ok {
			name, kind = m.Name, string(m.Kind)
		}
		row := shareListRow{ID: it.ID, Name: name, Kind: kind, Public: it.Visibility == api.Public}
		if row.Public {
			row.Policy = linkPolicySummary(it)
		}
		for _, g := range grants {
			label := g.GranteeHandle
			if email, ok := emailByHandle[g.GranteeHandle]; ok {
				label = email
			}
			row.Grantees = append(row.Grantees, label)
		}
		rows = append(rows, row)
	}
	if flagJSON {
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
	return printTable(os.Stdout, []string{"NAME", "ACCESS", "GRANTED-TO", "ID"}, cells)
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

func unshareCmd() *cobra.Command {
	var (
		with string
		yes  bool
	)
	cmd := &cobra.Command{
		Use:   "unshare <name-or-id|tracked-path>",
		Short: "Take back access: kill the public link (rotates the key), or revoke one grant (--with)",
		Long: "Bare `aqt unshare <id>` makes the resource private again and ROTATES its content\n" +
			"key, so every link ever issued for it stops decrypting. With --with <email> it\n" +
			"revokes that account's grant instead (also rotating the key on a private resource,\n" +
			"so the revoked wrap opens nothing that changes from here on).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireConfirmable(yes); err != nil {
				return err
			}
			// Resolve before confirming, so the prompt names the resource the key
			// rotation will actually hit rather than echoing the raw argument.
			cl, prof, err := authedClient()
			if err != nil {
				return err
			}
			mk, err := unlockMaster(prof)
			if err != nil {
				return err
			}
			items, err := cl.ListResources()
			if err != nil {
				mk.Wipe()
				return err
			}
			id, ok, err := trackedResourceID(args[0])
			if !ok {
				id, err = resolveOwnedResourceIDFromItems(items, mk, args[0])
			}
			if err != nil {
				mk.Wipe()
				return err
			}
			label := resourceLabel(items, mk, id)
			mk.Wipe()
			if with != "" {
				if err := confirmDestructive(fmt.Sprintf("Revoke %s's access to %s? [y/N] ", with, label), yes); err != nil {
					return err
				}
				return runShareRevoke(id, with)
			}
			if err := confirmDestructive(fmt.Sprintf("Make %s private and rotate its key? Every link ever issued for it stops working. [y/N] ", label), yes); err != nil {
				return err
			}
			return runPrivate(id)
		},
	}
	cmd.Flags().StringVar(&with, "with", "", "revoke this account's grant (by email) instead of the public link")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	markJSONSupported(cmd)
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
		return errors.New("cannot share a pack-and-seal folder (the format was removed): it stores no per-file objects, " +
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
	id, err := resolveOwnedResourceIDWithProfile(cl, prof, idArg)
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
	keys, err := openResourceKeys(prof, res, id)
	if err != nil {
		return err
	}
	defer keys.close()
	if err := checkShareableFolder(keys.meta); err != nil {
		return err
	}
	contact, err := lookupGrantee(cl, prof, email)
	if err != nil {
		return err
	}
	if contact.Handle == prof.OwnerHandle {
		return errors.New("cannot grant a resource to your own account")
	}
	wrap, err := crypto.WrapGrant(keys.ck, contact.EncPublicKey, id, prof.OwnerHandle, contact.Handle)
	if err != nil {
		return err
	}
	if err := cl.CreateGrant(id, api.CreateGrantRequest{GranteeHandle: contact.Handle, WrappedKey: wrap}); err != nil {
		if errors.Is(err, client.ErrSenderBlocked) {
			// A recipient-side block. Nothing about the grant can be fixed to get past it,
			// so say who declined rather than leaving it as a bare 403.
			return fmt.Errorf("%s is not accepting shares from your account: %w", email, err)
		}
		return err
	}
	if flagJSON {
		return printJSON(map[string]any{"id": id, "granted": email})
	}
	if flagQuiet {
		fmt.Printf("aqt://%s\n", id)
		return nil
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
	id, err := resolveOwnedResourceIDWithProfile(cl, prof, idArg)
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
	revoke := func() error {
		if err := cl.RevokeGrant(id, handle); err != nil {
			return fmt.Errorf("deleting the grant for %s failed: %w", email, err)
		}
		return nil
	}
	if res.Visibility == api.Public {
		// Dropping the grant changes nothing while the resource is public: the link
		// serves it to anyone unauthenticated, this account included. Say so on stdout —
		// reporting a bare "revoked" here reads as access removed when it is not.
		if err := revoke(); err != nil {
			return err
		}
		if flagJSON {
			return printJSON(map[string]any{"id": id, "revoked": email, "rotated": false, "accessRemoved": false})
		}
		fmt.Printf("removed %s's grant on aqt://%s, but did NOT remove their access: the resource is public\n", email, id)
		fmt.Fprintf(os.Stderr, "anyone with the link can still read it. Run `aqt unshare %s` to make it private and rotate the key.\n", id)
		return nil
	}
	if res.WrappedKey == nil {
		if err := revoke(); err != nil {
			return err
		}
		if flagJSON {
			return printJSON(map[string]any{"id": id, "revoked": email, "rotated": false})
		}
		fmt.Printf("revoked %s from aqt://%s (no owner key; content key not rotated)\n", email, id)
		return nil
	}
	keys, err := openResourceKeys(prof, res, id)
	if err != nil {
		return err
	}
	defer keys.close()
	newCK, err := rotateResourceKey(cl, id, res, keys.ck, keys.mk, keys.meta, handle)
	if errors.Is(err, errTreeRootDrift) {
		// The grant delete must still land; it is what actually cuts this grantee off
		// on a private resource.
		if visErr := revokeWithoutRotation(cl, id, res.Version, handle); visErr != nil {
			return fmt.Errorf("revoking %s failed: %w", email, visErr)
		}
		if flagJSON {
			return printJSON(map[string]any{"id": id, "revoked": email, "rotated": false, "accessRemoved": true})
		}
		fmt.Printf("revoked %s from aqt://%s\n", email, id)
		fmt.Fprintf(os.Stderr, "warning: the content key was NOT rotated (%v); %s cannot fetch it again, but can still decrypt bytes they already had\n", err, email)
		fmt.Fprintf(os.Stderr, "run `aqt sync` in the folder to re-seal it under the current account key, then `aqt unshare %s` to rotate\n", id)
		return nil
	}
	if err != nil {
		// The rotate+revoke is one PUT, but a lost response leaves its outcome unknown:
		// it may have committed. Do not claim it did not. Forward secrecy is safe either
		// way — a committed write cut the grantee off, a failed one never rotated — but a
		// committed-then-lost write can leave the surviving grantees split across two
		// keys. `aqt unshare` re-rotates and re-wraps every remaining grant, so it
		// reconciles them whatever happened here.
		return fmt.Errorf("revoking %s failed (%w); the revoke may not have taken effect — run `aqt unshare %s` to rotate the key and bring the remaining shares onto it", email, err, id)
	}
	defer newCK.Wipe()
	// The same write that rotated the key dropped the grant, but re-wrap from a fresh
	// list and skip the revoked handle anyway: a hostile server that ignored the delete
	// and keeps listing it would otherwise get us to hand it a wrap of the NEW key,
	// undoing the revocation the rotation just enforced.
	rewrapGrants(cl, prof, id, newCK, handle)
	if flagJSON {
		return printJSON(map[string]any{"id": id, "revoked": email, "rotated": true})
	}
	fmt.Printf("revoked %s from aqt://%s and rotated the content key\n", email, id)
	return nil
}

func runShare(idArg, password string, noClip bool, policy linkPolicy) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	id, err := resolveOwnedResourceIDWithProfile(cl, prof, idArg)
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
	keys, err := openResourceKeys(prof, res, id)
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
				return fmt.Errorf("%w; additionally, clearing the policy this attempt stored failed (%v) — the link may still expire destructively, so run `aqt unshare %s` to rotate the key and drop the policy", err, undo, id)
			}
			return err
		}
	}
	ref, err := buildRef(prof.Server, id, api.Public, keys.ck, password)
	if err != nil {
		return err
	}

	if flagJSON {
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
	if flagQuiet {
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

func runPrivate(idArg string) error {
	cl, prof, err := authedClient()
	if err != nil {
		return err
	}
	id, err := resolveOwnedResourceIDWithProfile(cl, prof, idArg)
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
	keys, err := openResourceKeys(prof, res, id)
	if err != nil {
		return err
	}
	defer keys.close()
	if err := checkShareableFolder(keys.meta); err != nil {
		return err
	}
	newCK, err := rotateResourceKey(cl, id, res, keys.ck, keys.mk, keys.meta, "")
	if errors.Is(err, errTreeRootDrift) {
		// Killing the link must not depend on being able to re-seal the tree.
		if visErr := revokeWithoutRotation(cl, id, res.Version, ""); visErr != nil {
			return visErr
		}
		if flagJSON {
			return printJSON(map[string]any{"id": id, "ref": "aqt://" + id, "rotated": false})
		}
		fmt.Println("aqt://" + id)
		fmt.Fprintf(os.Stderr, "link revoked: %s is private again and no longer serves to link holders\n", id)
		fmt.Fprintf(os.Stderr, "warning: its content key was NOT rotated (%v); anyone who saved the old link can still decrypt bytes they already fetched\n", err)
		fmt.Fprintf(os.Stderr, "run `aqt sync` in the folder to re-seal it under the current account key, then re-run `aqt unshare %s` to rotate\n", id)
		return nil
	}
	if err != nil {
		return err
	}
	defer newCK.Wipe()
	rewrapGrants(cl, prof, id, newCK, "")

	if flagJSON {
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
// the next sync re-seals the tree. Revocation must not depend on that having
// happened — see revokeWithoutRotation.
var errTreeRootDrift = errors.New("folder tree cannot be re-sealed under the current account key")

// revokeWithoutRotation is the fallback when the content key cannot be rotated: flip
// the resource private, which is what actually severs an unauthenticated link, then
// drop the grant. It leaves anyone who saved the old fragment key able to decrypt
// bytes they already fetched, so callers say so — but a link that still serves is
// strictly worse, and refusing outright left one live.
//
// The flip goes first deliberately. These are two requests, not one, so either can be
// the last to land; ending with the resource private and a stale grant row is
// recoverable by re-running, whereas ending with the grant gone and the resource
// still public would have handed everyone the access the command was asked to remove.
func revokeWithoutRotation(cl *client.Client, id string, version int, revoke string) error {
	if _, err := cl.SetVisibility(id, api.SetVisibilityRequest{
		Visibility: api.Private, ExpectedVersion: version,
	}); err != nil {
		return err
	}
	if revoke == "" {
		return nil
	}
	return cl.RevokeGrant(id, revoke)
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

// openResourceKeys unlocks the profile's master key, unwraps the resource's content key
// with it, and decodes the metadata that key opens — the prologue every owner-side share
// operation runs. Decoding the metadata doubles as a check that the unwrapped key is the
// right one, before a caller acts on it.
//
// res.WrappedKey must be non-nil. Callers report its absence themselves: what a missing
// owner key means differs per command, and for a revoke it is not an error at all.
//
// Both keys are wiped if any step fails, so a caller only ever receives keys it owns.
func openResourceKeys(prof *identity.Profile, res api.GetResourceResponse, id string) (_ *resourceKeys, err error) {
	if res.WrappedKey == nil {
		// Unreachable from the current callers, which all report the absence in their
		// own words first. A backstop so a later one gets an error, not a nil deref.
		return nil, errors.New("no owner key stored for this resource")
	}
	k := &resourceKeys{}
	defer func() {
		if err != nil {
			k.close()
		}
	}()
	if k.mk, err = unlockMaster(prof); err != nil {
		return nil, err
	}
	if k.ck, err = crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(k.mk)); err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	if k.meta, err = decodeMeta(res.EncryptedMeta, k.ck, id); err != nil {
		return nil, err
	}
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
		// Re-verify the pin against the server's current keys, exactly as a fresh
		// share does. Wrapping to the stored pin blindly means a grantee who rotated
		// their own root key gets their working wrap silently overwritten with a dead
		// one by an unrelated revocation — permanently, since nothing re-checks later.
		if err := confirmPinnedKeys(cl, prof, pin); err != nil {
			fmt.Fprintf(os.Stderr, "warning: not re-wrapping the grant for %s: %v\n", pin.Email, err)
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
		sealedTree, refs, err := syncengine.SealTree(manifest, crypto.DeriveConvergenceKey(mk), nil)
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
			segSrc, err := newPackSource(cl, root.ChunkIDs())
			if err != nil {
				return resealed{}, err
			}
			chunks, err = root.Resolve(segSrc.get)
			if err != nil {
				return resealed{}, err
			}
		}
		// SealFileRoot binds the root to the id even if the original create was unbound.
		blob, err := syncengine.SealFileRoot(root, newCK, id)
		if err != nil {
			return resealed{}, err
		}
		return resealed{blob: blob, refs: root.Refs(chunks)}, nil
	})
}
