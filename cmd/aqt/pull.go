// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

func (app *application) pullCmd() *cobra.Command {
	var (
		out   string
		pw    passwordFlags
		force bool
	)
	cmd := &cobra.Command{
		Use:   "pull <name-or-id|tracked-path|url>[/path]",
		Short: "Fetch and decrypt a resource, or a single entry inside a folder",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return app.runPull(args[0], out, password, false, force)
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "write to this path")
	pw.bind(cmd, "password for a gated link")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite the destination if it exists")
	app.bindPinOwner(cmd)
	markJSONSupported(cmd)
	// Only a subtree pull (aqt://<id>/<dir>) transfers enough entries to draw a bar,
	// but that is this command's own path, so --progress belongs here.
	markProgressSupported(cmd)
	return cmd
}

func (app *application) catCmd() *cobra.Command {
	var pw passwordFlags
	cmd := &cobra.Command{
		Use:   "cat <name-or-id|tracked-path|url>[/path]",
		Short: "Decrypt a resource (or one file inside a folder) to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := pw.resolve()
			if err != nil {
				return err
			}
			return app.runPull(args[0], "", password, true, false)
		},
	}
	pw.bind(cmd, "password for a gated link")
	app.bindPinOwner(cmd)
	return cmd
}

// bindPinOwner adds --yes to a command that can read through a grant, accepting the
// question openGrant asks before it opens a share from an owner nobody pinned.
func (app *application) bindPinOwner(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&app.pinOwner, "yes", "y", false, "open a share from an owner you have not pinned, pinning them on first use, without asking")
}

func (app *application) runPull(ref, out, password string, toStdout, force bool) error {
	baseRef, subpath := splitRefPath(ref)
	id, fragment, origin := parseRef(baseRef)

	// A public link decrypts from its fragment and needs no profile; a private
	// ref needs the account token (to fetch) and passphrase (to unwrap). Honor a
	// host embedded in the ref so a share link is self-contained, but never attach
	// the token to a foreign host (see newLinkClient).
	prof := app.loadProfileOptional()
	cl, err := app.newLinkClient(origin, prof)
	if err != nil {
		return err
	}
	// An owned ref may be a name or a tracked path, which only the account can
	// resolve; a link (fragment or foreign host) is opaque and stays untouched.
	// Unlock the master key at most once per invocation: resolving by name and
	// unwrapping the owner key below both need it, and a second unlockMaster would
	// prompt for the passphrase again whenever session caching is unavailable.
	var master *crypto.MasterKey
	if origin == "" && fragment == "" && prof != nil {
		mk, err := app.unlockMaster(prof)
		if err != nil {
			return err
		}
		defer mk.Wipe()
		master = &mk
		if id, err = resolveOwnedResourceID(cl, mk, baseRef); err != nil {
			return err
		}
	}

	res, err := cl.GetResource(id)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("resource %s not found: pass a unique name, an id, or an aqt:// ref "+
			"(it may also be private and not yours)", id)
	}
	if errors.Is(err, client.ErrGone) {
		return fmt.Errorf("this link has expired or reached its read limit: %w", err)
	}
	if err != nil {
		return err
	}

	ck, err := app.contentKeyWithMaster(cl, res, fragment, password, prof, master)
	if err != nil {
		return err
	}
	defer ck.Wipe()

	// An aqt://<id>/<path> ref (or a share URL with segments after /x/<id>)
	// addresses one entry inside a folder: only the path's spine nodes and that
	// entry's chunks are fetched, never the tree.
	if subpath != "" {
		return app.pullSubpath(cl, id, res, ck, subpath, out, toStdout, force, remoteFetch(cl, res, fragment))
	}

	meta, err := decodeMeta(res.EncryptedMeta, ck, id)
	if err != nil {
		return err
	}
	if meta.Kind == api.KindFolder {
		// The name is the link author's plaintext, not ours: sanitize before it reaches
		// the terminal, or an escape sequence in it forges the rest of this line.
		name := foreignText(meta.Name)
		if fragment != "" {
			return fmt.Errorf("%s is a folder: `aqt clone '<link>'` materializes it, and '<link>/<path>' pulls a single entry", name)
		}
		return fmt.Errorf("%s is a folder: `aqt clone aqt://%s` materializes it, `aqt ls aqt://%s` lists it, "+
			"and aqt://%s/<path> pulls a single entry", name, id, id, id)
	}
	content, err := openFileContent(cl, res, ck, meta, remoteFetch(cl, res, fragment))
	if err != nil {
		return err
	}
	if out == "" {
		out = safeOutputName(meta.Name)
	}
	return app.writeOutput(content, out, 0o600, toStdout, force)
}

// contentKey recovers the content key either from the share fragment (public/
// gated) or by unwrapping with the master key (private).
func (app *application) contentKey(cl *client.Client, res api.GetResourceResponse, fragment, password string, prof *identity.Profile) (crypto.ContentKey, error) {
	return app.contentKeyWithMaster(cl, res, fragment, password, prof, nil)
}

// contentKeyWithMaster is contentKey given an already-unlocked master key to reuse.
// A caller that has unlocked once (e.g. info resolving an owned ref by name) passes it
// so unwrapping the owner or grant key does not prompt for the passphrase a second time
// when session caching is unavailable. A nil master is unlocked on demand.
func (app *application) contentKeyWithMaster(cl *client.Client, res api.GetResourceResponse, fragment, password string, prof *identity.Profile, master *crypto.MasterKey) (crypto.ContentKey, error) {
	if fragment != "" {
		if strings.HasPrefix(fragment, "p.") && password == "" {
			p, err := app.promptPassphrase("Share password: ")
			if err != nil {
				return crypto.ContentKey{}, err
			}
			password = p
		}
		return crypto.DecodeFragment(fragment, password)
	}
	// A grant read carries the content key HPKE-wrapped to this account instead of
	// the owner's wrap; the info binding pins it to (resource, owner, this handle),
	// so a hostile server cannot splice another grant's wrap onto this resource.
	if res.WrappedKey == nil && res.GrantKey != nil {
		if prof == nil {
			return crypto.ContentKey{}, errors.New("granted resource: run `aqt login` to decrypt it")
		}
		mk, owned, err := app.borrowMaster(prof, master)
		if err != nil {
			return crypto.ContentKey{}, err
		}
		if owned {
			defer mk.Wipe()
		}
		return openGrant(cl, res, mk, prof, app.pinOwner)
	}
	if res.WrappedKey == nil {
		return crypto.ContentKey{}, errors.New("no decryption key: this looks like a public resource but the link had no #key")
	}
	if prof == nil {
		return crypto.ContentKey{}, errors.New("private resource: run `aqt login` to decrypt it")
	}
	mk, owned, err := app.borrowMaster(prof, master)
	if err != nil {
		return crypto.ContentKey{}, err
	}
	if owned {
		defer mk.Wipe()
	}
	return crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
}

// openGrant unwraps a grant read's content key, checks the owner's signature over it,
// and names the sender on stderr the way `aqt shares` does. The wrap alone proves
// nothing about who made it: anyone with this account's public enc key can wrap a key
// of their choosing, and the server can list it under any owner. A grant without a
// signature from the key it is attributed to is refused. One signed by the key the
// server reports for an owner nobody pinned opens only once that owner is pinned
// (askPinOwner); pinOwner pins them without asking.
func openGrant(cl *client.Client, res api.GetResourceResponse, mk crypto.MasterKey, prof *identity.Profile, pinOwner bool) (crypto.ContentKey, error) {
	ck, err := crypto.UnwrapGrant(res.GrantKey, mk, res.ID, res.Owner, prof.OwnerHandle)
	if err != nil {
		return ck, err
	}
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		ck.Wipe()
		return crypto.ContentKey{}, err
	}
	a := attributeGrant(pins, res.Owner, res.OwnerPublicKey, res.GrantSig, ck, res.ID, prof.OwnerHandle)
	row := shareRow{Ref: "aqt://" + foreignText(res.ID), From: foreignText(res.Owner), Attribution: attributionUnknown}
	row.attribute(a, res.OwnerEmail, res.OwnerPublicKey)
	switch {
	case a.signed && a.pin != nil:
	case a.signed:
		pin, err := askPinOwner(cl, prof, res, row, pinOwner)
		if err != nil {
			ck.Wipe()
			return crypto.ContentKey{}, err
		}
		row.attribute(grantAttribution{pin: &pin, signed: true}, "", nil)
	default:
		ck.Wipe()
		return crypto.ContentKey{}, unsignedGrantError(row.Ref, a)
	}
	fmt.Fprintf(os.Stderr, "%s is shared by %s\n", row.Ref, row.sender())
	return ck, nil
}

func unsignedGrantError(ref string, a grantAttribution) error {
	switch {
	case a.pin != nil:
		return fmt.Errorf("%s is listed as shared by %s, but the key you pinned for them did not sign it, so it was not opened. "+
			"They may have shared it before shares were signed (ask them to share it again) or rotated their account key (compare with `aqt contacts verify %s`); otherwise the server wrote it",
			ref, a.pin.Email, a.pin.Email)
	case a.misfiled != nil:
		return fmt.Errorf("%s is signed by the key you pinned for %s, but under an account handle that is not theirs, so it was not opened: "+
			"the server is misreporting who owns it. Compare keys with `aqt contacts verify %s`",
			ref, a.misfiled.Email, a.misfiled.Email)
	default:
		return fmt.Errorf("%s carries no valid signature from the account it is listed under, so it was not opened: "+
			"it was shared before shares were signed (ask the owner to share it again), or the server wrote it", ref)
	}
}

// confirmOwnerPin asks before a share from an owner nobody pinned is opened and that
// owner pinned; cliutil.ErrNotConfirmable means no terminal can answer. A variable so
// tests can answer for one.
var confirmOwnerPin = confirmDestructive

// askPinOwner settles a grant signed by the key the server reports for an owner this
// account has not pinned. That key and the email beside it are the server's word: a
// server can wrap a key of its own to this account and sign it with a key it made up,
// so the grant opens only once the user pins that owner, on a terminal after seeing the
// claim and its fingerprint, or up front with --yes. Either way it is the first-use pin
// a share makes. A claim on an email already pinned to another account is refused.
func askPinOwner(cl *client.Client, prof *identity.Profile, res api.GetResourceResponse, row shareRow, assumeYes bool) (identity.Contact, error) {
	if row.Attribution != attributionClaimed {
		return identity.Contact{}, fmt.Errorf("%s is shared by %s, and the server names no email for that account, so it cannot be pinned and was not opened", row.Ref, row.sender())
	}
	email, fp := row.ClaimedEmail, row.ClaimedFingerprint
	pins, err := identity.LoadContacts(prof.Name)
	if err != nil {
		return identity.Contact{}, err
	}
	if pin, ok := pins[email]; ok {
		return identity.Contact{}, fmt.Errorf("%s claims to be shared by %s, but the key you pinned for %s (%s) did not sign it, so it was not opened: the server wrote it or put their name on it",
			row.Ref, email, email, crypto.KeyFingerprint(pin.PublicKey))
	}
	keys, err := fetchAccountKeys(cl, email)
	if err != nil {
		return identity.Contact{}, err
	}
	if keys.Handle != res.Owner || !bytes.Equal(keys.PublicKey, res.OwnerPublicKey) {
		return identity.Contact{}, fmt.Errorf("the server's keys for %s do not belong to the account that signed %s, so it was not opened and nothing was pinned", email, row.Ref)
	}
	prompt := fmt.Sprintf("%s is shared by an account you have not pinned:\n  claims    %s\n  handle    %s\n  identity  %s\n"+
		"signup does not verify emails, and the server reports all three; compare %s with %s over a separate channel before trusting it.\n"+
		"Pin %s and open it? [y/N] ", row.Ref, email, row.From, fp, fp, email, email)
	switch err := confirmOwnerPin(prompt, assumeYes); {
	case errors.Is(err, cliutil.ErrNotConfirmable):
		return identity.Contact{}, fmt.Errorf("%s is shared by %s, an account you have not pinned, so it was not opened. "+
			"Compare %s with them over a separate channel and run `aqt contacts pin %s --fingerprint <fingerprint>`, then try again; or pass --yes to pin them on first use",
			row.Ref, row.sender(), fp, email)
	case errors.Is(err, cliutil.ErrAborted):
		return identity.Contact{}, fmt.Errorf("did not open %s; nothing was pinned", row.Ref)
	case err != nil:
		return identity.Contact{}, err
	}
	pin := pinFromKeys(email, keys, false)
	pins[email] = pin
	if err := identity.SaveContacts(prof.Name, pins); err != nil {
		return identity.Contact{}, err
	}
	fmt.Fprintf(os.Stderr, "pinned %s on first use (%s); confirm out-of-band with `aqt contacts verify %s`\n", email, fp, email)
	return pin, nil
}

// borrowMaster returns the caller's already-unlocked master key when non-nil (owned is
// false; the caller wipes it), otherwise unlocks a fresh key the caller must wipe.
func (app *application) borrowMaster(prof *identity.Profile, shared *crypto.MasterKey) (mk crypto.MasterKey, owned bool, err error) {
	if shared != nil {
		return *shared, false, nil
	}
	mk, err = app.unlockMaster(prof)
	if err != nil {
		return crypto.MasterKey{}, false, err
	}
	return mk, true, nil
}

// safeOutputName reduces an attacker-controlled metadata name to a bare basename
// inside the current directory, so a malicious link cannot steer a default
// destination to "../" or an absolute path and write outside CWD. The name is
// also the link author's plaintext and gets echoed in "wrote %s" and "%s already
// exists": sanitize it (see foreignText) so no control byte reaches the terminal
// or lands in the on-disk filename.
func safeOutputName(name string) string {
	base := filepath.Base(foreignText(name))
	if base == "" || base == "." || base == ".." || base == string(filepath.Separator) || base == "stdin" {
		return "aqt-download"
	}
	return base
}

// parseRef extracts the resource id, optional fragment, and origin (scheme://host)
// from any ref form: a full http(s) URL (.../x/<id>#<frag>), an aqt://<id> ref, or
// a bare id. origin is set only for an absolute http/https URL so a share link's
// own host can be honored; aqt:// refs and bare ids yield an empty origin.
func parseRef(ref string) (id, fragment, origin string) {
	// One parser for every ref form: strip any subpath first (aqt://<id>/<sub> or
	// .../x/<id>/<sub/path>), so a subpath-bearing link resolves to the same id
	// here as in the pull path (the last-index scan below would otherwise read the
	// subpath's tail as the id).
	ref, _ = splitRefPath(ref)
	if i := strings.Index(ref, "#"); i >= 0 {
		fragment = ref[i+1:]
		ref = ref[:i]
	}
	// Only an absolute http(s) URL carries a usable host; guarding on the scheme
	// keeps aqt://<id> (which parses to scheme=aqt, host=<id>) and bare ids from
	// yielding a spurious origin.
	if u, err := url.Parse(ref); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	ref = strings.TrimPrefix(ref, "aqt://")
	if i := strings.LastIndex(ref, "/x/"); i >= 0 {
		ref = ref[i+len("/x/"):]
	} else if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	return ref, fragment, origin
}

// decodeMeta decrypts and parses a resource's sealed metadata. A decrypt or parse
// failure is returned rather than swallowed: in an owner flow the content key is
// correct, so a failure means corruption (or a blob/meta mix-up), and treating it as
// a default (unstreamed file) resource silently misroutes it — e.g. pulling a
// chunked folder through the inline-file path and writing its sealed root to disk.
func decodeMeta(blob crypto.SealedBlob, ck crypto.ContentKey, resourceID string) (api.Metadata, error) {
	plain, err := crypto.OpenBound(blob, ck, crypto.AADMeta, resourceID)
	if err != nil {
		return api.Metadata{}, fmt.Errorf("decrypt metadata: %w", err)
	}
	var m api.Metadata
	if err := json.Unmarshal(plain, &m); err != nil {
		return api.Metadata{}, fmt.Errorf("parse metadata: %w", err)
	}
	return m, nil
}
