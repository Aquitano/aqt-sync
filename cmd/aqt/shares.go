// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/safetext"
)

// shareRow is one incoming grant, as shown by `aqt shares`. The strings somebody
// else authored — Name and Kind by the grantor, Ref, From and ClaimedEmail by the
// server — are sanitized on the way in (see foreignText); FromEmail and Fingerprint
// come from this device's own contact pins. The unexported id keeps the resource id
// exactly as it arrived, since that one is also a value we hand back to the server.
type shareRow struct {
	Ref  string `json:"ref"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
	// From is the grantor's opaque account handle; FromEmail and Fingerprint are
	// filled in when a local contact pin maps that handle back to a person.
	From        string `json:"from"`
	FromEmail   string `json:"fromEmail,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// ClaimedEmail and ClaimedFingerprint are what the server says about a grantor
	// with no pin: its account email and the fingerprint of its identity key.
	ClaimedEmail       string `json:"claimedEmail,omitempty"`
	ClaimedFingerprint string `json:"claimedFingerprint,omitempty"`
	Attribution        string `json:"attribution"`
	Since              string `json:"since"`
	Stale              bool   `json:"stale,omitempty"` // the wrap no longer opens (owner rotated the key)

	id        string
	createdAt int64
}

// How a share row names its sender, strongest first. Only a pin attributes a share:
// signup does not verify emails, so a claim is the server's word, and anyone with an
// account can append a row here.
const (
	attributionVerified = "verified" // a pin checked against a fingerprint
	attributionPinned   = "pinned"
	attributionClaimed  = "claimed"
	attributionUnknown  = "unknown" // a bare handle: the server named no one
)

func (r shareRow) sender() string {
	switch r.Attribution {
	case attributionVerified:
		return fmt.Sprintf("%s (%s, verified)", r.FromEmail, r.Fingerprint)
	case attributionPinned:
		return fmt.Sprintf("%s (%s)", r.FromEmail, r.Fingerprint)
	case attributionClaimed:
		return fmt.Sprintf("%s? (unverified, %s)", r.ClaimedEmail, r.ClaimedFingerprint)
	default:
		return fmt.Sprintf("%s (unknown sender)", r.From)
	}
}

// fetchCommand is a ready-to-run command that pulls the share, or "" for a row that
// cannot be fetched. The id is the server's, so a row whose id is not spelled the way
// the server mints them (base64url) gets no command a user might paste into a shell.
func (r shareRow) fetchCommand() string {
	base64URL := func(c rune) bool {
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
	}
	if r.Stale || r.id == "" || strings.ContainsFunc(r.id, func(c rune) bool { return !base64URL(c) }) {
		return ""
	}
	if r.Kind != api.KindFolder {
		return "aqt pull " + r.Ref
	}
	if dir := localDirName(r.Name); dir != "" {
		return fmt.Sprintf("aqt clone %s %s", r.Ref, dir)
	}
	return "aqt clone " + r.Ref
}

// localDirName turns a grantor-chosen folder name into a directory name that can be
// pasted into a shell: every run of other characters folds to one '-', and leading or
// trailing '-' and '.' go, so the name is neither a flag nor a hidden or parent
// directory. "" means nothing usable is left, and clone falls back to the id.
func localDirName(name string) string {
	var b strings.Builder
	folded := false
	for _, c := range name {
		if isPlainNameRune(c) {
			b.WriteRune(c)
			folded = false
		} else if !folded {
			b.WriteByte('-')
			folded = true
		}
	}
	return strings.Trim(b.String(), "-.")
}

func isPlainNameRune(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '.'
}

// isPlainEmail accepts a claimed email only in the plain local@domain shape. Signup
// takes any string as an email, and one with spaces or parentheses could spell out a
// fake "(SHA256:…, verified)" right beside the row's real attribution.
func isPlainEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && domain != "" && !strings.ContainsFunc(local+domain, func(c rune) bool {
		return !isPlainNameRune(c) && c != '+'
	})
}

// foreignText bounds and strips control bytes from a string this client did not
// author. A grantor picks the plaintext of a shared resource's name and the server
// picks the handles and ids, so without this either of them picks bytes that reach
// this terminal — enough to erase the line and forge a fingerprint MATCH or an
// aqt:// ref of their choosing.
func foreignText(s string) string { return safetext.Clean(s, safetext.DisplayMax) }

func (app *application) sharesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shares",
		Short: "List resources other accounts granted you (read-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, rows, err := app.collectShares()
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				if app.json {
					return printJSON([]shareRow{})
				}
				fmt.Println("no incoming shares")
				return nil
			}
			if app.json {
				if err := printJSON(rows); err != nil {
					return err
				}
				app.markSharesSeen(rows)
				return nil
			}
			unpinned := false
			for _, r := range rows {
				if r.Attribution == attributionClaimed || r.Attribution == attributionUnknown {
					unpinned = true
				}
				if r.Stale {
					fmt.Printf("%s  (stale grant — ask the owner to re-share)  from %s  since %s\n", r.Ref, r.sender(), r.Since)
					continue
				}
				// The name is quoted so a grantor cannot embed a fake "from …" clause
				// that reads as this row's real attribution.
				fmt.Printf("%s  %q  %s  from %s  since %s\n", r.Ref, r.Name, r.Kind, r.sender(), r.Since)
				if c := r.fetchCommand(); c != "" {
					fmt.Printf("    %s\n", c)
				}
			}
			fmt.Println("\nshares are read-only; decline one with `aqt shares rm aqt://<id>`, and add --block to refuse that account entirely")
			if unpinned {
				fmt.Println("an unverified or unknown sender is only the server's word: compare the fingerprint with them, then `aqt contacts pin <email> --fingerprint <fingerprint>`")
			}
			app.markSharesSeen(rows)
			return nil
		},
	}
	markJSONSupported(cmd)
	cmd.AddCommand(app.sharesRmCmd(), app.sharesBlockedCmd(), app.sharesUnblockCmd())
	return cmd
}

// collectShares decrypts each incoming grant's metadata and attributes it to a
// pinned contact where one matches, or else to what the server claims. It returns
// the authed client it built so a caller acting on a row does not construct a second
// one.
func (app *application) collectShares() (*client.Client, []shareRow, error) {
	cl, prof, err := app.authedClient()
	if err != nil {
		return nil, nil, err
	}
	items, err := cl.ListShares()
	if err != nil {
		return nil, nil, err
	}
	if len(items) == 0 {
		return cl, nil, nil
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return nil, nil, err
	}
	defer mk.Wipe()
	// A grant names its owner by opaque handle. `aqt contacts verify` protects the
	// grant direction only, so reverse-resolving the handle against the same pins is
	// what lets a recipient check an incoming share against a fingerprint they have
	// compared out-of-band.
	pinByHandle := map[string]identity.Contact{}
	if pins, err := identity.LoadContacts(prof.Name); err == nil {
		for _, c := range pins {
			pinByHandle[c.Handle] = c
		}
	}
	rows := make([]shareRow, 0, len(items))
	for _, it := range items {
		row := shareRow{
			id:          it.ResourceID,
			createdAt:   it.CreatedAt,
			Ref:         "aqt://" + foreignText(it.ResourceID),
			From:        foreignText(it.OwnerHandle),
			Since:       time.Unix(it.CreatedAt, 0).Format("2006-01-02"),
			Attribution: attributionUnknown,
		}
		if pin, ok := pinByHandle[it.OwnerHandle]; ok {
			row.FromEmail, row.Fingerprint = pin.Email, crypto.KeyFingerprint(pin.PublicKey)
			row.Attribution = attributionPinned
			if pin.Verified {
				row.Attribution = attributionVerified
			}
		} else if email := foreignText(it.OwnerEmail); isPlainEmail(email) && len(it.OwnerPublicKey) == ed25519.PublicKeySize {
			row.ClaimedEmail, row.ClaimedFingerprint = email, crypto.KeyFingerprint(it.OwnerPublicKey)
			row.Attribution = attributionClaimed
		}
		ck, err := crypto.UnwrapGrant(it.WrappedKey, mk, it.ResourceID, it.OwnerHandle, prof.OwnerHandle)
		if err != nil {
			// The owner rotated the key after granting (or the wrap is bound to
			// someone else); the grant row exists but no longer opens anything.
			row.Stale = true
			rows = append(rows, row)
			continue
		}
		meta, err := decodeMeta(it.EncryptedMeta, ck, it.ResourceID)
		ck.Wipe()
		row.Name = "(undecryptable metadata)"
		if err == nil {
			row.Name = foreignText(meta.Name)
			row.Kind = foreignText(meta.Kind)
		}
		rows = append(rows, row)
	}
	return cl, rows, nil
}

// markSharesSeen moves the profile's new-share marker past every listed row. The
// listing has already been shown, so a failure to record it is not worth reporting.
func (app *application) markSharesSeen(rows []shareRow) {
	var newest int64
	for _, r := range rows {
		newest = max(newest, r.createdAt)
	}
	// Loaded raw rather than through loadProfile, whose --server override must not
	// be written back.
	prof, err := identity.Load(app.profile)
	if err != nil || newest <= prof.SharesSeenAt {
		return
	}
	prof.SharesSeenAt = newest
	_ = identity.Save(prof)
}

// noticeNewShares prints one line on stderr when shares have arrived since `aqt
// shares` last listed them. It rides along on commands with a job of their own, so a
// failure is swallowed rather than allowed to change their output or outcome.
func (app *application) noticeNewShares() {
	cl, prof, err := app.authedClient()
	if err != nil {
		return
	}
	items, err := cl.ListShares()
	if err != nil {
		return
	}
	n := 0
	for _, it := range items {
		if it.CreatedAt > prof.SharesSeenAt {
			n++
		}
	}
	switch {
	case n == 1:
		fmt.Fprintln(os.Stderr, "1 new share from another account — run `aqt shares`")
	case n > 1:
		fmt.Fprintf(os.Stderr, "%d new shares from other accounts — run `aqt shares`\n", n)
	}
}

// sharesRmCmd is the grantee-side counterpart of `aqt unshare --with`: until it
// existed, only the account that appended a row to your share list could remove it.
func (app *application) sharesRmCmd() *cobra.Command {
	var block bool
	cmd := &cobra.Command{
		Use:     "rm <ref-or-name>",
		Aliases: []string{"remove", "decline"},
		Short:   "Decline an incoming share, optionally blocking the account that sent it",
		Long: "Removes one row from your incoming shares. The resource is untouched — you are\n" +
			"dropping your own access, not the owner's copy — and the owner can grant it again.\n" +
			"--block refuses that account's future grants and drops every share it has sent you;\n" +
			"lift it with `aqt shares unblock`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runSharesRemove(args[0], block)
		},
	}
	cmd.Flags().BoolVar(&block, "block", false, "also refuse future shares from the account that sent this one")
	markJSONSupported(cmd)
	return cmd
}

func (app *application) runSharesRemove(ref string, block bool) error {
	cl, rows, err := app.collectShares()
	if err != nil {
		return err
	}
	row, err := matchShare(rows, ref)
	if err != nil {
		return err
	}
	resp, err := cl.RemoveShare(row.id, block)
	if errors.Is(err, client.ErrNotFound) {
		return fmt.Errorf("no incoming share for %s", row.Ref)
	}
	if err != nil {
		return err
	}
	if app.json {
		return printJSON(map[string]any{
			"ref": row.Ref, "from": foreignText(resp.OwnerHandle), "removed": resp.Removed, "blocked": resp.Blocked,
		})
	}
	fmt.Printf("removed %s from your incoming shares\n", row.Ref)
	if block {
		fmt.Printf("blocked %s: %d share(s) dropped, and it can no longer grant to you\n", row.sender(), resp.Removed)
		fmt.Fprintln(os.Stderr, "lift it with `aqt shares unblock <email-or-handle>`")
	}
	return nil
}

// matchShare resolves a ref or a decrypted name against the incoming share list.
// Names come from the grantor, so an ambiguous one is reported rather than guessed:
// picking either row would let a sender aim a removal at somebody else's share by
// naming their resource the same thing.
func matchShare(rows []shareRow, ref string) (shareRow, error) {
	id, _, _ := parseRef(ref)
	for _, r := range rows {
		if r.id == id {
			return r, nil
		}
	}
	var matches []shareRow
	for _, r := range rows {
		if r.Name == ref {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return shareRow{}, fmt.Errorf("no incoming share matches %q; `aqt shares` lists them", ref)
	case 1:
		return matches[0], nil
	default:
		refs := make([]string, len(matches))
		for i, m := range matches {
			refs[i] = m.Ref
		}
		return shareRow{}, fmt.Errorf("share name %q is ambiguous (%s); use a ref", ref, strings.Join(refs, ", "))
	}
}

// blockRow is one blocked sender, as shown by `aqt shares blocked`. Handle is the
// server's, so it is sanitized on the way in like any other foreign text; Email
// comes from this device's own contact pins.
type blockRow struct {
	Handle  string `json:"handle"`
	Email   string `json:"email,omitempty"`
	Blocked string `json:"blocked"`
}

func (app *application) sharesBlockedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blocked",
		Short: "List accounts whose shares you are refusing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := app.authedClient()
			if err != nil {
				return err
			}
			blocks, err := cl.ListShareBlocks()
			if err != nil {
				return err
			}
			emailByHandle := map[string]string{}
			if pins, err := identity.LoadContacts(prof.Name); err == nil {
				for _, c := range pins {
					emailByHandle[c.Handle] = c.Email
				}
			}
			rows := make([]blockRow, 0, len(blocks))
			for _, b := range blocks {
				rows = append(rows, blockRow{
					Handle:  foreignText(b.OwnerHandle),
					Email:   emailByHandle[b.OwnerHandle],
					Blocked: time.Unix(b.CreatedAt, 0).Format("2006-01-02"),
				})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Handle < rows[j].Handle })
			if app.json {
				return printJSON(rows)
			}
			if len(rows) == 0 {
				fmt.Println("no blocked senders; `aqt shares rm <ref> --block` adds one")
				return nil
			}
			cells := make([][]string, 0, len(rows))
			for _, r := range rows {
				email := r.Email
				if email == "" {
					email = "(unknown)"
				}
				cells = append(cells, []string{email, r.Handle, r.Blocked})
			}
			return printTable(os.Stdout, []string{"ACCOUNT", "HANDLE", "BLOCKED"}, cells)
		},
	}
	markJSONSupported(cmd)
	return cmd
}

func (app *application) sharesUnblockCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unblock <email-or-handle>",
		Short: "Let a blocked account share with you again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, prof, err := app.authedClient()
			if err != nil {
				return err
			}
			// An email is the form a user remembers; it resolves through the local pins,
			// so unblocking never has to ask the server who an address belongs to.
			handle := args[0]
			if pins, err := identity.LoadContacts(prof.Name); err == nil {
				if pin, ok := pins[args[0]]; ok {
					handle = pin.Handle
				}
			}
			if err := cl.UnblockSender(handle); errors.Is(err, client.ErrNotFound) {
				return fmt.Errorf("%s is not blocked; `aqt shares blocked` lists the blocks", args[0])
			} else if err != nil {
				return err
			}
			if app.json {
				return printJSON(map[string]any{"unblocked": handle})
			}
			fmt.Printf("unblocked %s; it can share with you again\n", args[0])
			return nil
		},
	}
	markJSONSupported(cmd)
	return cmd
}
