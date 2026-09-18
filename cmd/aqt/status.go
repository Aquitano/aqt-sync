// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func (app *application) statusCmd() *cobra.Command {
	var opts statusOptions
	cmd := &cobra.Command{
		Use:   "status [dir]",
		Short: "Show local changes since the last sync, and any incoming changes on the server",
		Args:  cobra.MaximumNArgs(1),
		RunE:  func(cmd *cobra.Command, args []string) error { return app.runStatus(dirArg(args), opts) },
	}
	cmd.Flags().BoolVar(&opts.offline, "offline", false, "report only local changes; skip the server check for incoming changes")
	markJSONSupported(cmd)
	return cmd
}

type statusOptions struct {
	offline bool
}

func (app *application) runStatus(dir string, opts statusOptions) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	// Even the offline half needs the folder's own identity: the base manifest is
	// sealed under the owning profile's key.
	if err := app.bindTrackedRoot(root); err != nil {
		return err
	}
	base, err := folderstate.LoadBase(root, app.profile)
	if err != nil {
		return err
	}
	local, err := syncengine.ScanReusing(root, &base, false)
	if err != nil {
		return err
	}
	warnSkipped(local.Skipped)

	// The local half is offline: it compares the working tree to the last synced
	// manifest. Conflicts (both sides changed) still surface only during `sync`.
	ch := newChangeSet(syncengine.Diff(base, local))

	if app.json {
		out := map[string]any{
			"clean":    ch.total() == 0,
			"added":    nonNil(ch.added),
			"modified": nonNil(ch.modified),
			"deleted":  nonNil(ch.deleted),
			"renamed":  nonNilRenames(ch.renamed),
			"skipped":  skippedPaths(local.Skipped),
			// The buckets above flatten directories, mode edits, and type switches into
			// the three names they have always carried; changes reports each one as what
			// it is, so a caller never has to guess why a path is "modified".
			"changes": nonNilChanges(ch.changes),
		}
		if !opts.offline {
			if rep := app.collectIncoming(root, base); rep != nil {
				out["incoming"] = rep
			}
		}
		return printJSON(out)
	}

	if ch.total() == 0 {
		fmt.Println("clean (no local changes since last sync)")
	} else {
		printChanges(ch, "")
	}

	if opts.offline {
		return nil
	}
	printIncomingReport(app.collectIncoming(root, base))
	return nil
}

// skippedPaths renders a scan's unreadable paths for --json, where a name is all a
// script can act on.
func skippedPaths(skipped []syncengine.SkippedPath) []string {
	paths := make([]string, len(skipped))
	for i, s := range skipped {
		paths[i] = s.Path
	}
	return paths
}

// incomingReport is the server-side half of `status`: whether the server holds
// changes this machine has not pulled, at entry level when the folder key is at hand.
type incomingReport struct {
	State         string              `json:"state"` // "up-to-date" | "ahead" | "rollback"
	AheadBy       int                 `json:"aheadBy,omitempty"`
	ServerVersion int                 `json:"serverVersion,omitempty"` // set on rollback
	SeenVersion   int                 `json:"seenVersion,omitempty"`   // set on rollback
	Files         bool                `json:"-"`                       // the entry-level lists below are populated
	Added         []string            `json:"added,omitempty"`
	Modified      []string            `json:"modified,omitempty"`
	Deleted       []string            `json:"deleted,omitempty"`
	Renamed       []syncengine.Rename `json:"renamed,omitempty"`
	Changes       []syncengine.Change `json:"changes,omitempty"`
}

// collectIncoming reports whether the server holds changes this machine has not
// pulled, or nil when that cannot be determined. It is best-effort and never fails
// `status`: the command is primarily an offline, local-changes view, so a missing
// profile or an unreachable server downgrades to a short note on stderr. A precise
// file count needs the folder key, so it is computed only when an unlocked session
// is already cached — status never prompts for a passphrase; otherwise the coarser
// version delta is reported.
func (app *application) collectIncoming(root string, base syncengine.Manifest) *incomingReport {
	prof := app.loadProfileOptional()
	if prof == nil {
		return nil // never logged in: no server to compare against
	}
	st, err := folderstate.LoadState(root)
	if err != nil {
		return nil
	}
	cl, err := app.newBoundClient(prof.Server, prof.Token)
	if err != nil {
		return nil
	}
	res, err := cl.GetResource(st.ID)
	if err != nil {
		noteIncomingUnavailable(err)
		return nil
	}

	// Cheap freshness compare first: RemoteVersion is the server version this machine
	// last integrated (recorded by every init/clone/sync), so the resource header alone
	// answers "is the server ahead?" — no folder key, no tree walk.
	switch {
	case res.Version < st.RemoteVersion:
		return &incomingReport{State: "rollback", ServerVersion: res.Version, SeenVersion: st.RemoteVersion}
	case res.Version == st.RemoteVersion:
		return &incomingReport{State: "up-to-date"}
	}

	// The server is ahead. Try for a entry-level breakdown; it needs the folder key,
	// available without a prompt only when a session is already unlocked.
	{
		if mk, ok := identity.LoadSession(prof.Name); ok {
			defer mk.Wipe()
			if inc, ierr := incomingFiles(cl, res, base, mk); ierr == nil {
				state := "ahead"
				if inc.total() == 0 {
					state = "up-to-date"
				}
				return &incomingReport{
					State: state, Files: true,
					Added: inc.added, Modified: inc.modified, Deleted: inc.deleted,
					Renamed: inc.renamed, Changes: inc.changes,
				}
			}
		}
	}

	// Fallback: the server advanced but we cannot (or need not) enumerate the files.
	return &incomingReport{State: "ahead", AheadBy: res.Version - st.RemoteVersion}
}

// printIncomingReport renders collectIncoming's result for the human status view.
func printIncomingReport(rep *incomingReport) {
	if rep == nil {
		return
	}
	switch {
	case rep.State == "rollback":
		fmt.Printf("server reports an older version (%d < %d): it may have been restored from a backup; run `aqt sync`\n",
			rep.ServerVersion, rep.SeenVersion)
	case rep.State == "up-to-date":
		fmt.Println("up to date with the server")
	case rep.Files:
		printIncoming(changeSet{
			changes: rep.Changes, renamed: rep.Renamed,
			added: rep.Added, modified: rep.Modified, deleted: rep.Deleted,
		})
	case rep.AheadBy > 0:
		fmt.Printf("incoming: the server is ahead by %d version(s); run `aqt sync` to pull\n", rep.AheadBy)
	default:
		fmt.Println("the server may hold changes to pull; run `aqt sync`")
	}
}

// incomingFiles decrypts the remote manifest and diffs it against the last-synced
// base, yielding the files this machine would pull. It reuses the base tree's node
// ciphertexts so an unchanged remote subtree costs no fetch, exactly like a sync's
// remote read.
func incomingFiles(cl *client.Client, res api.GetResourceResponse, base syncengine.Manifest, mk crypto.MasterKey) (changeSet, error) {
	remote, err := remoteManifest(cl, res, mk, base)
	if err != nil {
		return changeSet{}, err
	}
	return newChangeSet(syncengine.Diff(base, remote)), nil
}

// readRemoteManifest reconstructs the remote folder manifest, reusing the base tree's
// node ciphertexts when a base is present (an unchanged subtree then costs no fetch)
// and falling back to a full walk when there is nothing to reuse.
func readRemoteManifest(cl *client.Client, res api.GetResourceResponse, ck crypto.ContentKey, base syncengine.Manifest, mk crypto.MasterKey) (syncengine.Manifest, error) {
	if len(base.Entries) == 0 && len(base.Dirs) == 0 {
		return openRemoteTree(cl, res.Blob, ck, res.ID)
	}
	conv := crypto.DeriveConvergenceKey(mk)
	defer conv.Wipe()
	baseCT, err := syncengine.SealTreeCiphertexts(base, conv, openSealMemo())
	if err != nil {
		return syncengine.Manifest{}, err
	}
	return openRemoteTreeReusingBase(cl, res.Blob, ck, res.ID, baseCT)
}

// printIncoming lists incoming changes indented under the "incoming:" summary, so
// they read as a group and never look like the top-level local changes above them.
func printIncoming(s changeSet) {
	if s.total() == 0 {
		fmt.Println("up to date with the server")
		return
	}
	fmt.Printf("incoming: %d to pull (%s); run `aqt sync`\n", s.total(), incomingBreakdown(s))
	printChanges(s, "  ")
}

func incomingBreakdown(s changeSet) string {
	var parts []string
	if n := len(s.added); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if n := len(s.modified); n > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", n))
	}
	if n := len(s.deleted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d deleted", n))
	}
	if n := len(s.renamed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d renamed", n))
	}
	return strings.Join(parts, ", ")
}

func noteIncomingUnavailable(err error) {
	switch {
	case isNetworkError(err):
		fmt.Fprintln(os.Stderr, "note: could not reach the server to check for incoming changes")
	case errors.Is(err, client.ErrNotFound):
		fmt.Fprintln(os.Stderr, "note: this folder no longer exists on the server")
	default:
		fmt.Fprintf(os.Stderr, "note: could not check the server for incoming changes: %v\n", err)
	}
}
