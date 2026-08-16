// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// untrackCmd is the way out of a folder whose remote is gone. Deleting the resource
// — with `aqt rm .` here, from another device, or by an operator — leaves .aqt
// pointing at nothing: every sync fails with "not found on the server" and `aqt init`
// refuses the directory because .aqt exists. Without this the only recovery is
// `rm -rf .aqt`, which nothing tells the user about.
func untrackCmd() *cobra.Command {
	var (
		deleteRemote bool
		keepRemote   bool
		yes          bool
	)
	cmd := &cobra.Command{
		Use:   "untrack [dir]",
		Short: "Stop tracking a folder for sync, leaving its files alone",
		Long: "Removes the folder's .aqt control directory. The files in the folder are " +
			"never touched, and the server-side resource is kept unless --delete-remote " +
			"is passed. Use this to recover a folder whose remote resource was deleted, " +
			"or before re-running `aqt init` against a different account or server.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if deleteRemote && keepRemote {
				return errors.New("--delete-remote and --keep-remote contradict each other; pass one")
			}
			return runUntrack(dirArg(args), deleteRemote, yes)
		},
	}
	cmd.Flags().BoolVar(&deleteRemote, "delete-remote", false, "also delete the server-side resource")
	cmd.Flags().BoolVar(&keepRemote, "keep-remote", false, "leave the server-side resource in place (the default)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

func runUntrack(dir string, deleteRemote, assumeYes bool) error {
	root, err := trackedRoot(dir)
	if err != nil {
		return err
	}
	// A live watcher outlives the control state it reads, so removing .aqt under one
	// leaves it failing in the background against a folder that no longer exists. The
	// sync lock below would not catch this: the daemon holds it only for the length of
	// a sync, so untrack would usually slip through between two of them.
	if pid, ok := readLockPID(controlPath(root, agentPIDFile)); ok && processAlive(pid) && looksLikeAqtProcess(pid) {
		return fmt.Errorf("a watch agent is running here (pid %d); stop it with `aqt agent stop` first", pid)
	}

	// A folder worth untracking often has broken control state, so an unreadable
	// state.json must not block the escape hatch — it only costs the prompt the
	// resource id.
	st, stateErr := loadState(root)

	remoteLine := "the server-side resource is kept"
	if deleteRemote {
		remoteLine = "the server-side resource is deleted too"
	}
	target := "this folder"
	if stateErr == nil && st.ID != "" {
		target = st.ID
	}
	if err := confirmDestructive(fmt.Sprintf(
		"Stop tracking %s (%s)? Files in %s are not touched, and %s. [y/N] ",
		root, target, root, remoteLine), assumeYes); err != nil {
		return err
	}

	// The delete runs first: dropping .aqt would lose the resource id, so a failure
	// in between must leave the folder tracked and retryable rather than orphan a
	// resource nothing points at any more.
	if deleteRemote {
		if stateErr != nil {
			return fmt.Errorf("read folder state: %w (cannot delete the remote resource without it; "+
				"re-run without --delete-remote to stop tracking locally)", stateErr)
		}
		if err := runRemove([]string{root}, false, true); err != nil {
			return fmt.Errorf("%w\n%s is still tracked; if the resource is already gone, "+
				"re-run `aqt untrack` without --delete-remote", err, root)
		}
	}

	// Under the sync lock, so a watch daemon mid-sync is not reading control state
	// out from under the removal. A live holder refuses, which is the right answer.
	release, err := acquireSyncLock(root)
	if err != nil {
		return err
	}
	// The lock is an open handle on .aqt/lock, which Windows will not let us
	// delete while it is held. Remove everything else under the lock's protection,
	// then release (closing the handle) and take the now-empty control dir with it.
	ctl := filepath.Join(root, syncengine.ControlDir)
	entries, err := os.ReadDir(ctl)
	if err != nil {
		release()
		return fmt.Errorf("read %s: %w", ctl, err)
	}
	for _, e := range entries {
		if e.Name() == "lock" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(ctl, e.Name())); err != nil {
			release()
			return fmt.Errorf("remove %s: %w", filepath.Join(ctl, e.Name()), err)
		}
	}
	release()
	if err := os.RemoveAll(ctl); err != nil {
		return fmt.Errorf("remove %s: %w", ctl, err)
	}
	fmt.Printf("untracked %s\n", root)
	if !deleteRemote && stateErr == nil && st.ID != "" {
		fmt.Fprintf(os.Stderr, "note: resource %s is still on the server; delete it with `aqt rm %s`\n", st.ID, st.ID)
	}
	return nil
}
