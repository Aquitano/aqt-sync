// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// Deleting a folder's resource used to be a one-way door: every later sync failed
// with "not found on the server", `aqt init` refused the directory because .aqt was
// still there, and nothing named the way out. untrack is that way out, and both dead
// ends now point at it.
func TestUntrackRecoversAFolderWhoseResourceIsGone(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "keep.txt", "data")
	h.sync(dir)

	if err := runRemove([]string{dir}, false, true); err != nil {
		t.Fatalf("rm: %v", err)
	}

	err := runSync(dir, syncOptions{})
	if err == nil {
		t.Fatal("sync succeeded against a deleted resource")
	}
	if !strings.Contains(err.Error(), "aqt untrack") {
		t.Fatalf("sync error does not name the recovery: %v", err)
	}
	if err := runInit(dir, nil); err == nil || !strings.Contains(err.Error(), "aqt untrack") {
		t.Fatalf("init over a tracked folder does not name the recovery: %v", err)
	}

	if err := runUntrack(dir, false, true); err != nil {
		t.Fatalf("untrack: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, syncengine.ControlDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".aqt survived untrack: %v", err)
	}
	if got := readTree(t, dir, "keep.txt"); got != "data" {
		t.Fatalf("untrack touched the working tree: keep.txt = %q", got)
	}

	// The folder is ordinary again, so it can be tracked afresh.
	h.init(dir)
	h.sync(dir)
}

// A watch agent reads the control state untrack removes, and holds the sync lock
// only for the length of each sync — so untrack would slip between two of them and
// leave the daemon failing in the background against a folder that no longer exists.
func TestUntrackRefusesWhileAWatchAgentRuns(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "keep.txt", "data")
	h.sync(dir)

	// This test binary stands in for the daemon: it is alive, and its name satisfies
	// the same recycled-PID check `aqt agent stop` uses.
	pidFile := controlPath(dir, agentPIDFile)
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}

	err := runUntrack(dir, false, true)
	if err == nil {
		t.Fatal("untrack removed .aqt out from under a running watch agent")
	}
	if !strings.Contains(err.Error(), "aqt agent stop") {
		t.Fatalf("error does not name the fix: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, syncengine.ControlDir)); statErr != nil {
		t.Fatalf(".aqt was removed despite the refusal: %v", statErr)
	}

	// With the agent gone, the folder untracks normally.
	if err := os.Remove(pidFile); err != nil {
		t.Fatal(err)
	}
	if err := runUntrack(dir, false, true); err != nil {
		t.Fatalf("untrack after the agent stopped: %v", err)
	}
}

// Plain untrack is local-only: the server-side resource stays, and can still be
// cloned elsewhere. --delete-remote is the opt-in that also removes it.
func TestUntrackRemoteChoice(t *testing.T) {
	h := newE2E(t)

	kept := t.TempDir()
	h.init(kept)
	writeTree(t, kept, "keep.txt", "data")
	h.sync(kept)
	keptID := h.folderID(kept)
	if err := runUntrack(kept, false, true); err != nil {
		t.Fatalf("untrack: %v", err)
	}
	if !h.resourceExists(keptID) {
		t.Fatal("untrack deleted the remote resource without being asked to")
	}

	gone := t.TempDir()
	h.init(gone)
	writeTree(t, gone, "bye.txt", "data")
	h.sync(gone)
	goneID := h.folderID(gone)
	if err := runUntrack(gone, true, true); err != nil {
		t.Fatalf("untrack --delete-remote: %v", err)
	}
	if h.resourceExists(goneID) {
		t.Fatal("untrack --delete-remote left the resource on the server")
	}
	if _, err := os.Stat(filepath.Join(gone, syncengine.ControlDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".aqt survived untrack --delete-remote: %v", err)
	}
	if got := readTree(t, gone, "bye.txt"); got != "data" {
		t.Fatalf("untrack --delete-remote touched the working tree: bye.txt = %q", got)
	}
}
