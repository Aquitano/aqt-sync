// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/folderstate"
)

// TestCheckSyncFormat pins the server-truth routing: a pre-tree folder is refused
// rather than reconciled as an empty chunked manifest (the silent tree-wipe), and a
// tree folder is accepted.
func TestCheckSyncFormat(t *testing.T) {
	cases := []struct {
		name string
		meta api.Metadata
		want string // substring of the expected error; empty means accepted
	}{
		{"chunked tree folder", api.Metadata{Tree: true}, ""},
		{"legacy folder", api.Metadata{}, "unsupported legacy format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSyncFormat(tc.meta)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkSyncFormat(%+v) = %v, want accepted", tc.meta, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkSyncFormat(%+v) = %v, want error containing %q", tc.meta, err, tc.want)
			}
		})
	}
}

// TestOpenSyncSessionRefusesMissingBase covers the shared prologue's no-base guard:
// syncing against an empty base resurrects deleted files, so it is refused unless
// --reconcile opts in.
func TestOpenSyncSessionRefusesMissingBase(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "A")
	h.sync(origin)

	if err := os.Remove(folderstate.BasePath(origin)); err != nil {
		t.Fatal(err)
	}
	if _, err := openSyncSession(origin, syncOptions{}); !errors.Is(err, errSyncNoBase) {
		t.Fatalf("openSyncSession without a base = %v, want errSyncNoBase", err)
	}

	sess, err := openSyncSession(origin, syncOptions{reconcile: true})
	if err != nil {
		t.Fatalf("openSyncSession with --reconcile: %v", err)
	}
	defer sess.Wipe()
	if sess.baseExists {
		t.Fatal("session reports a usable base after base.json was removed")
	}
}

// TestOpenRemoteRollbackOutranksFormatMismatch pins the ordering the shared prologue
// unified on: a rolled-back server is a data-integrity signal about the server, so it
// must be reported before any format refusal.
func TestOpenRemoteRollbackOutranksFormatMismatch(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	backup := h.snapshotServerData()
	writeTree(t, origin, "newer.txt", "written after the backup")
	h.sync(origin)
	h.restoreServer(backup)

	sess, err := openSyncSession(origin, syncOptions{})
	if err != nil {
		t.Fatalf("openSyncSession: %v", err)
	}
	defer sess.Wipe()

	if _, err := sess.openRemote(syncOptions{}); !errors.Is(err, errRollback) {
		t.Fatalf("openRemote on a rolled-back folder = %v, want errRollback", err)
	}

	// Accepting the rollback drops the base for this pass, which is what makes the
	// reconcile start from scratch instead of clobbering newer local files.
	rs, err := sess.openRemote(syncOptions{acceptRollback: true})
	if err != nil {
		t.Fatalf("openRemote with --accept-rollback: %v", err)
	}
	defer rs.ck.Wipe()
	if rs.trustBase {
		t.Fatal("openRemote trusted the base after accepting a rollback")
	}
}

// TestSyncRefusesUnparsableConfig: .aqtconfig is synced content, so a bad one can
// arrive from another device. Sync must refuse it up front — before any server work
// — rather than silently falling back to defaults. `{"pack": true}` is the stale
// config left by the removed pack-and-seal format; it is now just an unknown field.
func TestSyncRefusesUnparsableConfig(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	if err := os.WriteFile(filepath.Join(origin, ".aqtconfig"), []byte(`{"pack": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runSync(origin, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "pack") {
		t.Fatalf("sync with an unparsable config = %v, want an error naming the offending field", err)
	}
	if got := readTree(t, origin, "keep.txt"); got != "v1" {
		t.Fatalf("refused sync touched local files: %q", got)
	}
}
