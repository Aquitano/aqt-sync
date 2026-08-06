package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// TestCheckSyncFormat pins the one guard that cannot be shared verbatim between the
// adapters: a pack folder is created with Packed and no Tree flag, so applying the
// chunked path's legacy !Tree check to both modes would reject every pack folder.
func TestCheckSyncFormat(t *testing.T) {
	cases := []struct {
		name   string
		meta   api.Metadata
		format syncFormat
		want   string // substring of the expected error; empty means the folder is accepted
	}{
		{"chunked folder as chunked", api.Metadata{Tree: true}, formatChunked, ""},
		{"pack folder as chunked", api.Metadata{Packed: true}, formatChunked, "pack-and-seal on the server"},
		{"legacy folder as chunked", api.Metadata{}, formatChunked, "unsupported legacy format"},
		{"pack folder as pack", api.Metadata{Packed: true}, formatPacked, ""},
		{"chunked folder as pack", api.Metadata{Tree: true}, formatPacked, "was created chunked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSyncFormat(tc.meta, tc.format)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("checkSyncFormat(%+v) = %v, want accepted", tc.meta, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkSyncFormat(%+v) accepted the folder, want error containing %q", tc.meta, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
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

	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
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

// TestOpenRemoteGuardsBothModes drives the shared per-attempt prologue against real
// resources of both formats, so the guard the chunked and pack adapters now share is
// verified through one surface.
func TestOpenRemoteGuardsBothModes(t *testing.T) {
	h := newE2E(t)

	chunked := t.TempDir()
	h.init(chunked)
	writeTree(t, chunked, "a.txt", "A")
	h.sync(chunked)

	packed := t.TempDir()
	writePackConfig(t, packed)
	h.init(packed)
	writeTree(t, packed, "b.txt", "B")
	h.sync(packed)

	cases := []struct {
		name    string
		root    string
		format  syncFormat
		wantErr string // empty means the resource is accepted in this mode
	}{
		{"chunked as chunked", chunked, formatChunked, ""},
		{"chunked as pack", chunked, formatPacked, "was created chunked"},
		{"pack as pack", packed, formatPacked, ""},
		{"pack as chunked", packed, formatChunked, "pack-and-seal on the server"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := openSyncSession(tc.root, syncOptions{})
			if err != nil {
				t.Fatalf("openSyncSession: %v", err)
			}
			defer sess.Wipe()

			rs, err := sess.openRemote(syncOptions{}, tc.format)
			if tc.wantErr != "" {
				if err == nil {
					rs.ck.Wipe()
					t.Fatalf("openRemote accepted the resource, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("openRemote = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("openRemote: %v", err)
			}
			defer rs.ck.Wipe()
			if !rs.trustBase {
				t.Fatal("openRemote distrusted the base of a freshly synced folder")
			}
			if rs.meta.Packed != (tc.format == formatPacked) {
				t.Fatalf("decoded meta %+v does not match mode %v", rs.meta, tc.format)
			}
		})
	}
}

// TestOpenRemoteRollbackOutranksFormatMismatch pins the ordering the shared prologue
// unified on: a rolled-back server is a data-integrity signal about the server, so it
// must be reported even when a local .aqtconfig also names the wrong format. The pack
// adapter used to decode metadata first and hide the rollback behind the mismatch.
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

	// The folder is chunked on the server, so the pack mode is a cross-mode mismatch
	// as well as a rollback; the rollback must win.
	if _, err := sess.openRemote(syncOptions{}, formatPacked); !errors.Is(err, errRollback) {
		t.Fatalf("openRemote on a rolled-back cross-mode folder = %v, want errRollback", err)
	}

	// Accepting the rollback drops the base for this pass, which is what makes each
	// adapter reconcile from scratch instead of clobbering newer local files.
	rs, err := sess.openRemote(syncOptions{acceptRollback: true}, formatChunked)
	if err != nil {
		t.Fatalf("openRemote with --accept-rollback: %v", err)
	}
	defer rs.ck.Wipe()
	if rs.trustBase {
		t.Fatal("openRemote trusted the base after accepting a rollback")
	}
}

// TestPackSyncReportsRollbackOverConfigMismatch is the end-to-end shape of the
// ordering change: a stray pack=true on a chunked folder routes the sync to the pack
// adapter, which now surfaces the rolled-back server rather than the config typo.
func TestPackSyncReportsRollbackOverConfigMismatch(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	backup := h.snapshotServerData()
	writeTree(t, origin, "newer.txt", "written after the backup")
	h.sync(origin)
	h.restoreServer(backup)

	writePackConfig(t, origin)
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errRollback) {
		t.Fatalf("pack-routed sync of a rolled-back chunked folder = %v, want errRollback", err)
	}
	if got := readTree(t, origin, "newer.txt"); got != "written after the backup" {
		t.Fatalf("refused sync touched local files: %q", got)
	}
}
