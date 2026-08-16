// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// TestCheckSyncFormat pins the server-truth routing: a packed resource is the
// removed pack-and-seal format (refused with the recovery hint), a legacy folder
// without the Tree flag is unsupported, and a tree folder is accepted.
func TestCheckSyncFormat(t *testing.T) {
	cases := []struct {
		name string
		meta api.Metadata
		want string // substring of the expected error; empty means accepted
	}{
		{"chunked tree folder", api.Metadata{Tree: true}, ""},
		{"packed folder", api.Metadata{Packed: true}, "no longer supported"},
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

// markResourcePacked flips a tracked folder's sealed metadata to the removed
// pack-and-seal format server-side, emulating a resource written by an old client.
func markResourcePacked(t *testing.T, root string) {
	t.Helper()
	st, err := loadState(root)
	if err != nil {
		t.Fatal(err)
	}
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	res, err := cl.GetResource(st.ID)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Wipe()
	meta, err := decodeMeta(res.EncryptedMeta, ck, st.ID)
	if err != nil {
		t.Fatal(err)
	}
	meta.Packed, meta.Tree = true, false
	plain, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.SealBound(plain, ck, crypto.AADMeta, st.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.UpdateResourceMetadata(st.ID, api.UpdateResourceMetadataRequest{
		EncryptedMeta: sealed, ExpectedVersion: res.Version,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOpenRemoteRefusesPackedResource drives the shared per-attempt prologue
// against a resource whose server-side metadata names the removed pack-and-seal
// format: the sync must refuse with the recovery hint instead of reconciling the
// opaque blob as an empty chunked manifest (the silent tree-wipe).
func TestOpenRemoteRefusesPackedResource(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "A")
	h.sync(origin)
	markResourcePacked(t, origin)

	sess, err := openSyncSession(origin, syncOptions{})
	if err != nil {
		t.Fatalf("openSyncSession: %v", err)
	}
	defer sess.Wipe()
	if _, err := sess.openRemote(syncOptions{}); !errors.Is(err, errPackRemoved) {
		t.Fatalf("openRemote on a packed resource = %v, want errPackRemoved", err)
	}

	// The full sync path refuses the same way and leaves local files untouched.
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errPackRemoved) {
		t.Fatalf("sync of a packed resource = %v, want errPackRemoved", err)
	}
	if got := readTree(t, origin, "a.txt"); got != "A" {
		t.Fatalf("refused sync touched local files: %q", got)
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

// TestSyncRefusesStalePackConfig: a stray pack=true in .aqtconfig names the removed
// format and is refused up front with the recovery hint, before any server call.
func TestSyncRefusesStalePackConfig(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	if err := os.WriteFile(filepath.Join(origin, ".aqtconfig"), []byte(`{"pack": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errPackRemoved) {
		t.Fatalf("sync with stale pack config = %v, want errPackRemoved", err)
	}
	if got := readTree(t, origin, "keep.txt"); got != "v1" {
		t.Fatalf("refused sync touched local files: %q", got)
	}
}
