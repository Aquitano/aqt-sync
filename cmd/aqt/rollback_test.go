// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"io"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/server"
)

// snapshotServerData copies the server's data directory (SQLite db, packs, blobs),
// modeling the backup a rolled-back server is later restored from.
func (h *e2eHarness) snapshotServerData() string {
	h.t.Helper()
	dst := h.t.TempDir()
	err := filepath.WalkDir(h.dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(h.dataDir, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyRegularFile(p, target)
	})
	if err != nil {
		h.t.Fatalf("snapshot server data: %v", err)
	}
	return dst
}

// restoreServer brings up a server on an earlier data-directory snapshot and points
// the profile at it — the client-visible shape of a restore from backup.
func (h *e2eHarness) restoreServer(dataDir string) {
	h.t.Helper()
	store, err := server.OpenStore(dataDir)
	if err != nil {
		h.t.Fatalf("open restored store: %v", err)
	}
	h.t.Cleanup(func() { store.Close() })
	ts := httptest.NewServer(server.New(store).Router())
	h.t.Cleanup(ts.Close)
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		h.t.Fatalf("load profile: %v", err)
	}
	prof.Server = ts.URL
	if err := identity.Save(prof); err != nil {
		h.t.Fatalf("save profile: %v", err)
	}
	h.url, h.dataDir = ts.URL, dataDir
}

func copyRegularFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// TestSyncRefusesServerRollback covers the freshness guard on the chunked path: a
// server restored from a backup reports an older version, and treating that as
// remote changes would delete files created after the backup. The sync must refuse;
// --accept-rollback reconciles from scratch, so the one-sided difference surfaces
// as a conflict instead of a silent delete, and --force resolves it local-wins.
func TestSyncRefusesServerRollback(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	backup := h.snapshotServerData()
	writeTree(t, origin, "newer.txt", "written after the backup")
	h.sync(origin)

	h.restoreServer(backup)

	if err := runSync(origin, syncOptions{}); !errors.Is(err, errRollback) {
		t.Fatalf("sync against a rolled-back server = %v, want errRollback", err)
	}
	if got := readTree(t, origin, "newer.txt"); got != "written after the backup" {
		t.Fatalf("refused sync still touched local files: %q", got)
	}

	if err := runSync(origin, syncOptions{acceptRollback: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("accepted rollback = %v, want errConflictsRemain", err)
	}
	if got := readTree(t, origin, "newer.txt"); got != "written after the backup" {
		t.Fatalf("accepted rollback deleted a newer local file: %q", got)
	}

	h.syncOpts(origin, syncOptions{acceptRollback: true, force: true})
	h.sync(origin) // the forced push re-pinned the version; plain syncs work again
	if got := readTree(t, origin, "keep.txt"); got != "v1" {
		t.Fatalf("keep.txt corrupted: %q", got)
	}
	if got := readTree(t, origin, "newer.txt"); got != "written after the backup" {
		t.Fatalf("newer.txt lost after the forced reconcile: %q", got)
	}
}

func TestRollbackGuardSkipsLegacyState(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	h.sync(origin)

	backup := h.snapshotServerData()
	writeTree(t, origin, "newer.txt", "gone after the legacy pull")
	h.sync(origin)

	h.restoreServer(backup)

	st, err := loadState(origin)
	if err != nil {
		t.Fatal(err)
	}
	st.RemoteVersion = 0
	if err := saveState(origin, st); err != nil {
		t.Fatal(err)
	}

	h.sync(origin) // unpinned: legacy behavior, the rollback is pulled
	assertAbsent(t, origin, "newer.txt")
	st, err = loadState(origin)
	if err != nil {
		t.Fatal(err)
	}
	if st.RemoteVersion == 0 {
		t.Fatal("sync did not record a fresh version pin")
	}
}
