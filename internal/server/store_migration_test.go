// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"database/sql"
	"fmt"
	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countBlobs returns the number of blob files anywhere under dir. Blobs fan out by
// id prefix (blobs/<ab>/<cd>/...), so they are no longer direct children of blobsDir.
func countBlobs(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".bin") {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Re-opening a data dir re-runs migrate as a no-op (user_version gates already-applied
// steps), and the scaffold has created the device-token index.
func TestMigrateIsIdempotentAndIndexesDeviceToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s2, err := OpenStore(dir) // second migrate over the same dir must not error
	if err != nil {
		t.Fatalf("re-open after migrate: %v", err)
	}
	defer func() { _ = s2.Close() }()

	var uv int
	if err := s2.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d, want %d (all migrations applied)", uv, len(migrations))
	}
	var name string
	if err := s2.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_devices_token_hash'`,
	).Scan(&name); err != nil {
		t.Fatalf("device-token index missing after migrate: %v", err)
	}
}

// seedSchemaAt builds a data dir holding exactly the first k migration steps — what
// the release that shipped step k would have left behind — without going through
// OpenStore, which would run the whole chain.
func seedSchemaAt(t *testing.T, dir string, k int) {
	t.Helper()
	for _, d := range []string{"blobs", "packs"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "aqt.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for i := range k {
		if _, err := db.Exec(migrations[i]); err != nil {
			t.Fatalf("seed migration %d: %v", i+1, err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, k)); err != nil {
		t.Fatal(err)
	}
}

// A data dir written by any older release migrates forward to the current schema.
// The idempotency test above only re-opens an already-current dir, so it never
// exercises a step running against the shape that preceded it. This covers schema
// shape only: the seeded dirs hold no rows, so a step's backfill UPDATE runs over an
// empty table.
func TestMigrateForwardFromEveryVersion(t *testing.T) {
	t.Parallel()
	for k := range migrations {
		t.Run(fmt.Sprintf("from_v%d", k), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			seedSchemaAt(t, dir, k)
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatalf("migrate forward from user_version %d: %v", k, err)
			}
			defer func() { _ = s.Close() }()
			var uv int
			if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
				t.Fatal(err)
			}
			if uv != len(migrations) {
				t.Fatalf("user_version = %d after migrating from %d, want %d", uv, k, len(migrations))
			}
		})
	}
}

// A step that fails partway must leave nothing behind: not its already-executed
// statements, and not a user_version bump. Otherwise the next start replays the step
// over its own half-applied output and fails forever with `duplicate column name`.
func TestFailedMigrationStepRollsBackWhole(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// Shaped like a real step: an ALTER TABLE ADD COLUMN that succeeds, then a
	// statement that does not — the power-loss-in-the-middle case, only deterministic.
	step := "ALTER TABLE accounts ADD COLUMN wedge_probe INTEGER NOT NULL DEFAULT 0;"
	if err := s.applyMigration(len(migrations)+1, step+"\nALTER TABLE no_such_table ADD COLUMN x INTEGER;"); err == nil {
		t.Fatal("applyMigration accepted a step whose second statement is invalid")
	}

	var uv int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d after a failed step, want %d (bumped despite the failure)", uv, len(migrations))
	}
	if _, err := s.db.Exec(`SELECT wedge_probe FROM accounts`); err == nil {
		t.Fatal("the failed step's first statement survived the rollback")
	}

	// The point of the rollback: with the transient cause gone, the step applies. If
	// its first statement had survived, this is where the data dir wedges forever with
	// `duplicate column name`.
	if err := s.applyMigration(len(migrations)+1, step); err != nil {
		t.Fatalf("retry of a rolled-back step: %v", err)
	}
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations)+1 {
		t.Fatalf("user_version = %d after the retry, want %d", uv, len(migrations)+1)
	}
	if _, err := s.db.Exec(`SELECT wedge_probe FROM accounts`); err != nil {
		t.Fatalf("retry did not apply the step: %v", err)
	}
}

// The crash-window guarantee rests on the driver journaling PRAGMA user_version with
// the transaction: a bump inside a rolled-back tx must be undone, or an interrupted
// migration leaves the version ahead of the schema. The rollback test above fails
// before its bump runs, so this pins the driver behavior itself against upgrades.
func TestUserVersionRollsBackWithTransaction(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+7)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var uv int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != len(migrations) {
		t.Fatalf("user_version = %d after rollback, want %d: the driver no longer journals the pragma", uv, len(migrations))
	}
}

// A data dir a newer aqt-server has already migrated is refused, not served against
// a schema this build does not understand.
func TestMigrateRefusesNewerDataDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+3)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	_, err = OpenStore(dir)
	if err == nil {
		t.Fatal("OpenStore accepted a data dir migrated by a newer build")
	}
	if !strings.Contains(err.Error(), "newer aqt-server") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// A data dir from the even-older flat layout (resource_chunks without owner_handle)
// must also be rejected loudly.
func TestStaleResourceChunksSchemaFailsLoud(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", filepath.Join(dir, "aqt.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(
		`CREATE TABLE resource_chunks (resource_id TEXT NOT NULL, chunk_id TEXT NOT NULL, PRIMARY KEY(resource_id, chunk_id))`,
	); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "older build") {
		t.Fatalf("OpenStore on a legacy schema = %v, want a clear stale-schema error", err)
	}
}

// Usage reads blob_size unconditionally, so the startup backfill is what makes
// rows written before migration 16 countable. A row whose file is gone (operator
// deletion, crash-window orphan) records 0 rather than failing the boot: a hard
// error there would wedge every account, since AccountUsage feeds metrics, pack
// and resource puts, and auto-snapshots.
func TestBlobSizeBackfillRunsAtStartup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	owner := s.mustAccount(t, "backfill@example.com")
	ck, _ := crypto.GenerateContentKey()
	meta, _ := crypto.Seal([]byte(`{"name":"f","size":4}`), ck, crypto.AADMeta)
	wrapped, _ := crypto.WrapKey(ck, [crypto.KeySize]byte{})
	put := func(body string) (string, crypto.SealedBlob) {
		blob, _ := crypto.Seal([]byte(body), ck, crypto.AADBlob)
		id, _, err := s.PutResource(owner, api.ClientCapability, api.PutResourceRequest{
			Visibility: api.Private, Blob: blob, EncryptedMeta: meta, WrappedKey: &wrapped,
			MinClient: api.CapabilityBaseline,
		})
		if err != nil {
			t.Fatal(err)
		}
		return id, blob
	}
	kept, keptBlob := put("body")
	orphan, orphanBlob := put("orphaned body")

	// Age both rows back to the pre-migration-16 state, and strip one of its file.
	if _, err := s.db.Exec(`UPDATE resources SET blob_size = -1`); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.blobPath(orphan, orphanBlob.Nonce)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenStore(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	size := func(id string) int64 {
		var n int64
		if err := s.db.QueryRow(`SELECT blob_size FROM resources WHERE id = ?`, id).Scan(&n); err != nil {
			t.Fatalf("read blob_size: %v", err)
		}
		return n
	}
	if got, want := size(kept), int64(len(keptBlob.Ciphertext)); got != want {
		t.Fatalf("backfilled blob_size = %d, want %d", got, want)
	}
	if got := size(orphan); got != 0 {
		t.Fatalf("orphaned row blob_size = %d, want 0", got)
	}
	blobBytes, err := s.ownerBlobBytes(owner)
	if err != nil {
		t.Fatalf("usage after backfill: %v", err)
	}
	if want := int64(len(keptBlob.Ciphertext)); blobBytes != want {
		t.Fatalf("blob bytes after backfill = %d, want %d", blobBytes, want)
	}
}
