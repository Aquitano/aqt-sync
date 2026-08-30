// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite"

	"github.com/aquitano/aqt-sync/internal/api"
)

// ErrNotFound is returned when a lookup misses. Handlers map it to 404, which is
// also what an unauthorized access to a private resource returns (no oracle).
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a unique constraint (e.g. duplicate email) fails.
var ErrConflict = errors.New("conflict")

// ErrVersionConflict is returned when an update's ExpectedVersion no longer
// matches the stored version: another writer got there first.
var ErrVersionConflict = errors.New("version conflict")

// ErrIdempotencyConflict is returned when a key is reused with another payload.
var ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")

// ErrSharedNeedsRefs is returned when a refs-less write targets a public or granted
// resource whose prior version carried refs. ChunkRefs are the scope of object ids
// a non-owner reader may fetch, so dropping them from a shared resource would leave
// its readers unable to fetch any new content. Handlers map it to 400.
var ErrSharedNeedsRefs = errors.New("a public or granted resource must carry its chunk refs")

// ErrNonceReuse is returned when a replace carries the blob nonce the resource already
// stores. Blobs are addressed by id+nonce and treated as immutable per nonce, so a
// repeated nonce would make the new write target the live file. Handlers map it to 400.
var ErrNonceReuse = errors.New("replace reuses the stored blob nonce")

// ErrQuotaExceeded is returned when storing a pack would push an owner's stored bytes
// past the configured quota. Handlers map it to 507; the client surfaces it clearly.
var ErrQuotaExceeded = errors.New("storage quota exceeded")

type LimitExceededError struct {
	Kind           string
	Current, Limit int64
}

func (e *LimitExceededError) Error() string {
	return fmt.Sprintf("%s limit exceeded: current=%d limit=%d", e.Kind, e.Current, e.Limit)
}
func (e *LimitExceededError) Unwrap() error { return ErrQuotaExceeded }

// ErrSnapshotAnchored is returned when a delete targets an anchored snapshot. Anchors
// exist precisely so retention (and an accidental explicit prune) cannot drop a pinned
// checkpoint, so the store refuses the delete rather than trusting the client to skip
// it. Handlers map it to 409 with the anchored error code.
var ErrSnapshotAnchored = errors.New("snapshot is anchored")

// ErrGone is returned when a public link has expired, reached its read limit, or had
// its ciphertext reclaimed. Handlers map it to 410 so a link holder learns the link is
// dead rather than seeing an indistinguishable 404. Distinct from ErrNotFound so the
// tombstone never decays to "never existed".
var ErrGone = errors.New("resource gone")

// ErrPolicyOnPrivate is returned when a lifecycle policy (expiry/max-reads) is attached
// to a non-public resource. Lifecycle is a property of the public link, so this is a
// client bug; handlers map it to 400.
var ErrPolicyOnPrivate = errors.New("lifecycle policy requires a public resource")

// ErrBadPolicy is returned when a policy carries a negative expiry or read limit.
// Handlers map it to 400.
var ErrBadPolicy = errors.New("lifecycle policy values must be non-negative")

// ErrGitRemotePolicy is returned when an operation would expose or reclassify a
// git-remote resource. Git remotes are private-only in v1 and cannot carry grants.
var ErrGitRemotePolicy = errors.New("git remote resources are private and cannot be shared")

// ErrDeviceLimit is returned when a device attach hits the account's cap. Handlers
// map it to 403.
var ErrDeviceLimit = errors.New("device limit reached")

// UpgradeRequiredError is returned when a write targets a resource whose stored
// min_client exceeds the writer's capability: a client that cannot read the current
// state must not overwrite it. MinClient is the capability the resource needs.
// Handlers map it to 426.
type UpgradeRequiredError struct{ MinClient int }

func (e *UpgradeRequiredError) Error() string {
	return fmt.Sprintf("resource requires client capability %d", e.MinClient)
}

func validateGitRemotePolicy(req api.PutResourceRequest, storedCompactAt int) (int, error) {
	if req.CompactAt < 0 {
		return 0, ErrGitRemotePolicy
	}
	compactAt := req.CompactAt
	if storedCompactAt > 0 {
		if compactAt == 0 {
			compactAt = storedCompactAt
		}
		if compactAt != storedCompactAt || req.MinClient < api.CapabilityGitRemote || req.Visibility != api.Private {
			return 0, ErrGitRemotePolicy
		}
		return compactAt, nil
	}
	if req.ID != "" && compactAt > 0 {
		return 0, ErrGitRemotePolicy // resource kinds are immutable
	}
	if compactAt > 0 && (req.MinClient < api.CapabilityGitRemote || req.Visibility != api.Private) {
		return 0, ErrGitRemotePolicy
	}
	return compactAt, nil
}

// resolvePolicy validates a lifecycle request and turns it into the stored columns.
// expireSeconds is a TTL: the absolute expires_at is now + TTL, so a client never has
// to agree with the server's clock. A policy is legal only on a public resource. A
// zero field means "no limit" (NULL). Negative values, or an unknown on-expiry action,
// are a client bug.
func resolvePolicy(vis api.Visibility, expireSeconds, maxReads int64, onExpiry api.OnExpiry, now int64) (expiresAt, max sql.NullInt64, action string, err error) {
	if expireSeconds < 0 || maxReads < 0 {
		return sql.NullInt64{}, sql.NullInt64{}, "", ErrBadPolicy
	}
	if (expireSeconds > 0 || maxReads > 0) && vis != api.Public {
		return sql.NullInt64{}, sql.NullInt64{}, "", ErrPolicyOnPrivate
	}
	action, err = storedOnExpiry(onExpiry)
	if err != nil {
		return sql.NullInt64{}, sql.NullInt64{}, "", err
	}
	if expireSeconds > 0 {
		expiresAt = sql.NullInt64{Int64: now + expireSeconds, Valid: true}
	}
	if maxReads > 0 {
		max = sql.NullInt64{Int64: maxReads, Valid: true}
	}
	return expiresAt, max, action, nil
}

// storedOnExpiry maps a requested end-of-life action to the on_expiry column value, and
// is the only place that mapping lives: the response echo goes through it too, so the
// server can never promise one action and store another. An absent action is reclaim:
// that is what every client written before the field existed meant, and what the server
// did for them. An unknown action is a client bug.
func storedOnExpiry(onExpiry api.OnExpiry) (string, error) {
	switch onExpiry {
	case "", api.ExpiryReclaim:
		return string(api.ExpiryReclaim), nil
	case api.ExpiryRetire:
		return string(api.ExpiryRetire), nil
	default:
		return "", ErrBadPolicy
	}
}

// queryer is the read subset shared by *sql.DB and *sql.Tx, so a query helper runs
// unchanged inside or outside a write transaction.
type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Store persists accounts, devices, and resource metadata in SQLite, with the
// ciphertext blobs and packs on the filesystem. It holds no plaintext and no live
// keys.
type Store struct {
	db *sql.DB
	// rdb is a read-only pool over the same database file. WAL lets its readers run
	// concurrently with the single writer connection, so GETs, auth lookups, and GC
	// planning no longer queue behind writes. Reads that are part of a mutation flow
	// (inside a write transaction or under a resource lock) stay on db.
	rdb *sql.DB
	// usageStmt and blobBytesStmt are the two statements behind AccountUsage,
	// prepared once: the usage query is the most expensive statement in the server
	// to parse (~1 KB of subqueries) and it runs on every quota-checked write, so
	// re-parsing it per call cost more than executing it on an empty account.
	usageStmt     *sql.Stmt
	blobBytesStmt *sql.Stmt
	auth          *authCache
	// suspended memoizes per-account suspension. It is separate from auth because
	// an operator writes it from another process, so it needs a much shorter expiry
	// than a token resolution this process controls. See suspensionTTL.
	suspended *suspensionCache
	blobsDir  string
	packsDir  string
	// gcLocks serializes the GC/repack sequence per owner. The single DB connection
	// serializes the transactions, but not the pack-file writes and removes around
	// them, so two concurrent passes could double-handle a repack candidate; this lock
	// closes that window. See GC.
	gcLocks *keyedMutex
	// resLocks serializes mutations of a single resource (update, visibility change,
	// delete) against each other and against a snapshot capturing that resource. It
	// lives in the store rather than the HTTP layer so the keyless scheduled snapshot
	// job (RunAutoSnapshots, which never goes through a handler) is serialized the same
	// way a manual snapshot is; otherwise it could capture a torn (blob, chunk-roots)
	// pair from a concurrent sync.
	resLocks *keyedMutex
}

func OpenStore(dataDir string) (*Store, error) {
	blobsDir := filepath.Join(dataDir, "blobs")
	packsDir := filepath.Join(dataDir, "packs")
	for _, d := range []string{blobsDir, packsDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	// busy_timeout lets a writer wait out a momentarily-locked database instead
	// of failing the request with SQLITE_BUSY; WAL keeps readers off the writer's
	// back; foreign_keys turns on the resource_chunks -> chunks reference so a
	// dangling chunk reference fails the write loudly instead of inserting silently.
	dbPath := filepath.Join(dataDir, "aqt.db")
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// One writer connection. The store has no in-process lock around chunk
	// uploads, GC, or creates, so two writers on separate connections would race
	// to SQLITE_BUSY and surface as 500s the client never retries. A single
	// connection serializes every write in-process. This suits the v1
	// single-instance server; horizontal scaling would need real row locks.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, auth: newAuthCache(), suspended: newSuspensionCache(), blobsDir: blobsDir, packsDir: packsDir, gcLocks: newKeyedMutex(), resLocks: newKeyedMutex()}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// One-shot: migration 16 left pre-existing rows without a recorded blob size, and
	// usage now reads the column unconditionally. A dir that has already been through
	// it has no rows to visit.
	if err := s.backfillBlobSizes(); err != nil {
		db.Close()
		return nil, fmt.Errorf("backfill blob sizes: %w", err)
	}
	// The read pool. query_only makes a stray write on it fail loudly instead of
	// racing the writer to SQLITE_BUSY; a fresh read transaction per query sees the
	// latest committed write, so read-your-writes holds for request flows that
	// commit on db before reading on rdb.
	rdsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=query_only(1)"
	rdb, err := sql.Open("sqlite", rdsn)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open read pool: %w", err)
	}
	rdb.SetMaxOpenConns(max(4, runtime.NumCPU()))
	s.rdb = rdb
	if s.usageStmt, err = rdb.Prepare(accountUsageQuery); err != nil {
		s.Close()
		return nil, fmt.Errorf("prepare usage query: %w", err)
	}
	if s.blobBytesStmt, err = rdb.Prepare(ownerBlobBytesQuery); err != nil {
		s.Close()
		return nil, fmt.Errorf("prepare blob-bytes query: %w", err)
	}
	return s, nil
}

func (s *Store) Ping() error {
	var one int
	return s.rdb.QueryRow(`SELECT 1`).Scan(&one)
}

func (s *Store) Close() error {
	if s.usageStmt != nil {
		s.usageStmt.Close()
	}
	if s.blobBytesStmt != nil {
		s.blobBytesStmt.Close()
	}
	rerr := s.rdb.Close()
	if err := s.db.Close(); err != nil {
		return err
	}
	return rerr
}

// migrations are the forward-only schema steps, applied in order and tracked by
// PRAGMA user_version. Append new steps; never edit or reorder a shipped one.
//
// Step 1 creates every table with IF NOT EXISTS, so re-running it over a data dir
// created before this scaffold (user_version still 0) is a harmless no-op that then
// lets the later steps apply in place — no wipe-and-resync for additive changes.
// Later steps are mostly ALTER TABLE ADD COLUMN, which is *not* idempotent; migrate
// applies each step and its user_version bump in one transaction so a step never
// half-lands and wedges the next start with `duplicate column name`.
var migrations = []string{
	// 1: v1 baseline.
	`
CREATE TABLE IF NOT EXISTS accounts (
    owner_handle TEXT PRIMARY KEY,
    email        TEXT UNIQUE NOT NULL,
    kdf          TEXT NOT NULL,
    public_key   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id    TEXT PRIMARY KEY,
    owner_handle TEXT NOT NULL REFERENCES accounts(owner_handle),
    name         TEXT NOT NULL,
    token_hash   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    nonce      BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resources (
    id             TEXT PRIMARY KEY,
    owner_handle   TEXT NOT NULL REFERENCES accounts(owner_handle),
    visibility     TEXT NOT NULL,
    encrypted_meta TEXT NOT NULL,
    wrapped_key    TEXT,
    blob_nonce     BLOB NOT NULL,
    version        INTEGER NOT NULL
);
-- A pack is one immutable file of concatenated ciphertext objects. created_at is
-- the GC age guard: a pack younger than gcMinAge is never swept, so an in-flight
-- push's freshly uploaded pack survives until its manifest commits.
CREATE TABLE IF NOT EXISTS packs (
    owner_handle TEXT NOT NULL,
    pack_id      TEXT NOT NULL,
    length       INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY(owner_handle, pack_id)
);
-- Where each object lives: chunk_id (the content address, also the dedup key)
-- maps to a slice of one pack. Replaces the old per-chunk file model.
CREATE TABLE IF NOT EXISTS objects (
    owner_handle TEXT NOT NULL,
    chunk_id     TEXT NOT NULL,
    pack_id      TEXT NOT NULL,
    offset       INTEGER NOT NULL,
    length       INTEGER NOT NULL,
    PRIMARY KEY(owner_handle, chunk_id),
    FOREIGN KEY(owner_handle, pack_id) REFERENCES packs(owner_handle, pack_id)
);
CREATE INDEX IF NOT EXISTS idx_objects_pack ON objects(owner_handle, pack_id);
-- Which objects a resource's current manifest references; the GC roots. Replaced
-- in full on every resource write, so it always reflects the live manifest. The
-- FK to objects (with foreign_keys on) is the backstop for the GC/dedup race: a
-- manifest that references an object the owner no longer stores is rejected at PUT
-- rather than committing a dangling reference that a later clone/pull can't read.
CREATE TABLE IF NOT EXISTS resource_chunks (
    resource_id  TEXT NOT NULL,
    owner_handle TEXT NOT NULL,
    chunk_id     TEXT NOT NULL,
    PRIMARY KEY(resource_id, chunk_id),
    FOREIGN KEY(owner_handle, chunk_id) REFERENCES objects(owner_handle, chunk_id)
);
CREATE INDEX IF NOT EXISTS idx_resource_chunks_chunk ON resource_chunks(chunk_id);`,
	// 2: index the device-token lookup authMiddleware runs on every request, and
	// enforce token uniqueness.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);`,
	// 3: wrapped-root identity. The master key is now a random root key wrapped under
	// the passphrase-derived unlock key (wrapped_root), so a passphrase change re-wraps
	// it without re-encrypting data. auth_verifier is the hash of the passphrase proof a
	// device must present to attach; auth_epoch invalidates every token issued before
	// the latest passphrase change (a device's token is valid only while its epoch
	// matches its account's). server_meta holds the secret that makes an unknown-email
	// bootstrap return an indistinguishable decoy.
	`ALTER TABLE accounts ADD COLUMN wrapped_root TEXT NOT NULL DEFAULT '';
	 ALTER TABLE accounts ADD COLUMN auth_verifier BLOB NOT NULL DEFAULT x'';
	 ALTER TABLE accounts ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 1;
	 ALTER TABLE devices ADD COLUMN auth_epoch INTEGER NOT NULL DEFAULT 1;
	 CREATE TABLE IF NOT EXISTS server_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);`,
	// 4: snapshots. A snapshot is a frozen copy of a resource version: its sealed
	// root blob (stored as a snapshot-owned blob file, so a later resource update or
	// delete cannot reclaim it) plus the chunk roots it referenced at snapshot time.
	// snapshot_chunks mirrors resource_chunks and is unioned into the GC root set, so
	// the objects a snapshot needs survive the sweep that drops the live resource's
	// own roots. auto_snapshot is the per-resource opt-out for the scheduled job.
	`CREATE TABLE IF NOT EXISTS snapshots (
	    snapshot_id      TEXT PRIMARY KEY,
	    owner_handle     TEXT NOT NULL,
	    resource_id      TEXT NOT NULL,
	    visibility       TEXT NOT NULL,
	    encrypted_meta   TEXT NOT NULL,
	    wrapped_key      TEXT,
	    blob_nonce       BLOB NOT NULL,
	    version_captured INTEGER NOT NULL,
	    created_at       INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_snapshots_owner ON snapshots(owner_handle, resource_id);
	CREATE TABLE IF NOT EXISTS snapshot_chunks (
	    snapshot_id  TEXT NOT NULL,
	    owner_handle TEXT NOT NULL,
	    chunk_id     TEXT NOT NULL,
	    PRIMARY KEY(snapshot_id, chunk_id),
	    FOREIGN KEY(owner_handle, chunk_id) REFERENCES objects(owner_handle, chunk_id)
	);
	CREATE INDEX IF NOT EXISTS idx_snapshot_chunks_chunk ON snapshot_chunks(chunk_id);
	ALTER TABLE resources ADD COLUMN auto_snapshot INTEGER NOT NULL DEFAULT 1;`,
	// 5: optional snapshot label, sealed by the client under the resource content key
	// (NULL on scheduled snapshots, which the keyless server cannot seal). Stored
	// opaquely; the server never reads it.
	`ALTER TABLE snapshots ADD COLUMN encrypted_label TEXT;`,
	// 6: mark snapshots the scheduled job created, so server-side retention prunes
	// only those and never a user's manual snapshot. Pre-existing rows cannot be
	// classified and stay manual (never auto-pruned).
	`ALTER TABLE snapshots ADD COLUMN scheduled INTEGER NOT NULL DEFAULT 0;`,
	// 7: per-owner stored-pack-byte counter for quota enforcement. Maintained
	// incrementally in the pack put/GC/repack transactions so a quota check never
	// scans the objects table; backfilled from the current pack sizes so an existing
	// data dir starts accurate.
	`ALTER TABLE accounts ADD COLUMN pack_bytes INTEGER NOT NULL DEFAULT 0;
	 UPDATE accounts SET pack_bytes = COALESCE(
	     (SELECT SUM(length) FROM packs WHERE packs.owner_handle = accounts.owner_handle), 0);`,
	// 8: per-pack object counters, so GC candidate selection reads the packs table
	// alone instead of scanning every object row with liveness subqueries per run.
	// obj_count is the pack's object rows; live_count/live_bytes are the subset some
	// resource or snapshot roots. Maintained incrementally by every write that moves
	// objects or roots (see recountPacks); backfilled here for existing rows. The
	// backfill UPDATE is this migration's own frozen copy of the recount, not shared
	// with the runtime helper, so later changes to the helper cannot rewrite a
	// shipped migration.
	`ALTER TABLE packs ADD COLUMN obj_count INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE packs ADD COLUMN live_count INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE packs ADD COLUMN live_bytes INTEGER NOT NULL DEFAULT 0;
	 UPDATE packs SET
	   obj_count = (SELECT count(*) FROM objects o
	                WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id),
	   live_count = (SELECT count(*) FROM objects o
	                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id
	                   AND (EXISTS(SELECT 1 FROM resource_chunks rc
	                               WHERE rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id)
	                        OR EXISTS(SELECT 1 FROM snapshot_chunks sc
	                                  WHERE sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id))),
	   live_bytes = COALESCE((SELECT sum(o.length) FROM objects o
	                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id
	                   AND (EXISTS(SELECT 1 FROM resource_chunks rc
	                               WHERE rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id)
	                        OR EXISTS(SELECT 1 FROM snapshot_chunks sc
	                                  WHERE sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id))), 0);`,
	// 9: min_client is the lowest client capability that can read a resource's (or a
	// snapshot's) sealed formats. Existing rows default to 1 (v0.1.0 baseline): they
	// were written before capability negotiation and are readable by every release, so
	// the server must not start rejecting reads of them. A capable client re-declares a
	// higher value the next time it writes an id-bound format. A snapshot copies the
	// value from its source resource at capture time.
	`ALTER TABLE resources ADD COLUMN min_client INTEGER NOT NULL DEFAULT 1;
	 ALTER TABLE snapshots ADD COLUMN min_client INTEGER NOT NULL DEFAULT 1;`,
	// 10: server-enforced lifecycle for public links. expires_at (NULL = none) and
	// max_reads (NULL = none) are the policy; reads counts non-owner serves; exhausted_at
	// records when the read limit was reached (so the sweep can grant a grace window for
	// an in-flight streamed pull); reclaimed marks a tombstone whose ciphertext has been
	// reaped and which now returns 410 (not 404) forever. All default to "no policy", so
	// existing rows are unaffected.
	`ALTER TABLE resources ADD COLUMN expires_at INTEGER;
	 ALTER TABLE resources ADD COLUMN max_reads INTEGER;
	 ALTER TABLE resources ADD COLUMN reads INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE resources ADD COLUMN exhausted_at INTEGER;
	 ALTER TABLE resources ADD COLUMN reclaimed INTEGER NOT NULL DEFAULT 0;`,
	// 11: an anchor pins a snapshot against every retention path (the scheduled job's
	// prune, the client's --keep-last/--before selection, and an explicit prune,
	// which the store refuses). Like `scheduled`, it is a plaintext server-side boolean
	// so retention can act on it without a key; it leaks only "this snapshot is
	// protected", the same shape of leak as scheduled, while the name stays sealed.
	// Pre-existing rows default to unanchored.
	`ALTER TABLE snapshots ADD COLUMN anchored INTEGER NOT NULL DEFAULT 0;`,
	// 12: account-to-account grants. enc_public_key is the account's published X25519
	// key (derived client-side from the master key), enc_key_sig its Ed25519
	// self-signature; signup registers both, and only a row predating this migration
	// can be NULL. A grant row wraps one resource's content
	// key to one grantee (HPKE, client-sealed); the server stores it opaquely. No FK on
	// grantee_handle: a grant to a decoy handle (unknown-email lookup) must be accepted
	// indistinguishably from a real one, or grant creation becomes an existence oracle.
	`ALTER TABLE accounts ADD COLUMN enc_public_key BLOB;
	 ALTER TABLE accounts ADD COLUMN enc_key_sig BLOB;
	 CREATE TABLE IF NOT EXISTS grants (
	     resource_id    TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
	     owner_handle   TEXT NOT NULL,
	     grantee_handle TEXT NOT NULL,
	     wrapped_key    BLOB NOT NULL,
	     created_at     INTEGER NOT NULL,
	     PRIMARY KEY(resource_id, grantee_handle)
	 );
	 CREATE INDEX IF NOT EXISTS idx_grants_grantee ON grants(grantee_handle);`,
	// 13: on_expiry is what happens when a link's lifecycle policy fires. Migration 10
	// only ever reclaimed (destroy the ciphertext, leave a 410 tombstone), which is
	// right for an ephemeral `push --public --burn` but destroys the content behind a
	// link over a resource that existed first — a shared synced folder above all. The
	// writer now says which it meant. Existing rows default to 'reclaim', the behavior
	// they were written under.
	`ALTER TABLE resources ADD COLUMN on_expiry TEXT NOT NULL DEFAULT 'reclaim';`,
	// 14: resource timestamps support stable date sorting in the CLI. Existing
	// rows receive the migration time; subsequent writes maintain updated_at.
	`ALTER TABLE resources ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE resources ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
	 UPDATE resources SET created_at = unixepoch(), updated_at = unixepoch();`,
	// 15: retry-safe creation keys, scoped by owner and operation kind.
	`CREATE TABLE IF NOT EXISTS idempotency_keys (
	    owner_handle TEXT NOT NULL,
	    kind TEXT NOT NULL,
	    key TEXT NOT NULL,
	    request_hash BLOB NOT NULL,
	    response TEXT NOT NULL,
	    created_at INTEGER NOT NULL,
	    PRIMARY KEY(owner_handle, kind, key)
	);`,
	// 16: blob sizes recorded on write. Usage previously summed them with one
	// os.Stat per live resource and per snapshot, on the hot path of every resource
	// create, snapshot create, and pack PUT (all under the per-account lock) and for
	// every account on every Prometheus scrape. A column makes it one SUM. Existing
	// rows land at -1, meaning "not recorded"; OpenStore's backfillBlobSizes stats
	// those once at startup, so the column is authoritative from then on.
	`ALTER TABLE resources ADD COLUMN blob_size INTEGER NOT NULL DEFAULT -1;
	 ALTER TABLE snapshots ADD COLUMN blob_size INTEGER NOT NULL DEFAULT -1;`,
	// 17: a non-zero compact_at identifies a private git-remote resource and stores
	// its per-repository bundle compaction threshold. Repository names, refs, and
	// bundle topology remain inside the encrypted resource blob and metadata.
	`ALTER TABLE resources ADD COLUMN compact_at INTEGER NOT NULL DEFAULT 0;`,
	// 18: per-account operator overrides. quota_bytes NULL means "inherit
	// AQT_QUOTA_BYTES", which is distinct from 0 ("explicitly unlimited") — an
	// operator must be able to exempt one account on a server that caps the rest.
	// disabled_at is when an operator suspended the account; 0 is active. Suspension
	// is deliberately reversible and touches no ciphertext, unlike deletion.
	// created_at cannot be backfilled — nothing recorded it — so pre-existing rows
	// keep 0, which operator output renders as unknown rather than as the epoch.
	`ALTER TABLE accounts ADD COLUMN quota_bytes INTEGER;
	 ALTER TABLE accounts ADD COLUMN disabled_at INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE accounts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;`,
	// 19: grantee-side share blocks. Registration is open and the handle lookup is
	// unrestricted, so any account can append a row to any other account's incoming
	// shares; dropping that row only helps if the sender cannot re-add it. A block is
	// one (grantee, grantor) pair, and PutGrant refuses against it. No FK on either
	// handle: a block outlives the grant it came from, and a grant to a decoy handle
	// must stay indistinguishable from a grant to a real one.
	`CREATE TABLE IF NOT EXISTS share_blocks (
	     grantee_handle TEXT NOT NULL,
	     owner_handle   TEXT NOT NULL,
	     created_at     INTEGER NOT NULL,
	     PRIMARY KEY(grantee_handle, owner_handle)
	 );`,
	// 20: indexes for the per-owner scans the hot paths run. Usage accounting sums
	// resources, grants, and devices by owner on every quota-checked write; none of
	// the three had an owner-leading index, so each check scanned the whole table.
	// The auto-snapshot due query probes snapshots by (resource_id, version_captured)
	// per candidate resource, which idx_snapshots_owner cannot serve.
	`CREATE INDEX IF NOT EXISTS idx_resources_owner ON resources(owner_handle);
	 CREATE INDEX IF NOT EXISTS idx_grants_owner ON grants(owner_handle);
	 CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices(owner_handle);
	 CREATE INDEX IF NOT EXISTS idx_snapshots_resource_version ON snapshots(resource_id, version_captured);`,
	// 21: client-managed GC. Reachability moved into the client (`aqt prune`), whose
	// walk treats every snapshot as a root, so snapshot_chunks — the pin set the
	// server-side sweep unioned in — has no reader left. live_count counted a pack's
	// rooted objects; without server-side root tracking an object row is live until
	// its owner deletes it, making the column obj_count under another name. The
	// recount trues up counters on a data dir whose values still exclude objects the
	// old root tables did not reach.
	`DROP INDEX IF EXISTS idx_snapshot_chunks_chunk;
	 DROP TABLE IF EXISTS snapshot_chunks;
	 ALTER TABLE packs DROP COLUMN live_count;
	 UPDATE packs SET
	   obj_count = (SELECT count(*) FROM objects o
	                WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id),
	   live_bytes = COALESCE((SELECT sum(o.length) FROM objects o
	                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id), 0);`,
	// 22: per-owner object-row counter. The usage scan behind quota and row-cap
	// enforcement ran COUNT(*) over the owner's objects — its largest table — on
	// every quota-checked write, so pushing an account of total size S cost O(S^2).
	// Maintained incrementally, mirroring pack_bytes, in the same transactions that
	// insert or delete object rows (pack put, client chunk GC, pack GC, repack; an
	// account purge deletes the accounts row itself); backfilled so an existing
	// data dir starts accurate.
	`ALTER TABLE accounts ADD COLUMN object_count INTEGER NOT NULL DEFAULT 0;
	 UPDATE accounts SET object_count =
	     (SELECT COUNT(*) FROM objects WHERE objects.owner_handle = accounts.owner_handle);`,
}

// migrate applies the migrations a data dir has not yet run, then validates the
// resulting schema. PRAGMA user_version records how many steps have run.
func (s *Store) migrate() error {
	var applied int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&applied); err != nil {
		return err
	}
	// A data dir a newer build already migrated must fail closed. Serving it would
	// silently run today's queries against tomorrow's schema — writes skipping columns
	// a newer release depends on, defaults applied where the newer server would have
	// written a real value — and the damage only shows up after the operator rolls
	// forward again. Downgrading is not supported; say so instead of limping.
	if applied > len(migrations) {
		return fmt.Errorf("server data dir was migrated by a newer aqt-server "+
			"(schema version %d, this build understands %d); upgrade aqt-server, or restore "+
			"the data dir from a backup taken before the upgrade", applied, len(migrations))
	}
	// A legacy layout must fail loud before any step touches it: migration 8's
	// backfill reads resource_chunks.owner_handle, which the pre-pack layouts lack,
	// so applying it there would surface as an opaque SQL error instead of
	// checkSchema's recoverable instruction. A fresh dir has no resource_chunks yet
	// and skips this (migration 1 creates the current shape).
	if exists, err := s.tableExists("resource_chunks"); err != nil {
		return err
	} else if exists {
		if err := s.checkSchema(); err != nil {
			return err
		}
	}
	for i := applied; i < len(migrations); i++ {
		if err := s.applyMigration(i+1, migrations[i]); err != nil {
			return err
		}
	}
	return s.checkSchema()
}

// applyMigration runs one step's statements and its user_version bump as a single
// transaction. Most steps are multi-statement ALTER TABLE ADD COLUMN blocks, which
// are not idempotent, so a crash between the DDL and the bump would leave the columns
// added and the version behind — and every later start would replay the step and die
// with `duplicate column name`, with no recovery short of deleting the data dir,
// which on a zero-knowledge server is every account's only copy of its ciphertext.
// SQLite journals user_version with the rest of the database, so setting it inside
// the same transaction makes the pair atomic: the step lands whole or not at all.
func (s *Store) applyMigration(version int, stmts string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(stmts); err != nil {
		return fmt.Errorf("apply migration %d: %w", version, err)
	}
	// PRAGMA takes no bound parameters; version is a controlled integer, not user input.
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, version)); err != nil {
		return fmt.Errorf("apply migration %d: %w", version, err)
	}
	return tx.Commit()
}

// checkSchema guards against the two pre-migration layouts, which predate
// user_version and so look like a version-0 dir the steps could simply apply to.
// CREATE TABLE IF NOT EXISTS silently no-ops over a pre-existing table, so such a dir
// would otherwise limp along with a wrong FK and opaque INSERT failures. Neither
// layout has a migration path, so fail loudly with a recoverable instruction. Two
// cases:
//
//   - A legacy `chunks` table means the pre-pack object store (one row + one file
//     per chunk). The new resource_chunks FK targets `objects`, which that data dir
//     lacks, so every manifest write would fail; reject it up front.
//   - resource_chunks without owner_handle is the even-older flat layout.
func (s *Store) checkSchema() error {
	legacy, err := s.tableExists("chunks")
	if err != nil {
		return err
	}
	if legacy {
		return errors.New("server data dir is from an older build (pre-pack chunk store); " +
			"delete the server data dir and re-sync")
	}

	var hasOwner bool
	rows, err := s.db.Query(`PRAGMA table_info(resource_chunks)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "owner_handle" {
			hasOwner = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasOwner {
		return errors.New("resource_chunks schema is from an older build (missing owner_handle); " +
			"delete the server data dir and re-sync")
	}
	return nil
}

// tableExists reports whether a table of the given name is present.
func (s *Store) tableExists(name string) (bool, error) {
	var n int
	err := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name,
	).Scan(&n)
	return n > 0, err
}
