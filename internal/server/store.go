package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
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

// ErrDropsRoots is returned when a replace would clear every GC root of a resource
// that still has some: an object-backed resource (folder/streamed file) re-PUT with
// no ChunkRefs. Committing it would orphan the still-referenced objects for the next
// GC, so the store refuses it rather than lose data.
var ErrDropsRoots = errors.New("replace drops all chunk roots")

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

// ErrDeviceLimit is returned when attaching a device would exceed an account's
// configured device cap. Handlers map it to 403.
var ErrDeviceLimit = errors.New("device limit reached")

// UpgradeRequiredError is returned when a write targets a resource whose stored
// min_client exceeds the writer's capability: a client that cannot read the current
// state must not overwrite it. MinClient is the capability the resource needs.
// Handlers map it to 426.
type UpgradeRequiredError struct{ MinClient int }

func (e *UpgradeRequiredError) Error() string {
	return fmt.Sprintf("resource requires client capability %d", e.MinClient)
}

// normalizeMinClient floors a declared min_client at the baseline: a legacy writer
// declares 0, and a resource is never over-restricted below the format every release
// reads.
func normalizeMinClient(declared int) int {
	if declared < api.CapabilityBaseline {
		return api.CapabilityBaseline
	}
	return declared
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
	// An absent action is reclaim: that is what every client written before the field
	// existed meant, and what the server did for them.
	switch onExpiry {
	case "", api.ExpiryReclaim:
		action = string(api.ExpiryReclaim)
	case api.ExpiryRetire:
		action = string(api.ExpiryRetire)
	default:
		return sql.NullInt64{}, sql.NullInt64{}, "", ErrBadPolicy
	}
	if expireSeconds > 0 {
		expiresAt = sql.NullInt64{Int64: now + expireSeconds, Valid: true}
	}
	if maxReads > 0 {
		max = sql.NullInt64{Int64: maxReads, Valid: true}
	}
	return expiresAt, max, action, nil
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
	rdb      *sql.DB
	auth     *authCache
	blobsDir string
	packsDir string
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
	s := &Store{db: db, auth: newAuthCache(), blobsDir: blobsDir, packsDir: packsDir, gcLocks: newKeyedMutex(), resLocks: newKeyedMutex()}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
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
	return s, nil
}

func (s *Store) Ping() error {
	var one int
	return s.rdb.QueryRow(`SELECT 1`).Scan(&one)
}

func (s *Store) Close() error {
	rerr := s.rdb.Close()
	if err := s.db.Close(); err != nil {
		return err
	}
	return rerr
}

// migrations are the forward-only schema steps, applied in order and tracked by
// PRAGMA user_version. Append new steps; never edit or reorder a shipped one. Every
// statement is IF NOT EXISTS, so re-running step 1 over a data dir created before
// this scaffold (user_version still 0) is a harmless no-op that then lets the later
// steps apply in place — no wipe-and-resync for additive changes.
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
	// self-signature; both NULL until a new-enough client uploads them (signup or the
	// lazy PUT /v1/account/enc-key backfill). A grant row wraps one resource's content
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
	// rows are left at -1, meaning "not recorded"; those still fall back to a stat,
	// so the backfill happens as rows are rewritten rather than in one pass over
	// every blob at upgrade time.
	`ALTER TABLE resources ADD COLUMN blob_size INTEGER NOT NULL DEFAULT -1;
	 ALTER TABLE snapshots ADD COLUMN blob_size INTEGER NOT NULL DEFAULT -1;`,
}

// migrate applies the migrations a data dir has not yet run, then validates the
// resulting schema. PRAGMA user_version records how many steps have run.
func (s *Store) migrate() error {
	var applied int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&applied); err != nil {
		return err
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
		if _, err := s.db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
		// PRAGMA takes no bound parameters; i+1 is a controlled integer, not user input.
		if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return err
		}
	}
	return s.checkSchema()
}

// checkSchema guards against a data dir created by an older build. CREATE TABLE IF
// NOT EXISTS silently no-ops over a pre-existing table, so an old layout would
// otherwise limp along with a wrong FK and opaque INSERT failures. There is no
// versioned migration yet (this feature is pre-release), so fail loudly with a
// recoverable instruction instead. Two cases:
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

// --- Accounts & devices ---

type Account struct {
	OwnerHandle string
	Email       string
	Kdf         crypto.KdfParams
	WrappedRoot crypto.SealedBlob
}

// CreateAccount registers an account with its Ed25519 public key, wrapped root key,
// and passphrase-verifier hash, and returns it. Returns ErrConflict if the email is
// already taken. The new account starts at auth epoch 1. encPublicKey/encKeySig are
// the optional published X25519 key and its identity self-signature (empty from a
// pre-grants client; the caller validates the signature before storing).
func (s *Store) CreateAccount(email string, kdf crypto.KdfParams, publicKey []byte, wrappedRoot crypto.SealedBlob, authVerifier, encPublicKey, encKeySig []byte) (Account, error) {
	handle := newID(12)
	kdfJSON, err := json.Marshal(kdf)
	if err != nil {
		return Account{}, err
	}
	rootJSON, err := json.Marshal(wrappedRoot)
	if err != nil {
		return Account{}, err
	}
	vh := sha256.Sum256(authVerifier)
	var encPub, encSig any
	if len(encPublicKey) > 0 {
		encPub, encSig = encPublicKey, encKeySig
	}
	_, err = s.db.Exec(
		`INSERT INTO accounts(owner_handle, email, kdf, public_key, wrapped_root, auth_verifier, auth_epoch, enc_public_key, enc_key_sig)
		 VALUES(?,?,?,?,?,?,1,?,?)`,
		handle, email, string(kdfJSON), publicKey, string(rootJSON), vh[:], encPub, encSig,
	)
	if err != nil {
		if isUnique(err) {
			return Account{}, ErrConflict
		}
		return Account{}, err
	}
	return Account{OwnerHandle: handle, Email: email, Kdf: kdf, WrappedRoot: wrappedRoot}, nil
}

// AccountByEmail returns the account's bootstrap fields (KDF params + wrapped root)
// or ErrNotFound.
func (s *Store) AccountByEmail(email string) (Account, error) {
	var (
		acc               Account
		kdfJSON, rootJSON string
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, email, kdf, wrapped_root FROM accounts WHERE email = ?`, email,
	).Scan(&acc.OwnerHandle, &acc.Email, &kdfJSON, &rootJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if err := json.Unmarshal([]byte(kdfJSON), &acc.Kdf); err != nil {
		return Account{}, err
	}
	if rootJSON != "" {
		if err := json.Unmarshal([]byte(rootJSON), &acc.WrappedRoot); err != nil {
			return Account{}, err
		}
	}
	return acc, nil
}

// AccountForAuth returns the fields needed to authenticate a device attach: the
// owner handle, the Ed25519 public key (to verify the challenge signature), the
// stored auth-verifier hash (to check the passphrase proof), and the current auth
// epoch (which the new device's token is tagged with). ErrNotFound if no account.
func (s *Store) AccountForAuth(email string) (ownerHandle string, publicKey, verifierHash []byte, epoch int, err error) {
	err = s.rdb.QueryRow(
		`SELECT owner_handle, public_key, auth_verifier, auth_epoch FROM accounts WHERE email = ?`, email,
	).Scan(&ownerHandle, &publicKey, &verifierHash, &epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, nil, 0, ErrNotFound
	}
	if err != nil {
		return "", nil, nil, 0, err
	}
	return ownerHandle, publicKey, verifierHash, epoch, nil
}

// ServerSecret returns the persistent per-server secret used to synthesize a decoy
// bootstrap response for unknown emails, creating it on first use. Stable across
// restarts so the same unknown email always yields the same decoy.
func (s *Store) ServerSecret() ([]byte, error) {
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO server_meta(key, value) VALUES('bootstrap-decoy-secret', ?)`,
		randomBytes(32),
	); err != nil {
		return nil, err
	}
	var secret []byte
	if err := s.db.QueryRow(
		`SELECT value FROM server_meta WHERE key = 'bootstrap-decoy-secret'`,
	).Scan(&secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// ChangePassphrase re-wraps the account's root key under a new passphrase. It
// verifies the caller knows the current passphrase (oldVerifier) and that no other
// device changed it first (expectedEpoch), then stores the new KDF/wrapped-root/
// verifier, bumps the account epoch (invalidating every other device's token), and
// re-tags the calling device's token with the new epoch so it stays valid. Returns
// the new epoch. ErrNotFound if the verifier is wrong, ErrVersionConflict on a stale
// epoch.
func (s *Store) ChangePassphrase(owner, deviceID string, kdf crypto.KdfParams, wrappedRoot crypto.SealedBlob, oldVerifier, newVerifier []byte, expectedEpoch int) (int, error) {
	kdfJSON, err := json.Marshal(kdf)
	if err != nil {
		return 0, err
	}
	rootJSON, err := json.Marshal(wrappedRoot)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var (
		curEpoch    int
		curVerifier []byte
	)
	if err := tx.QueryRow(
		`SELECT auth_epoch, auth_verifier FROM accounts WHERE owner_handle = ?`, owner,
	).Scan(&curEpoch, &curVerifier); err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	oldHash := sha256.Sum256(oldVerifier)
	if subtle.ConstantTimeCompare(oldHash[:], curVerifier) != 1 {
		tx.Rollback()
		return 0, ErrNotFound // wrong current passphrase
	}
	if expectedEpoch != curEpoch {
		tx.Rollback()
		return 0, ErrVersionConflict
	}
	newEpoch := curEpoch + 1
	newHash := sha256.Sum256(newVerifier)
	if _, err := tx.Exec(
		`UPDATE accounts SET kdf = ?, wrapped_root = ?, auth_verifier = ?, auth_epoch = ? WHERE owner_handle = ?`,
		string(kdfJSON), string(rootJSON), newHash[:], newEpoch, owner,
	); err != nil {
		tx.Rollback()
		return 0, err
	}
	// Keep the initiating device usable; every other device stays on the old epoch
	// and its token now fails the epoch check.
	if _, err := tx.Exec(
		`UPDATE devices SET auth_epoch = ? WHERE owner_handle = ? AND device_id = ?`,
		newEpoch, owner, deviceID,
	); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	// Every other device's cached token entry is now stale (its epoch no longer
	// matches); the calling device re-caches on its next request.
	s.auth.invalidateOwner(owner)
	return newEpoch, nil
}

// RotateRootKey atomically swaps every root-dependent server record. The client has
// already rewrapped each opaque key; this method checks the set is complete before
// changing identity, then gives the initiating device a fresh token and removes all
// other devices.
func (s *Store) RotateRootKey(owner, deviceID string, req api.RootKeyRotationRequest) (string, int, error) {
	kdfJSON, err := json.Marshal(req.Kdf)
	if err != nil {
		return "", 0, err
	}
	rootJSON, err := json.Marshal(req.WrappedRoot)
	if err != nil {
		return "", 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	fail := func(e error) (string, int, error) { _ = tx.Rollback(); return "", 0, e }
	var epoch int
	var verifier []byte
	if err := tx.QueryRow(`SELECT auth_epoch, auth_verifier FROM accounts WHERE owner_handle = ?`, owner).Scan(&epoch, &verifier); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fail(ErrNotFound)
		}
		return fail(err)
	}
	oldHash := sha256.Sum256(req.OldAuthVerifier)
	if subtle.ConstantTimeCompare(oldHash[:], verifier) != 1 {
		return fail(ErrNotFound)
	}
	if req.ExpectedEpoch != epoch {
		return fail(ErrVersionConflict)
	}
	if err := verifyKeyMigrations(tx, owner, req.Resources, req.Snapshots, req.IncomingGrants); err != nil {
		return fail(err)
	}
	for _, m := range req.Resources {
		b, err := json.Marshal(m.WrappedKey)
		if err != nil {
			return fail(err)
		}
		if _, err := tx.Exec(`UPDATE resources SET wrapped_key = ? WHERE id = ? AND owner_handle = ?`, string(b), m.ID, owner); err != nil {
			return fail(err)
		}
	}
	for _, m := range req.Snapshots {
		b, err := json.Marshal(m.WrappedKey)
		if err != nil {
			return fail(err)
		}
		if _, err := tx.Exec(`UPDATE snapshots SET wrapped_key = ? WHERE snapshot_id = ? AND owner_handle = ?`, string(b), m.ID, owner); err != nil {
			return fail(err)
		}
	}
	for _, m := range req.IncomingGrants {
		if _, err := tx.Exec(`UPDATE grants SET wrapped_key = ? WHERE resource_id = ? AND owner_handle = ? AND grantee_handle = ?`, m.WrappedKey, m.ResourceID, m.OwnerHandle, owner); err != nil {
			return fail(err)
		}
	}
	newEpoch := epoch + 1
	newVerifier := sha256.Sum256(req.NewAuthVerifier)
	if _, err := tx.Exec(`UPDATE accounts SET kdf=?, wrapped_root=?, auth_verifier=?, auth_epoch=?, public_key=?, enc_public_key=?, enc_key_sig=? WHERE owner_handle=?`, string(kdfJSON), string(rootJSON), newVerifier[:], newEpoch, req.PublicKey, req.EncPublicKey, req.EncKeySig, owner); err != nil {
		return fail(err)
	}
	token := newID(32)
	th := sha256.Sum256([]byte(token))
	if _, err := tx.Exec(`DELETE FROM devices WHERE owner_handle = ? AND device_id <> ?`, owner, deviceID); err != nil {
		return fail(err)
	}
	res, err := tx.Exec(`UPDATE devices SET token_hash = ?, auth_epoch = ? WHERE owner_handle = ? AND device_id = ?`, th[:], newEpoch, owner, deviceID)
	if err != nil {
		return fail(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fail(ErrNotFound)
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	s.auth.invalidateOwner(owner)
	return token, newEpoch, nil
}

func verifyKeyMigrations(tx *sql.Tx, owner string, resources, snapshots []api.KeyWrapMigration, grants []api.GrantKeyMigration) error {
	seen := map[string]bool{}
	for _, m := range resources {
		if m.ID == "" || seen[m.ID] {
			return ErrVersionConflict
		}
		seen[m.ID] = true
		var version int
		err := tx.QueryRow(`SELECT version FROM resources WHERE id=? AND owner_handle=? AND wrapped_key IS NOT NULL AND reclaimed=0`, m.ID, owner).Scan(&version)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVersionConflict
		}
		if err != nil {
			return err
		}
		if version != m.ExpectedVersion {
			return ErrVersionConflict
		}
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM resources WHERE owner_handle=? AND wrapped_key IS NOT NULL AND reclaimed=0`, owner).Scan(&n); err != nil {
		return err
	}
	if n != len(resources) {
		return ErrVersionConflict
	}
	seen = map[string]bool{}
	for _, m := range snapshots {
		if m.ID == "" || seen[m.ID] {
			return ErrVersionConflict
		}
		seen[m.ID] = true
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM snapshots WHERE snapshot_id=? AND owner_handle=? AND wrapped_key IS NOT NULL`, m.ID, owner).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVersionConflict
		}
		if err != nil {
			return err
		}
	}
	if err := tx.QueryRow(`SELECT count(*) FROM snapshots WHERE owner_handle=? AND wrapped_key IS NOT NULL`, owner).Scan(&n); err != nil {
		return err
	}
	if n != len(snapshots) {
		return ErrVersionConflict
	}
	seen = map[string]bool{}
	for _, m := range grants {
		k := m.ResourceID + "\x00" + m.OwnerHandle
		if m.ResourceID == "" || m.OwnerHandle == "" || len(m.WrappedKey) == 0 || seen[k] {
			return ErrVersionConflict
		}
		seen[k] = true
		var exists int
		err := tx.QueryRow(`SELECT 1 FROM grants g JOIN resources r ON r.id = g.resource_id WHERE g.resource_id=? AND g.owner_handle=? AND g.grantee_handle=? AND r.reclaimed=0`, m.ResourceID, m.OwnerHandle, owner).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrVersionConflict
		}
		if err != nil {
			return err
		}
	}
	if err := tx.QueryRow(`SELECT count(*) FROM grants g JOIN resources r ON r.id = g.resource_id WHERE g.grantee_handle=? AND r.reclaimed=0`, owner).Scan(&n); err != nil {
		return err
	}
	if n != len(grants) {
		return ErrVersionConflict
	}
	return nil
}

// challengeTTL bounds how long an issued nonce remains valid.
const challengeTTL = 2 * time.Minute

// CreateChallenge issues a one-time nonce for email to sign. It is stored with a
// short expiry and consumed on use, so it cannot be replayed.
func (s *Store) CreateChallenge(email string) (id string, nonce []byte, err error) {
	id = newID(16)
	nonce = randomBytes(32)
	now := time.Now()
	// Opportunistic sweep: challenges are deleted on consume, but an unconsumed one
	// would otherwise linger forever. Reaping expired rows on each issue keeps the
	// table bounded without a background job.
	s.db.Exec(`DELETE FROM challenges WHERE expires_at < ?`, now.Unix())
	expiresAt := now.Add(challengeTTL).Unix()
	_, err = s.db.Exec(
		`INSERT INTO challenges(id, email, nonce, expires_at) VALUES(?,?,?,?)`,
		id, email, nonce, expiresAt,
	)
	if err != nil {
		return "", nil, err
	}
	return id, nonce, nil
}

// ConsumeChallenge returns the nonce for (id, email) and deletes it, so each
// challenge is single-use. Expired or missing challenges return ErrNotFound.
func (s *Store) ConsumeChallenge(id, email string) ([]byte, error) {
	var (
		nonce     []byte
		expiresAt int64
	)
	err := s.db.QueryRow(
		`SELECT nonce, expires_at FROM challenges WHERE id = ? AND email = ?`, id, email,
	).Scan(&nonce, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.db.Exec(`DELETE FROM challenges WHERE id = ?`, id) // single-use, regardless of validity
	if time.Now().Unix() > expiresAt {
		return nil, ErrNotFound
	}
	return nonce, nil
}

// CreateDevice issues a device token tagged with the account's current auth epoch.
// It returns the plaintext token once; only its hash is stored.
// maxDevices > 0 caps the account's device count: the count and the insert run in one
// transaction, so a signup's first device and a concurrent attach cannot both slip
// past the cap. Returns ErrDeviceLimit when the cap is already reached.
func (s *Store) CreateDevice(ownerHandle, name string, epoch, maxDevices int) (deviceID, token string, err error) {
	deviceID = newID(10)
	token = newID(32)
	h := sha256.Sum256([]byte(token))
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	if maxDevices > 0 {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM devices WHERE owner_handle = ?`, ownerHandle).Scan(&count); err != nil {
			tx.Rollback()
			return "", "", err
		}
		if count >= maxDevices {
			tx.Rollback()
			return "", "", ErrDeviceLimit
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO devices(device_id, owner_handle, name, token_hash, auth_epoch) VALUES(?,?,?,?,?)`,
		deviceID, ownerHandle, name, h[:], epoch,
	); err != nil {
		tx.Rollback()
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	return deviceID, token, nil
}

// OwnerPackBytes returns the owner's current stored-pack-byte total: the quota
// counter, maintained incrementally in the pack put/GC/repack transactions, so this
// is a single indexed read rather than a scan of the objects table.
func (s *Store) OwnerPackBytes(owner string) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT pack_bytes FROM accounts WHERE owner_handle = ?`, owner).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return n, err
}

// addOwnerPackBytes adjusts the owner's stored-byte counter by delta (may be
// negative) inside the caller's transaction, so the counter moves atomically with the
// pack rows it accounts for. It floors at zero as a backstop against a counter
// drifting negative.
func addOwnerPackBytes(tx *sql.Tx, owner string, delta int64) error {
	_, err := tx.Exec(
		`UPDATE accounts SET pack_bytes = MAX(0, pack_bytes + ?) WHERE owner_handle = ?`,
		delta, owner,
	)
	return err
}

// AccountUsage summarizes what one account has stored. StorageBytes is the
// pack-byte quota counter; the rest are row counts. Resources counts live rows
// only — a reclaimed tombstone holds no content and exists just to keep its link
// answering 410, so it is excluded from the modeled byte total too (otherwise a
// delete-heavy account could sit over quota forever).
type AccountUsage struct {
	Owner        string
	StorageBytes int64
	Packs        int64
	Objects      int64
	Resources    int64
	Snapshots    int64
	Devices      int64
}

const accountUsageColumns = `
	a.owner_handle,
	a.pack_bytes
	  + COALESCE((SELECT SUM(length(r.encrypted_meta) + COALESCE(length(r.wrapped_key), 0) + length(r.blob_nonce) + 256) FROM resources r WHERE r.owner_handle = a.owner_handle AND r.reclaimed = 0), 0)
	  + COALESCE((SELECT SUM(length(sn.encrypted_meta) + COALESCE(length(sn.encrypted_label), 0) + COALESCE(length(sn.wrapped_key), 0) + length(sn.blob_nonce) + 256) FROM snapshots sn WHERE sn.owner_handle = a.owner_handle), 0)
	  + COALESCE((SELECT SUM(length(g.wrapped_key) + 128) FROM grants g WHERE g.owner_handle = a.owner_handle), 0)
	  + 96 * (SELECT COUNT(*) FROM objects o WHERE o.owner_handle = a.owner_handle)
	  + 64 * (SELECT COUNT(*) FROM devices d WHERE d.owner_handle = a.owner_handle),
	(SELECT COUNT(*) FROM packs p WHERE p.owner_handle = a.owner_handle),
	(SELECT COUNT(*) FROM objects o WHERE o.owner_handle = a.owner_handle),
	(SELECT COUNT(*) FROM resources r WHERE r.owner_handle = a.owner_handle AND r.reclaimed = 0),
	(SELECT COUNT(*) FROM snapshots sn WHERE sn.owner_handle = a.owner_handle),
	(SELECT COUNT(*) FROM devices d WHERE d.owner_handle = a.owner_handle)`

func scanAccountUsage(row interface{ Scan(...any) error }) (AccountUsage, error) {
	var u AccountUsage
	err := row.Scan(&u.Owner, &u.StorageBytes, &u.Packs, &u.Objects, &u.Resources, &u.Snapshots, &u.Devices)
	return u, err
}

// AccountUsage returns the storage summary for one account.
func (s *Store) AccountUsage(owner string) (AccountUsage, error) {
	u, err := scanAccountUsage(s.rdb.QueryRow(
		`SELECT `+accountUsageColumns+` FROM accounts a WHERE a.owner_handle = ?`, owner))
	if errors.Is(err, sql.ErrNoRows) {
		return AccountUsage{}, ErrNotFound
	}
	if err != nil {
		return AccountUsage{}, err
	}
	blobBytes, err := s.ownerBlobBytes(owner)
	if err != nil {
		return AccountUsage{}, err
	}
	u.StorageBytes += blobBytes
	return u, err
}

// ResourceStoredBytes reports what one live resource already contributes to its
// owner's usage, in the same shape estimatedResourceBytes models a pending write.
// An in-place update replaces those bytes rather than adding to them, so the quota
// check charges only the difference. A missing row or blob reports 0, which charges
// the write in full — the fail-closed direction.
func (s *Store) ResourceStoredBytes(owner, id string) (int64, error) {
	var (
		metaLen, wrappedLen int64
		nonce               []byte
	)
	err := s.rdb.QueryRow(
		`SELECT length(encrypted_meta), length(COALESCE(wrapped_key, '')), blob_nonce
		 FROM resources WHERE id = ? AND owner_handle = ? AND reclaimed = 0`, id, owner,
	).Scan(&metaLen, &wrappedLen, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(s.blobPath(id, nonce))
	if err != nil {
		return 0, nil
	}
	return info.Size() + int64(len(nonce)) + metaLen + wrappedLen + 256, nil
}

// ResourceCreateReplayed reports whether req's Idempotency-Key already names a
// completed create of this resource. A replay stores nothing new, so charging it
// against the quota would answer 507 for a resource that exists — defeating the
// retry the key exists for.
func (s *Store) ResourceCreateReplayed(owner string, req api.PutResourceRequest) bool {
	if req.IdempotencyKey == "" || req.ID != "" {
		return false
	}
	digest, err := idempotencyDigest(req)
	if err != nil {
		return false
	}
	var prior api.PutResourceResponse
	found, err := lookupIdempotency(s.rdb, owner, "resource.create", req.IdempotencyKey, digest, &prior)
	return err == nil && found
}

// ownerBlobBytes totals the resource and snapshot blob bytes an account holds.
// Rows written since migration 16 carry their size, so the common case is one
// aggregate query; only rows predating it (blob_size = -1) are stat'ed, and each
// such stat is replaced by a recorded size the next time that row is rewritten.
func (s *Store) ownerBlobBytes(owner string) (int64, error) {
	var recorded int64
	if err := s.rdb.QueryRow(
		`SELECT COALESCE(SUM(blob_size), 0) FROM (
		   SELECT blob_size FROM resources WHERE owner_handle = ? AND reclaimed = 0 AND blob_size >= 0
		   UNION ALL
		   SELECT blob_size FROM snapshots WHERE owner_handle = ? AND blob_size >= 0
		 )`, owner, owner,
	).Scan(&recorded); err != nil {
		return 0, err
	}
	rows, err := s.rdb.Query(
		`SELECT id, blob_nonce FROM resources WHERE owner_handle = ? AND reclaimed = 0 AND blob_size < 0
		 UNION ALL
		 SELECT snapshot_id, blob_nonce FROM snapshots WHERE owner_handle = ? AND blob_size < 0`, owner, owner)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := recorded
	for rows.Next() {
		var id string
		var nonce []byte
		if err := rows.Scan(&id, &nonce); err != nil {
			return 0, err
		}
		info, err := os.Stat(s.blobPath(id, nonce))
		if errors.Is(err, os.ErrNotExist) {
			// An orphaned row (operator-deleted file, crash window) holds no bytes.
			// Failing here would wedge every usage-dependent path account-wide:
			// metrics, pack/resource puts, and auto-snapshots all call AccountUsage.
			continue
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, rows.Err()
}

// AccountUsageAll returns the storage summary for every account, for the metrics
// collector and any operator-side reporting.
func (s *Store) AccountUsageAll() ([]AccountUsage, error) {
	rows, err := s.rdb.Query(`SELECT owner_handle FROM accounts ORDER BY owner_handle`)
	if err != nil {
		return nil, err
	}
	var owners []string
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			rows.Close()
			return nil, err
		}
		owners = append(owners, owner)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := make([]AccountUsage, 0, len(owners))
	for _, owner := range owners {
		u, err := s.AccountUsage(owner)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// OwnerByToken resolves a bearer token to its owning account handle, but only while
// the token's epoch still matches its account's — a passphrase change bumps the
// account epoch, so every token issued before it stops authenticating (ErrNotFound).
func (s *Store) OwnerByToken(token string) (string, error) {
	owner, _, err := s.AuthByToken(token)
	return owner, err
}

// AuthByToken resolves a bearer token to its owner handle and device id, enforcing
// the same epoch check as OwnerByToken. The device id lets a passphrase change keep
// the calling device's token alive while invalidating the rest.
//
// Successful resolutions are cached (this SELECT otherwise runs on every request).
// ChangePassphrase and DeleteDevice invalidate the affected entries, and the TTL
// bounds the staleness of any path that misses; only positive results are cached, so
// unauthenticated garbage cannot grow the map.
func (s *Store) AuthByToken(token string) (owner, deviceID string, err error) {
	h := sha256.Sum256([]byte(token))
	if owner, deviceID, ok := s.auth.get(h); ok {
		return owner, deviceID, nil
	}
	err = s.rdb.QueryRow(
		`SELECT d.owner_handle, d.device_id FROM devices d
		   JOIN accounts a ON a.owner_handle = d.owner_handle
		 WHERE d.token_hash = ? AND d.auth_epoch = a.auth_epoch`, h[:],
	).Scan(&owner, &deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	s.auth.put(h, owner, deviceID)
	return owner, deviceID, nil
}

// ListDevices returns the owner's attached devices (id + name). Token hashes never
// leave the store.
func (s *Store) ListDevices(owner string, page pageParams) ([]api.Device, string, error) {
	limit := page.effectiveLimit()
	where := "owner_handle = ?"
	args := []any{owner}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 1)
		if err != nil {
			return nil, "", err
		}
		where += " AND device_id > ?"
		args = append(args, parts[0])
	}
	args = append(args, limit+1)
	rows, err := s.rdb.Query(
		`SELECT device_id, name FROM devices WHERE `+where+` ORDER BY device_id LIMIT ?`, args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	devices := []api.Device{}
	for rows.Next() {
		var d api.Device
		if err := rows.Scan(&d.ID, &d.Name); err != nil {
			return nil, "", err
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(devices) > limit {
		devices = devices[:limit]
		next = encodeCursor(devices[len(devices)-1].ID)
	}
	return devices, next, nil
}

// DeleteDevice revokes a device, scoped to its owner so one account cannot revoke
// another's device. Returns ErrNotFound if no such device belongs to the owner.
func (s *Store) DeleteDevice(owner, deviceID string) error {
	res, err := s.db.Exec(`DELETE FROM devices WHERE device_id = ? AND owner_handle = ?`, deviceID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.auth.invalidateDevice(owner, deviceID) // a revoked token must stop working now, not at TTL
	return nil
}

// Owners lists every account handle, for jobs that sweep all accounts (the
// scheduled GC).
func (s *Store) Owners() ([]string, error) {
	rows, err := s.rdb.Query(`SELECT owner_handle FROM accounts ORDER BY owner_handle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, err
		}
		owners = append(owners, o)
	}
	return owners, rows.Err()
}

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

func idempotencyDigest(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

func lookupIdempotency(q queryRower, owner, kind, key string, digest []byte, out any) (bool, error) {
	if key == "" {
		return false, nil
	}
	var storedHash []byte
	var response string
	err := q.QueryRow(`SELECT request_hash, response FROM idempotency_keys WHERE owner_handle = ? AND kind = ? AND key = ?`, owner, kind, key).Scan(&storedHash, &response)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(storedHash, digest) {
		return false, ErrIdempotencyConflict
	}
	return true, json.Unmarshal([]byte(response), out)
}

// idempotencyTTL bounds how long a recorded response stays replayable. Client
// retries land within seconds; older rows are dead weight, and each stores a
// full JSON response, so without the GC sweep the table grows forever.
const idempotencyTTL = 48 * time.Hour

func (s *Store) sweepIdempotencyKeys(owner string, now time.Time) error {
	_, err := s.db.Exec(`DELETE FROM idempotency_keys WHERE owner_handle = ? AND created_at < ?`,
		owner, now.Add(-idempotencyTTL).Unix())
	return err
}

func recordIdempotency(tx *sql.Tx, owner, kind, key string, digest []byte, response any) error {
	if key == "" {
		return nil
	}
	b, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO idempotency_keys(owner_handle, kind, key, request_hash, response, created_at) VALUES(?,?,?,?,?,unixepoch())`, owner, kind, key, digest, string(b))
	return err
}

// --- Resources ---

// PutResource creates a resource (req.ID empty) or replaces one in place
// (req.ID set, ownership-checked, version bumped). The DB write and the blob
// write are coupled so a failure of either leaves no half-written resource:
// the row is committed only after the blob lands, and the blob is written
// atomically so a failed replace keeps the previous content intact.
// capability is the writer's declared client capability (already validated by the
// handler to be >= req.MinClient). An update whose stored min_client exceeds it is
// rejected with *UpgradeRequiredError: a client that cannot read the current state
// must not overwrite it.
func (s *Store) PutResource(owner string, capability int, req api.PutResourceRequest) (id string, version int, err error) {
	metaJSON, err := json.Marshal(req.EncryptedMeta)
	if err != nil {
		return "", 0, err
	}
	var wrappedJSON sql.NullString
	if req.WrappedKey != nil {
		b, err := json.Marshal(req.WrappedKey)
		if err != nil {
			return "", 0, err
		}
		wrappedJSON = sql.NullString{String: string(b), Valid: true}
	}
	if req.ID == "" {
		return s.createResource(owner, req, string(metaJSON), wrappedJSON)
	}
	return s.updateResource(owner, capability, req, string(metaJSON), wrappedJSON)
}

func (s *Store) createResource(owner string, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
	digest, err := idempotencyDigest(req)
	if err != nil {
		return "", 0, err
	}
	var prior api.PutResourceResponse
	if found, err := lookupIdempotency(s.rdb, owner, "resource.create", req.IdempotencyKey, digest, &prior); err != nil {
		return "", 0, err
	} else if found {
		return prior.ID, prior.Version, nil
	}
	id := newID(8)
	const version = 1

	expiresAt, maxReads, onExpiry, err := resolvePolicy(req.Visibility, req.ExpireSeconds, req.MaxReads, req.OnExpiry, time.Now().Unix())
	if err != nil {
		return "", 0, err
	}

	// Write and fsync the blob before opening the transaction, mirroring
	// updateResource: keep the durable write off the single writer connection (an
	// fsync inside the tx stalls every other request) and drop the file unless the
	// commit roots it. The immutable-per-nonce layout means a crash only ever orphans
	// this new file, never pairs the row's nonce with mismatched bytes.
	newPath := s.blobPath(id, req.Blob.Nonce)
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(newPath)
		}
	}()
	if err := s.writeBlob(id, req.Blob.Nonce, req.Blob.Ciphertext); err != nil {
		return "", 0, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	// Authoritative duplicate check: the pre-tx lookup on the read pool may see a
	// stale WAL snapshot; only this re-check on the single writer connection is
	// race-free. Do not remove it as redundant.
	if found, err := lookupIdempotency(tx, owner, "resource.create", req.IdempotencyKey, digest, &prior); err != nil {
		tx.Rollback()
		return "", 0, err
	} else if found {
		tx.Rollback()
		return prior.ID, prior.Version, nil
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(
		`INSERT INTO resources(id, owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, blob_size, version, min_client, expires_at, max_reads, on_expiry, created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, owner, string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, int64(len(req.Blob.Ciphertext)), version, normalizeMinClient(req.MinClient), expiresAt, maxReads, onExpiry, now, now,
	); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := replaceResourceChunks(tx, id, owner, req.ChunkRefs); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := recordIdempotency(tx, owner, "resource.create", req.IdempotencyKey, digest, api.PutResourceResponse{ID: id, Version: version}); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	committed = true
	return id, version, nil
}

func (s *Store) updateResource(owner string, capability int, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
	expiresAt, maxReads, onExpiry, err := resolvePolicy(req.Visibility, req.ExpireSeconds, req.MaxReads, req.OnExpiry, time.Now().Unix())
	if err != nil {
		return "", 0, err
	}
	defer s.resLocks.lock(req.ID)()
	var (
		current   int
		storedMin int
		reclaimed bool
	)
	err = s.db.QueryRow(
		`SELECT version, min_client, reclaimed FROM resources WHERE id = ? AND owner_handle = ?`, req.ID, owner,
	).Scan(&current, &storedMin, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	// A client that cannot read the current sealed format must not overwrite it (it
	// would clobber state it can't merge). Checked under the per-resource lock, so it
	// races no concurrent min_client change.
	if capability < storedMin {
		return "", 0, &UpgradeRequiredError{MinClient: storedMin}
	}
	// Optimistic concurrency: a client that based its update on an older version
	// is rejected so a concurrent write is never lost. (The per-resource lock above
	// makes this check-then-update atomic; the WHERE version=? on the UPDATE
	// is a second line of defense.)
	if req.ExpectedVersion > 0 && current != req.ExpectedVersion {
		return "", 0, ErrVersionConflict
	}
	version := current + 1

	// Blobs are immutable per version: write the new version to its own durable
	// file before the row commits, never mutating the live one. The committed
	// row's version then selects the authoritative blob, so a crash or a failed
	// write at any point can only orphan the new file, never pair the row's nonce
	// with mismatched bytes (which would make the resource undecryptable). The new
	// file is dropped unless the commit roots it.
	newPath := s.blobPath(req.ID, req.Blob.Nonce)
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(newPath)
		}
	}()
	if err := s.writeBlob(req.ID, req.Blob.Nonce, req.Blob.Ciphertext); err != nil {
		return "", 0, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	// An update may lower min_client: a capable client legitimately rewrites a
	// resource in an older (baseline) format, and that state is then readable by
	// older clients again.
	//
	// A replace re-specifies the resource's content, but not necessarily its link, so
	// the lifecycle policy is taken from this request only when the request carries one
	// (a re-share), flips the resource private (a policy belongs to the public link and
	// dies with it), or resurrects a tombstone (whose policy already fired, and whose
	// stale read count must not carry over). Every other write preserves the policy: a
	// folder sync pushing a new manifest is not a re-share, and clearing the expiry —
	// or restarting the read counter — behind the owner's back would quietly un-share
	// the folder they shared.
	const setContent = `visibility=?, encrypted_meta=?, wrapped_key=?, blob_nonce=?, blob_size=?, version=?, min_client=?, updated_at=unixepoch()`
	replacePolicy := req.Visibility != api.Public || req.ExpireSeconds > 0 || req.MaxReads > 0 || reclaimed

	var res sql.Result
	if replacePolicy {
		res, err = tx.Exec(
			`UPDATE resources SET `+setContent+`,
			   expires_at=?, max_reads=?, on_expiry=?, reads=0, exhausted_at=NULL, reclaimed=0
			 WHERE id=? AND owner_handle=? AND version=?`,
			string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, int64(len(req.Blob.Ciphertext)), version, normalizeMinClient(req.MinClient),
			expiresAt, maxReads, onExpiry, req.ID, owner, current,
		)
	} else {
		res, err = tx.Exec(
			`UPDATE resources SET `+setContent+`
			 WHERE id=? AND owner_handle=? AND version=?`,
			string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, int64(len(req.Blob.Ciphertext)), version, normalizeMinClient(req.MinClient),
			req.ID, owner, current,
		)
	}
	if err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		tx.Rollback()
		return "", 0, ErrVersionConflict
	}
	// Defense-in-depth against a client re-PUTting an object-backed resource without
	// its roots (e.g. a buggy key rotation): clearing every ChunkRef while the prior
	// version had some would orphan the still-referenced objects for the next GC. No
	// legitimate replace does this — a folder/streamed update always carries at least
	// its manifest/root objects — so reject it rather than commit the unrooting. The
	// per-resource lock above makes this count-then-replace atomic.
	if len(req.ChunkRefs) == 0 {
		var existing int
		if err := tx.QueryRow(
			`SELECT count(*) FROM resource_chunks WHERE resource_id = ?`, req.ID,
		).Scan(&existing); err != nil {
			tx.Rollback()
			return "", 0, err
		}
		if existing > 0 {
			tx.Rollback()
			return "", 0, ErrDropsRoots
		}
	}
	// Replace the GC roots to match the new manifest; chunks only this version
	// referenced become unreferenced and eligible for a later sweep.
	if err := replaceResourceChunks(tx, req.ID, owner, req.ChunkRefs); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	// A revocation is a key rotation and a grant delete, and this is what makes them one
	// operation. Split across two requests, a rotation that commits while the delete is
	// lost leaves the revoked account still listed as a grantee — so the next rotation
	// dutifully re-wraps the new key to it. Deleting a grant that is already gone is a
	// no-op, which keeps a retried rotation idempotent.
	if req.RevokeGrantee != "" {
		if _, err := tx.Exec(
			`DELETE FROM grants WHERE resource_id = ? AND owner_handle = ? AND grantee_handle = ?`,
			req.ID, owner, req.RevokeGrantee,
		); err != nil {
			tx.Rollback()
			return "", 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	committed = true
	s.removeStaleBlobs(req.ID, req.Blob.Nonce) // reclaim the superseded blob(s)
	return req.ID, version, nil
}

// GetResource loads a resource by id and spends a max-reads permit if the read is
// subject to one. requireOwner, when non-empty, restricts access to that owner; a
// mismatch returns ErrNotFound (private resources never confirm their own existence
// to non-owners).
func (s *Store) GetResource(id, requireOwner string) (api.GetResourceResponse, error) {
	res, countRead, err := s.GetResourceUncounted(id, requireOwner)
	if err != nil {
		return res, err
	}
	if countRead {
		if err := s.CountResourceRead(id); err != nil {
			return api.GetResourceResponse{}, err
		}
	}
	return res, nil
}

// CountResourceRead spends one of a public link's max-reads permits, returning
// ErrGone once none are left (or the row has been reclaimed since).
func (s *Store) CountResourceRead(id string) error {
	_, err := s.countPublicRead(id)
	return err
}

// GetResourceUncounted is GetResource with the max-reads permit left unspent.
// countRead reports that this read is subject to the link's read limit and that the
// caller owes exactly one CountResourceRead — which is also what enforces
// exhaustion — before it serves any bytes. The public read handler uses this so a
// request it goes on to refuse (too old a client, no acceptable representation)
// cannot burn a link the intended recipient never received.
func (s *Store) GetResourceUncounted(id, requireOwner string) (api.GetResourceResponse, bool, error) {
	var (
		out         api.GetResourceResponse
		owner       string
		visibility  string
		metaJSON    string
		wrappedJSON sql.NullString
		nonce       []byte
		version     int
		minClient   int
		expiresAt   sql.NullInt64
		maxReads    sql.NullInt64
		reads       int64
		reclaimed   bool
		createdAt   int64
		updatedAt   int64
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version, min_client, expires_at, max_reads, reads, reclaimed, created_at, updated_at
		 FROM resources WHERE id = ?`, id,
	).Scan(&owner, &visibility, &metaJSON, &wrappedJSON, &nonce, &version, &minClient, &expiresAt, &maxReads, &reads, &reclaimed, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, false, ErrNotFound
	}
	if err != nil {
		return out, false, err
	}

	// A reclaimed tombstone is gone for everyone (its ciphertext is deleted), including
	// the owner; the owner reaches it only to `aqt rm` the row. Short-circuit before any
	// blob load, whose file no longer exists.
	if reclaimed {
		return out, false, ErrGone
	}

	vis := api.Visibility(visibility)
	isOwner := requireOwner != "" && requireOwner == owner
	// An authenticated non-owner may hold a grant: the content key HPKE-wrapped to
	// their enc key, substituting for ownership on the read path only (every mutation
	// stays owner-scoped). The lookup runs for public resources too, so a grantee can
	// decrypt without a link fragment; a private id without a grant stays ErrNotFound,
	// indistinguishable from a missing one.
	var grantKey []byte
	if !isOwner && requireOwner != "" {
		w, ok, err := s.grantWrappedKey(id, requireOwner)
		if err != nil {
			return out, false, err
		}
		if ok {
			grantKey = w
		}
	}
	isGrantee := grantKey != nil
	if vis == api.Private && !isOwner && !isGrantee {
		return out, false, ErrNotFound
	}
	// A non-owner read of a public link is subject to the lifecycle policy. Expiry is a
	// pure time check (no state to mutate); the max-reads count is left to the caller,
	// so only a read that is actually served spends a permit. Owner reads are never
	// counted or gated (until reclaimed, handled above), and neither are grantee reads:
	// lifecycle is a property of the public link, and a grant is a per-account
	// credential, not a link.
	if !isOwner && !isGrantee {
		now := time.Now().Unix()
		if expiresAt.Valid && now >= expiresAt.Int64 {
			return out, false, ErrGone
		}
	}

	ciphertext, err := s.readBlob(id, nonce)
	if err != nil {
		return out, false, err
	}
	countRead := !isOwner && !isGrantee && maxReads.Valid
	out = api.GetResourceResponse{
		ID:         id,
		Visibility: vis,
		Blob:       crypto.SealedBlob{Nonce: nonce, Ciphertext: ciphertext},
		Version:    version,
		MinClient:  minClient,
	}
	// Lifecycle fields (expiry, read counts, create/update timestamps) are the owner's
	// operational view of the link. A public-link recipient or grantee has no business
	// learning when the link dies, how many reads remain, or when it was last touched,
	// so they are withheld from every non-owner read. Enforcement (expiry, max-reads)
	// stays server-side and is unaffected.
	if isOwner {
		out.ExpiresAt = expiresAt.Int64
		out.MaxReads = maxReads.Int64
		out.Reads = reads
		out.CreatedAt = createdAt
		out.UpdatedAt = updatedAt
	}
	if err := json.Unmarshal([]byte(metaJSON), &out.EncryptedMeta); err != nil {
		return out, false, err
	}
	// The wrapped key is the owner's recovery path and is meaningless to anyone
	// else (it is ciphertext under the owner's master key). Only return it to the
	// owner; a public resource read by anyone else carries no wrapped key.
	if wrappedJSON.Valid && requireOwner == owner {
		var wk crypto.WrappedKey
		if err := json.Unmarshal([]byte(wrappedJSON.String), &wk); err != nil {
			return out, false, err
		}
		out.WrappedKey = &wk
	}
	// A grantee gets the grant wrap instead, plus the owner handle its HPKE info
	// binding needs (a wrong handle from a hostile server just fails the unwrap).
	if isGrantee {
		out.GrantKey = grantKey
		out.Owner = owner
	}
	return out, countRead, nil
}

// countPublicRead atomically records one non-owner serve of a max-reads-limited public
// resource. Held under the resource lock and re-read inside the transaction so two
// concurrent fetches can never both slip past the last permitted read: the Nth reader
// commits reads == max_reads and stamps exhausted_at, the (N+1)th sees the limit and
// gets ErrGone. A policy the update path cleared (max_reads now NULL) means no limit.
func (s *Store) countPublicRead(id string) (int64, error) {
	defer s.resLocks.lock(id)()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var (
		reads     int64
		maxReads  sql.NullInt64
		reclaimed bool
	)
	if err := tx.QueryRow(
		`SELECT reads, max_reads, reclaimed FROM resources WHERE id = ?`, id,
	).Scan(&reads, &maxReads, &reclaimed); err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if reclaimed {
		tx.Rollback()
		return 0, ErrGone
	}
	if !maxReads.Valid {
		tx.Rollback()
		return reads, nil
	}
	if reads >= maxReads.Int64 {
		tx.Rollback()
		return 0, ErrGone
	}
	reads++
	var exhaustedAt sql.NullInt64
	if reads >= maxReads.Int64 {
		exhaustedAt = sql.NullInt64{Int64: time.Now().Unix(), Valid: true}
	}
	if _, err := tx.Exec(
		`UPDATE resources SET reads = ?, exhausted_at = COALESCE(exhausted_at, ?) WHERE id = ?`,
		reads, exhaustedAt, id,
	); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return reads, nil
}

// PublicResourcePreflight reads only lifecycle columns and encrypted metadata. It
// never calls countPublicRead and therefore cannot consume a burn/read-limited link.
func (s *Store) PublicResourcePreflight(id string) (api.PublicResourcePreflight, error) {
	var (
		visibility string
		metaJSON   string
		minClient  int
		expiresAt  sql.NullInt64
		maxReads   sql.NullInt64
		reads      int64
		reclaimed  bool
	)
	err := s.rdb.QueryRow(
		`SELECT visibility, encrypted_meta, min_client, expires_at, max_reads, reads, reclaimed FROM resources WHERE id = ?`, id,
	).Scan(&visibility, &metaJSON, &minClient, &expiresAt, &maxReads, &reads, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) || err == nil && api.Visibility(visibility) != api.Public {
		return api.PublicResourcePreflight{}, ErrNotFound
	}
	if err != nil {
		return api.PublicResourcePreflight{}, err
	}
	if reclaimed || expiresAt.Valid && time.Now().Unix() >= expiresAt.Int64 || maxReads.Valid && reads >= maxReads.Int64 {
		return api.PublicResourcePreflight{}, ErrGone
	}
	var meta crypto.SealedBlob
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		return api.PublicResourcePreflight{}, err
	}
	out := api.PublicResourcePreflight{ID: id, EncryptedMeta: meta, MinClient: minClient, Reads: reads}
	if expiresAt.Valid {
		out.ExpiresAt = expiresAt.Int64
	}
	if maxReads.Valid {
		out.MaxReads = maxReads.Int64
	}
	return out, nil
}

// ResourceVisibility returns a resource's visibility without loading its blob.
// The web landing page uses it to decide whether to render (public), 410 (a gone
// public link), or 404 (private or unknown), so a private resource's existence is
// never confirmed. gone reports an expired/exhausted-and-reclaimed public link:
// reclaimed is a hard tombstone, and an expired-but-not-yet-swept link is gone too so
// the page does not offer a pull command that would 410.
func (s *Store) ResourceVisibility(id string) (vis api.Visibility, gone bool, err error) {
	var (
		visStr    string
		expiresAt sql.NullInt64
		reclaimed bool
	)
	err = s.rdb.QueryRow(
		`SELECT visibility, expires_at, reclaimed FROM resources WHERE id = ?`, id,
	).Scan(&visStr, &expiresAt, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	gone = reclaimed || (expiresAt.Valid && time.Now().Unix() >= expiresAt.Int64)
	return api.Visibility(visStr), gone, nil
}

// SetVisibility flips a resource public/private in place (owner-checked, version
// bumped) without touching the blob or its wrapped key. The request's
// ExpireSeconds/MaxReads/OnExpiry carry an optional lifecycle policy applied on the
// same flip: keeping/turning public with a policy replaces it and resets the read
// counter (and clears any exhausted mark), so a re-share starts fresh; turning private
// clears the policy entirely, since lifecycle is a property of the public link. A
// policy on a private flip is a client bug (ErrPolicyOnPrivate).
func (s *Store) SetVisibility(owner, id string, req api.SetVisibilityRequest) (int, error) {
	expiresAt, maxReadsCol, onExpiry, err := resolvePolicy(req.Visibility, req.ExpireSeconds, req.MaxReads, req.OnExpiry, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	defer s.resLocks.lock(id)()
	var current int
	err = s.db.QueryRow(`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, id, owner).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if req.ExpectedVersion > 0 && req.ExpectedVersion != current {
		return 0, ErrVersionConflict
	}
	res, err := s.db.Exec(
		`UPDATE resources SET visibility = ?, version = version + 1, updated_at = unixepoch(),
		   expires_at = ?, max_reads = ?, on_expiry = ?, reads = 0, exhausted_at = NULL
		 WHERE id = ? AND owner_handle = ?`,
		string(req.Visibility), expiresAt, maxReadsCol, onExpiry, id, owner,
	)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	return current + 1, nil
}

// UpdateResourceMetadata atomically replaces the opaque metadata blob without
// touching content, chunk roots, visibility, grants, or lifecycle policy.
// capability is gated against the stored min_client the same way updateResource
// gates content writes: a client that cannot read the current sealed format must
// not overwrite it. min_client itself is left unchanged — this write carries no
// format bump.
func (s *Store) UpdateResourceMetadata(owner, id string, capability int, req api.UpdateResourceMetadataRequest) (int, error) {
	metaJSON, err := json.Marshal(req.EncryptedMeta)
	if err != nil {
		return 0, err
	}
	defer s.resLocks.lock(id)()
	var storedMin int
	err = s.rdb.QueryRow(
		`SELECT min_client FROM resources WHERE id = ? AND owner_handle = ? AND reclaimed = 0`, id, owner,
	).Scan(&storedMin)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if capability < storedMin {
		return 0, &UpgradeRequiredError{MinClient: storedMin}
	}
	res, err := s.db.Exec(
		`UPDATE resources SET encrypted_meta = ?, version = version + 1, updated_at = unixepoch()
		 WHERE id = ? AND owner_handle = ? AND version = ? AND reclaimed = 0`,
		string(metaJSON), id, owner, req.ExpectedVersion,
	)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var current int
		err := s.rdb.QueryRow(`SELECT version FROM resources WHERE id = ? AND owner_handle = ? AND reclaimed = 0`, id, owner).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		return 0, ErrVersionConflict
	}
	return req.ExpectedVersion + 1, nil
}

// ListResources returns one page of the owner's resources ordered by id, plus the
// cursor for the next page (empty when the page is the last). The cursor is the last
// row's id; the query keyset-seeks past it, so paging never buffers the whole set.
func (s *Store) ListResources(owner string, page pageParams) ([]api.ResourceListItem, string, error) {
	limit := page.effectiveLimit()
	where := "owner_handle = ?"
	args := []any{owner}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 1)
		if err != nil {
			return nil, "", err
		}
		where += " AND id > ?"
		args = append(args, parts[0])
	}
	args = append(args, limit+1) // one extra row tells us whether a next page exists
	rows, err := s.rdb.Query(
		`SELECT id, visibility, encrypted_meta, wrapped_key, version, auto_snapshot,
		        COALESCE(expires_at, 0), COALESCE(max_reads, 0), COALESCE(reads, 0), created_at, updated_at
		 FROM resources WHERE `+where+` ORDER BY id LIMIT ?`, args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var items []api.ResourceListItem
	for rows.Next() {
		var (
			item        api.ResourceListItem
			vis         string
			metaJSON    string
			wrappedJSON sql.NullString
		)
		if err := rows.Scan(&item.ID, &vis, &metaJSON, &wrappedJSON, &item.Version, &item.AutoSnapshot,
			&item.ExpiresAt, &item.MaxReads, &item.Reads, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, "", err
		}
		item.Visibility = api.Visibility(vis)
		if err := json.Unmarshal([]byte(metaJSON), &item.EncryptedMeta); err != nil {
			return nil, "", err
		}
		// The owner's recovery key, so they can decrypt their own resource names in
		// `ls`/`find`. This endpoint is owner-only (authed), so returning it leaks
		// nothing a per-resource GET would not.
		if wrappedJSON.Valid {
			var wk crypto.WrappedKey
			if err := json.Unmarshal([]byte(wrappedJSON.String), &wk); err != nil {
				return nil, "", err
			}
			item.WrappedKey = &wk
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		next = encodeCursor(items[len(items)-1].ID)
	}
	return items, next, nil
}

func (s *Store) DeleteResource(owner, id string) error {
	return s.DeleteResourceVersion(owner, id, 0)
}

func (s *Store) DeleteResourceVersion(owner, id string, expectedVersion int) error {
	defer s.resLocks.lock(id)()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if expectedVersion > 0 {
		var current int
		err := tx.QueryRow(`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, id, owner).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return ErrNotFound
		}
		if err != nil {
			tx.Rollback()
			return err
		}
		if current != expectedVersion {
			tx.Rollback()
			return ErrVersionConflict
		}
	}
	res, err := tx.Exec(`DELETE FROM resources WHERE id = ? AND owner_handle = ?`, id, owner)
	if err != nil {
		tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		tx.Rollback()
		return ErrNotFound
	}
	// Drop the GC roots; the chunks themselves are reclaimed by a later sweep
	// (they may still be referenced by another of the owner's resources or pinned
	// by a snapshot). The dropped ids are read before the delete so the pack
	// counters can be recomputed for exactly the packs this unrooting touches.
	dropped, err := resourceChunkIDs(tx, id)
	if err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}
	if err := recountPacksForChunks(tx, owner, dropped); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeStaleBlobs(id, nil) // drop every blob file for this resource
	return nil
}

// SetResourceMinClientForTest overrides a resource's stored min_client. It exists
// only so end-to-end tests can simulate a future write-format boundary (a resource
// whose min_client exceeds the current ClientCapability) without a client that could
// declare one — production writes go through PutResource, which caps the declared
// value at the writer's own capability.
func (s *Store) SetResourceMinClientForTest(id string, minClient int) error {
	_, err := s.db.Exec(`UPDATE resources SET min_client = ? WHERE id = ?`, minClient, id)
	return err
}

// SetResourceExpiryForTest overrides a resource's stored expires_at (unix seconds), so
// an end-to-end test can drive a link past its expiry without waiting out a real TTL.
func (s *Store) SetResourceExpiryForTest(id string, expiresAt int64) error {
	_, err := s.db.Exec(`UPDATE resources SET expires_at = ? WHERE id = ?`, expiresAt, id)
	return err
}

// ResourcePolicyForTest reports whether a resource carries a lifecycle policy, so a
// test can assert a failed policy write left nothing armed behind it.
func (s *Store) ResourcePolicyForTest(id string) (hasExpiry, hasMaxReads bool, err error) {
	var expiresAt, maxReads sql.NullInt64
	err = s.rdb.QueryRow(`SELECT expires_at, max_reads FROM resources WHERE id = ?`, id).
		Scan(&expiresAt, &maxReads)
	return expiresAt.Valid, maxReads.Valid, err
}

// --- snapshots ---
//
// A snapshot freezes a resource version against the in-place overwrite the next
// sync performs: updateResource replaces the blob and the resource's GC roots and
// removeStaleBlobs drops the superseded blob file, so without a snapshot the prior
// state is gone. CreateSnapshot copies the root blob to a snapshot-owned file and
// the chunk roots into snapshot_chunks, which the GC root queries union in (see
// GCPacks/repackCandidates/commitRepack), so the objects a snapshot needs stay
// live. Snapshots are owner-scoped and never public; all decryption is the
// client's, so the server copies only ciphertext and never sees a key.

// decodeMetaKey parses a stored resource/snapshot's JSON-encoded sealed metadata
// and optional wrapped key into the api shapes. The wrapped key stays nil when the
// column is null (a public resource without a recovery key).
func decodeMetaKey(metaJSON string, wrappedJSON sql.NullString, meta *crypto.SealedBlob, wk **crypto.WrappedKey) error {
	if err := json.Unmarshal([]byte(metaJSON), meta); err != nil {
		return err
	}
	if wrappedJSON.Valid {
		var k crypto.WrappedKey
		if err := json.Unmarshal([]byte(wrappedJSON.String), &k); err != nil {
			return err
		}
		*wk = &k
	}
	return nil
}

// decodeLabel parses a snapshot's optional JSON-encoded sealed label, returning nil
// when the column is null (no label, or a scheduled snapshot).
func decodeLabel(labelJSON sql.NullString) (*crypto.SealedBlob, error) {
	if !labelJSON.Valid {
		return nil, nil
	}
	var b crypto.SealedBlob
	if err := json.Unmarshal([]byte(labelJSON.String), &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// CreateSnapshot pins the owner's current version of a resource, returning the new
// snapshot's metadata. It is keyless: it copies the already-sealed blob and the
// existing chunk roots, decrypting nothing. label, when non-nil, is the client-
// sealed user label stored opaquely alongside. anchor pins the snapshot against
// retention (see `aqt checkpoint`).
func (s *Store) CreateSnapshot(owner, resourceID string, label *crypto.SealedBlob, anchor bool) (api.SnapshotInfo, error) {
	return s.createSnapshot(owner, resourceID, label, false, anchor, "")
}

// createSnapshot is CreateSnapshot plus the scheduled marker: the scheduled job's
// snapshots are tagged so retention can prune them without touching manual ones.
// anchored pins the snapshot against every retention path.
func (s *Store) CreateSnapshotIdempotent(owner string, req api.CreateSnapshotRequest) (api.SnapshotInfo, error) {
	return s.createSnapshot(owner, req.ResourceID, req.EncryptedLabel, false, req.Anchor, req.IdempotencyKey)
}

func (s *Store) createSnapshot(owner, resourceID string, label *crypto.SealedBlob, scheduled, anchored bool, idempotencyKey string) (api.SnapshotInfo, error) {
	digest, err := idempotencyDigest(struct {
		ResourceID string
		Label      *crypto.SealedBlob
		Anchored   bool
	}{resourceID, label, anchored})
	if err != nil {
		return api.SnapshotInfo{}, err
	}
	var prior api.SnapshotInfo
	if found, err := lookupIdempotency(s.rdb, owner, "snapshot.create", idempotencyKey, digest, &prior); err != nil {
		return api.SnapshotInfo{}, err
	} else if found {
		return prior, nil
	}
	// Serialize against a concurrent update/delete of the same resource so the
	// snapshot copies a consistent (blob, chunk-roots) pair, not a torn mix of two
	// versions. Held in the store so the keyless scheduled job is serialized too, not
	// only the manual path that comes through the handler.
	defer s.resLocks.lock(resourceID)()
	var (
		visibility, metaJSON string
		wrappedJSON          sql.NullString
		nonce                []byte
		version              int
		minClient            int
	)
	err = s.db.QueryRow(
		`SELECT visibility, encrypted_meta, wrapped_key, blob_nonce, version, min_client
		 FROM resources WHERE id = ? AND owner_handle = ?`, resourceID, owner,
	).Scan(&visibility, &metaJSON, &wrappedJSON, &nonce, &version, &minClient)
	if errors.Is(err, sql.ErrNoRows) {
		return api.SnapshotInfo{}, ErrNotFound
	}
	if err != nil {
		return api.SnapshotInfo{}, err
	}

	blob, err := s.readBlob(resourceID, nonce)
	if err != nil {
		return api.SnapshotInfo{}, err
	}

	snapID := newID(8)
	// Copy the root blob to the snapshot's own nonce-addressed file before the row
	// commits, mirroring createResource: a crash only orphans this new file, never
	// leaves a snapshot row pointing at missing bytes. removeStaleBlobs globs by the
	// resource id and the snapshot's file is named by snapID, so a later update or
	// delete of the source resource never touches it.
	committed := false
	defer func() {
		if !committed {
			s.removeStaleBlobs(snapID, nil)
		}
	}()
	if err := s.writeBlob(snapID, nonce, blob); err != nil {
		return api.SnapshotInfo{}, err
	}
	blobSize := int64(len(blob))

	var labelJSON sql.NullString
	if label != nil {
		b, err := json.Marshal(label)
		if err != nil {
			return api.SnapshotInfo{}, err
		}
		labelJSON = sql.NullString{String: string(b), Valid: true}
	}

	sched := 0
	if scheduled {
		sched = 1
	}
	anchor := 0
	if anchored {
		anchor = 1
	}
	createdAt := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return api.SnapshotInfo{}, err
	}
	// Authoritative duplicate check; see the matching re-check in createResource.
	if found, err := lookupIdempotency(tx, owner, "snapshot.create", idempotencyKey, digest, &prior); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	} else if found {
		tx.Rollback()
		return prior, nil
	}
	info := api.SnapshotInfo{ID: snapID, ResourceID: resourceID, Version: version, CreatedAt: createdAt, EncryptedLabel: label, Anchored: anchored}
	if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO snapshots(snapshot_id, owner_handle, resource_id, visibility, encrypted_meta, encrypted_label, wrapped_key, blob_nonce, blob_size, version_captured, created_at, scheduled, min_client, anchored)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		snapID, owner, resourceID, visibility, metaJSON, labelJSON, wrappedJSON, nonce, blobSize, version, createdAt, sched, minClient, anchor,
	); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	// Pin every object the live resource references now. The FK to objects holds
	// because the resource still roots them, and copying inside the tx makes the pin
	// atomic against a concurrent GC (the single writer connection serializes the two
	// transactions). No pack recount is needed: every pinned object is already live
	// via resource_chunks, so the pin flips no object's rooted state.
	if _, err := tx.Exec(
		`INSERT INTO snapshot_chunks(snapshot_id, owner_handle, chunk_id)
		 SELECT ?, owner_handle, chunk_id FROM resource_chunks WHERE resource_id = ?`,
		snapID, resourceID,
	); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	if err := recordIdempotency(tx, owner, "snapshot.create", idempotencyKey, digest, info); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.SnapshotInfo{}, err
	}
	committed = true

	return info, nil
}

// ListSnapshots returns one page of the owner's snapshots, newest first, plus the
// cursor for the next page. A non-empty resourceID restricts the list to one
// resource's history. The ordering is (created_at DESC, snapshot_id ASC), so the
// keyset seek uses that mixed-direction predicate.
func (s *Store) ListSnapshots(owner, resourceID string, page pageParams) ([]api.SnapshotInfo, string, error) {
	limit := page.effectiveLimit()
	query := `SELECT snapshot_id, resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key, anchored
	          FROM snapshots WHERE owner_handle = ?`
	args := []any{owner}
	if resourceID != "" {
		query += ` AND resource_id = ?`
		args = append(args, resourceID)
	}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 2)
		if err != nil {
			return nil, "", err
		}
		createdAt, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, "", errBadCursor
		}
		query += ` AND (created_at < ? OR (created_at = ? AND snapshot_id > ?))`
		args = append(args, createdAt, createdAt, parts[1])
	}
	query += ` ORDER BY created_at DESC, snapshot_id LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.rdb.Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []api.SnapshotInfo
	for rows.Next() {
		var (
			info        api.SnapshotInfo
			metaJSON    string
			labelJSON   sql.NullString
			wrappedJSON sql.NullString
		)
		if err := rows.Scan(&info.ID, &info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON, &info.Anchored); err != nil {
			return nil, "", err
		}
		if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
			return nil, "", err
		}
		if info.EncryptedLabel, err = decodeLabel(labelJSON); err != nil {
			return nil, "", err
		}
		out = append(out, info)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(strconv.FormatInt(last.CreatedAt, 10), last.ID)
	}
	return out, next, nil
}

// GetSnapshot returns one snapshot's sealed root blob plus the copied meta and
// wrapped key, so the client can reconstruct it; the chunk objects are fetched by
// id through the normal object-store path.
func (s *Store) GetSnapshot(owner, snapshotID string) (api.GetSnapshotResponse, error) {
	var (
		out         api.GetSnapshotResponse
		metaJSON    string
		labelJSON   sql.NullString
		wrappedJSON sql.NullString
		nonce       []byte
	)
	info := api.SnapshotInfo{ID: snapshotID}
	var minClient int
	err := s.rdb.QueryRow(
		`SELECT resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key, blob_nonce, min_client, anchored
		 FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner,
	).Scan(&info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON, &nonce, &minClient, &info.Anchored)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
		return out, err
	}
	if info.EncryptedLabel, err = decodeLabel(labelJSON); err != nil {
		return out, err
	}
	ciphertext, err := s.readBlob(snapshotID, nonce)
	if err != nil {
		return out, err
	}
	out.Snapshot = info
	out.Blob = crypto.SealedBlob{Nonce: nonce, Ciphertext: ciphertext}
	out.MinClient = minClient
	return out, nil
}

// DeleteSnapshot removes a snapshot and its chunk roots. Objects it pinned that no
// live resource or other snapshot still roots become unreferenced and are reclaimed
// by a later GC sweep/repack; the snapshot's own blob copy is dropped here.
func (s *Store) DeleteSnapshot(owner, snapshotID string) error {
	var (
		nonce    []byte
		anchored bool
	)
	err := s.db.QueryRow(
		`SELECT blob_nonce, anchored FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner,
	).Scan(&nonce, &anchored)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// Refuse in the store, not just the client: the anchor is the durable guarantee a
	// checkpoint is not pruned, so it must hold against any caller, including a stale
	// client that never learned the snapshot was anchored.
	if anchored {
		return ErrSnapshotAnchored
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// Unpinning can flip objects dead (if no resource or other snapshot still roots
	// them), so the affected packs' counters are recomputed in the same transaction.
	dropped, err := snapshotChunkIDs(tx, snapshotID)
	if err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM snapshot_chunks WHERE snapshot_id = ?`, snapshotID); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner); err != nil {
		tx.Rollback()
		return err
	}
	if err := recountPacksForChunks(tx, owner, dropped); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeStaleBlobs(snapshotID, nil)
	return nil
}

// snapshotChunkIDs returns the chunk ids a snapshot currently pins.
func snapshotChunkIDs(tx *sql.Tx, snapshotID string) ([]string, error) {
	rows, err := tx.Query(`SELECT chunk_id FROM snapshot_chunks WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetSnapshotAnchor sets a snapshot's anchor flag and returns the updated metadata so
// the client can verify the new state (an older server that lacks the column would
// echo the old value, which the client treats as a hard error). Owner-checked;
// ErrNotFound if no such snapshot belongs to the owner.
func (s *Store) SetSnapshotAnchor(owner, snapshotID string, anchored bool) (api.SnapshotInfo, error) {
	v := 0
	if anchored {
		v = 1
	}
	res, err := s.db.Exec(
		`UPDATE snapshots SET anchored = ? WHERE snapshot_id = ? AND owner_handle = ?`, v, snapshotID, owner,
	)
	if err != nil {
		return api.SnapshotInfo{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return api.SnapshotInfo{}, ErrNotFound
	}

	info := api.SnapshotInfo{ID: snapshotID}
	var (
		metaJSON    string
		labelJSON   sql.NullString
		wrappedJSON sql.NullString
	)
	if err := s.db.QueryRow(
		`SELECT resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key, anchored
		 FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner,
	).Scan(&info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON, &info.Anchored); err != nil {
		return api.SnapshotInfo{}, err
	}
	if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
		return api.SnapshotInfo{}, err
	}
	if info.EncryptedLabel, err = decodeLabel(labelJSON); err != nil {
		return api.SnapshotInfo{}, err
	}
	return info, nil
}

// SetAutoSnapshot toggles whether the scheduled job covers a resource (the per-root
// opt-out). Owner-checked.
func (s *Store) SetAutoSnapshot(owner, resourceID string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := s.db.Exec(
		`UPDATE resources SET auto_snapshot = ? WHERE id = ? AND owner_handle = ?`, v, resourceID, owner,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RunAutoSnapshots snapshots every auto-snapshot resource whose current version is
// not already snapshotted, across all owners, and returns the count created.
// Version-dedup keeps the scheduled job's cost proportional to actual change rather
// than to how often it ticks.
func (s *Store) RunAutoSnapshots() (int, error) {
	return s.RunAutoSnapshotsWithLimits(0, 0)
}

func (s *Store) RunAutoSnapshotsWithLimits(maxSnapshots int, quotaBytes int64) (int, error) {
	// wrapped_key IS NOT NULL skips public resources: their content key only lives in
	// a share URL fragment, so a keyless snapshot of one could never be restored, yet
	// would pin its chunks forever. A manual snapshot stays the owner's call.
	rows, err := s.rdb.Query(
		`SELECT r.owner_handle, r.id FROM resources r
		 WHERE r.auto_snapshot = 1
		   AND r.wrapped_key IS NOT NULL
		   AND NOT EXISTS (
		     SELECT 1 FROM snapshots s
		     WHERE s.resource_id = r.id AND s.version_captured = r.version
		   )`,
	)
	if err != nil {
		return 0, err
	}
	type ref struct{ owner, id string }
	var due []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.owner, &r.id); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close() // release the read connection before the CreateSnapshot writes below

	// Snapshot each due resource independently: a per-resource failure (e.g. the rare
	// row/blob race a concurrent update can cause, which GetResource also tolerates)
	// must not block the rest of the batch. The first error is returned for logging
	// after the loop has done what it could.
	// AccountUsage stats every blob the owner has, so an owner with many due
	// resources must not recompute it per resource: read it once per owner and
	// adjust the cached copy as snapshots land.
	usageByOwner := map[string]*AccountUsage{}
	created := 0
	var firstErr error
	for _, r := range due {
		var u *AccountUsage
		var added int64
		if maxSnapshots > 0 || quotaBytes > 0 {
			var ok bool
			u, ok = usageByOwner[r.owner]
			if !ok {
				fresh, err := s.AccountUsage(r.owner)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				u = &fresh
				usageByOwner[r.owner] = u
			}
			if maxSnapshots > 0 && u.Snapshots >= int64(maxSnapshots) {
				if firstErr == nil {
					firstErr = &LimitExceededError{Kind: "snapshots", Current: u.Snapshots, Limit: int64(maxSnapshots)}
				}
				continue
			}
			if quotaBytes > 0 {
				res, err := s.GetResource(r.id, r.owner)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				added = estimatedResourceBytes(api.PutResourceRequest{Blob: res.Blob, EncryptedMeta: res.EncryptedMeta, WrappedKey: res.WrappedKey})
				if u.StorageBytes+added > quotaBytes {
					if firstErr == nil {
						firstErr = &LimitExceededError{Kind: "storageBytes", Current: u.StorageBytes, Limit: quotaBytes}
					}
					continue
				}
			}
		}
		if _, err := s.createSnapshot(r.owner, r.id, nil, true, false, ""); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("auto-snapshot %s: %w", r.id, err)
			}
			continue
		}
		created++
		if u != nil {
			u.Snapshots++
			u.StorageBytes += added
		}
	}
	return created, firstErr
}

// PruneAutoSnapshots deletes scheduled snapshots beyond the newest keepLast per
// (owner, resource), oldest first; manual snapshots are never touched. This is the
// retention cap that keeps the scheduled job's storage bounded: without it every
// version ever auto-snapshotted stays pinned forever. keepLast <= 0 disables it.
func (s *Store) PruneAutoSnapshots(keepLast int) (int, error) {
	if keepLast <= 0 {
		return 0, nil
	}
	// Anchored snapshots sit outside the retention universe entirely: the outer
	// s.anchored = 0 never selects one for pruning, and the inner n.anchored = 0 keeps
	// an anchored snapshot from consuming a keep-last slot, so it neither ages out nor
	// pushes an unanchored snapshot out of the window.
	rows, err := s.db.Query(
		`SELECT snapshot_id, owner_handle FROM snapshots s
		 WHERE s.scheduled = 1 AND s.anchored = 0
		   AND (SELECT COUNT(*) FROM snapshots n
		        WHERE n.owner_handle = s.owner_handle AND n.resource_id = s.resource_id
		          AND n.scheduled = 1 AND n.anchored = 0
		          AND (n.created_at > s.created_at
		               OR (n.created_at = s.created_at AND n.snapshot_id > s.snapshot_id))) >= ?`,
		keepLast,
	)
	if err != nil {
		return 0, err
	}
	type ref struct{ id, owner string }
	var due []ref
	for rows.Next() {
		var r ref
		if err := rows.Scan(&r.id, &r.owner); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close() // the single writer connection can't take DeleteSnapshot's writes with this cursor open

	pruned := 0
	var firstErr error
	for _, r := range due {
		if err := s.DeleteSnapshot(r.owner, r.id); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("prune snapshot %s: %w", r.id, err)
			}
			continue
		}
		pruned++
	}
	return pruned, firstErr
}

// --- packed object store ---
//
// Objects are opaque, content-addressed chunks (chunk_id = hex sha256 of the
// ciphertext), scoped to one owner, and stored not as one file each but packed:
// many objects concatenated into one ~16 MiB pack file with a self-describing
// index. The server verifies every object's address on upload and otherwise never
// inspects them. This collapses the per-chunk row+file explosion into a few
// hundred packs and lets a whole pack ship as raw bytes.

// ErrBadPack marks a pack a client uploaded that is malformed or whose contents do
// not match their advertised ids. Handlers map it to 400 (a bad client), distinct
// from a 500 storage failure.
var ErrBadPack = errors.New("malformed pack")

func replaceResourceChunks(tx *sql.Tx, resourceID, owner string, refs []string) error {
	oldRefs, err := resourceChunkIDs(tx, resourceID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, resourceID); err != nil {
		return err
	}
	const batch = 300 // 3 bound vars per row, kept well under SQLite's limit
	for start := 0; start < len(refs); start += batch {
		end := min(start+batch, len(refs))
		group := refs[start:end]
		var values strings.Builder
		args := make([]any, 0, len(group)*3)
		for i, id := range group {
			if i > 0 {
				values.WriteByte(',')
			}
			values.WriteString("(?,?,?)")
			args = append(args, resourceID, owner, id)
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO resource_chunks(resource_id, owner_handle, chunk_id) VALUES `+values.String(),
			args...,
		); err != nil {
			return err
		}
	}
	// Only a ref entering or leaving this resource can flip an object's rooted
	// state (a ref in both sets keeps it rooted throughout), so the recount is
	// scoped to the packs holding the symmetric difference — proportional to the
	// change, not the manifest.
	return recountPacksForChunks(tx, owner, symmetricDiff(oldRefs, refs))
}

// resourceChunkIDs returns the chunk ids a resource currently roots.
func resourceChunkIDs(tx *sql.Tx, resourceID string) ([]string, error) {
	rows, err := tx.Query(`SELECT chunk_id FROM resource_chunks WHERE resource_id = ?`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// symmetricDiff returns the ids present in exactly one of the two sets.
func symmetricDiff(a, b []string) []string {
	setA := make(map[string]bool, len(a))
	for _, id := range a {
		setA[id] = true
	}
	setB := make(map[string]bool, len(b))
	for _, id := range b {
		setB[id] = true
	}
	var out []string
	emittedB := make(map[string]bool, len(b))
	for _, id := range b {
		if setA[id] || emittedB[id] {
			continue
		}
		emittedB[id] = true
		out = append(out, id)
	}
	emittedA := make(map[string]bool, len(a))
	for _, id := range a {
		if setB[id] || emittedA[id] {
			continue
		}
		emittedA[id] = true
		out = append(out, id)
	}
	return out
}

// recountPacksForChunks recomputes the counters of every pack holding one of the
// given chunks, from the post-mutation state inside the caller's transaction.
func recountPacksForChunks(tx *sql.Tx, owner string, chunkIDs []string) error {
	if len(chunkIDs) == 0 {
		return nil
	}
	packSet := map[string]bool{}
	var packs []string
	const batch = 400 // keep the IN clause well under SQLite's bound-variable limit
	err := queryIDsBatched(tx,
		`SELECT DISTINCT pack_id FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, chunkIDs, batch,
		func(rows *sql.Rows) error {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			if !packSet[id] {
				packSet[id] = true
				packs = append(packs, id)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	return recountPacks(tx, owner, packs)
}

// recountPacks recomputes obj_count/live_count/live_bytes for the named packs from
// the objects and root tables as they stand inside the caller's transaction. Every
// write that can flip an object's rooted state or move object rows funnels through
// this, so the counters GC selects on are exact, not approximations.
func recountPacks(tx *sql.Tx, owner string, packIDs []string) error {
	const batch = 400
	for start := 0; start < len(packIDs); start += batch {
		end := min(start+batch, len(packIDs))
		group := packIDs[start:end]
		args := make([]any, 0, len(group)+1)
		args = append(args, owner)
		for _, id := range group {
			args = append(args, id)
		}
		if _, err := tx.Exec(
			`UPDATE packs SET
			   obj_count = (SELECT count(*) FROM objects o
			                WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id),
			   live_count = (SELECT count(*) FROM objects o
			                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id
			                   AND `+objectIsLive+`),
			   live_bytes = COALESCE((SELECT sum(o.length) FROM objects o
			                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id
			                   AND `+objectIsLive+`), 0)
			 WHERE owner_handle = ? AND pack_id IN (`+placeholders(len(group))+`)`,
			args...,
		); err != nil {
			return err
		}
	}
	return nil
}

// objectIsLive is the SQL predicate for "some resource or snapshot roots object o".
const objectIsLive = `(EXISTS(SELECT 1 FROM resource_chunks rc
	                           WHERE rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id)
	                   OR EXISTS(SELECT 1 FROM snapshot_chunks sc
	                             WHERE sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id))`

// MissingChunks returns the subset of object ids the owner does not already store,
// and re-arms the GC age guard on the packs holding the ids it does (the dedup-hit
// set).
//
// An object present here is one the caller will reference in its imminent manifest
// PUT but will not re-upload. Without the touch, a concurrent GC could reap the
// old, momentarily-unreferenced pack holding it in the window between this check
// and that PUT, leaving the committed manifest pointing at a deleted object.
// Bumping the pack's created_at keeps it past the age guard until the PUT roots it.
func (s *Store) MissingChunks(owner string, ids []string) ([]string, error) {
	present := make(map[string]bool, len(ids))
	const batch = 400 // keep the IN clause well under SQLite's bound-variable limit
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, ids, batch,
		func(rows *sql.Rows) error {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			present[id] = true
			return nil
		},
	); err != nil {
		return nil, err
	}

	var missing []string
	for _, id := range ids {
		if !present[id] {
			missing = append(missing, id)
		}
	}
	presentIDs := make([]string, 0, len(present))
	for id := range present {
		presentIDs = append(presentIDs, id)
	}
	if err := s.touchPacksFor(owner, presentIDs); err != nil {
		return nil, err
	}
	return missing, nil
}

// touchPacksFor resets created_at to now on every pack holding one of the given
// objects, re-arming the GC age guard so a sync about to reference them has time to
// commit. Touching the pack (not the object) is what the pack-granularity GC reads.
func (s *Store) touchPacksFor(owner string, objIDs []string) error {
	if len(objIDs) == 0 {
		return nil
	}
	args := make([]any, 0, len(objIDs)+3)
	args = append(args, time.Now().Unix(), owner, owner)
	for _, id := range objIDs {
		args = append(args, id)
	}
	_, err := s.db.Exec(
		`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id IN (
		   SELECT pack_id FROM objects WHERE owner_handle = ? AND chunk_id IN (`+placeholders(len(objIDs))+`)
		 )`,
		args...,
	)
	return err
}

// placeholders returns "?,?,..." with n entries for an IN clause.
func placeholders(n int) string {
	return strings.TrimPrefix(strings.Repeat(",?", n), ",")
}

// rowQueryer is the subset of *sql.DB and *sql.Tx that queryIDsBatched needs.
type rowQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// queryIDsBatched runs query once per batch-size group of ids, keeping the IN clause
// well under SQLite's bound-variable limit. It prepends lead to the bound args and
// splices the group's placeholder list plus closing paren onto query, so callers pass
// the SELECT up to and including "IN (". Each batch's rows are closed before the next
// runs, and the first scan error aborts.
func queryIDsBatched(q rowQueryer, query string, lead []any, ids []string, batch int, scan func(*sql.Rows) error) error {
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		group := ids[start:end]
		args := make([]any, 0, len(lead)+len(group))
		args = append(args, lead...)
		for _, id := range group {
			args = append(args, id)
		}
		rows, err := q.Query(query+placeholders(len(group))+`)`, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := scan(rows); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	return nil
}

// PutPack stores one self-describing pack for the owner. It verifies the pack
// address (pack_id = sha256 of the bytes) and every object slice against its id,
// then writes the file and inserts the pack + object rows in one transaction.
//
// Idempotent in two ways: re-uploading the same pack re-arms its age guard, and an
// object already stored (in this or another pack, by content address) is left where
// it is — dedup keys on chunk_id, so a second home is just harmless dead space.
// Returns how many objects were newly stored.
//
// quotaBytes > 0 caps the owner's total stored pack bytes: a new pack
// that would push the owner past it is rejected with ErrQuotaExceeded (a re-PUT of an
// already-stored pack is idempotent and never counted twice). The byte counter is
// adjusted in the same transaction that inserts the pack row, so it can never drift
// from the rows it accounts for.
func (s *Store) PutPack(owner, packID string, data []byte, quotaBytes int64) (int, error) {
	return s.PutPackWithLimits(owner, packID, data, quotaBytes, 0)
}

func (s *Store) PutPackWithLimits(owner, packID string, data []byte, quotaBytes int64, maxObjects int) (int, error) {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != packID {
		return 0, fmt.Errorf("%w: pack id does not match its bytes", ErrBadPack)
	}
	index, objectsEnd, err := parsePackIndex(data)
	if err != nil {
		return 0, err
	}
	for _, e := range index {
		// Off and Len come from client JSON, so the bounds check must never add them
		// (off=MaxInt64 + len=1 would wrap negative, slip past, and panic the slice).
		// Compare against objectsEnd without ever computing Off+Len.
		if e.Off < 0 || e.Len < 0 || e.Off > objectsEnd || e.Len > objectsEnd-e.Off {
			return 0, fmt.Errorf("%w: object %s slice escapes the object region", ErrBadPack, e.ID)
		}
		s := sha256.Sum256(data[e.Off : e.Off+e.Len])
		if hex.EncodeToString(s[:]) != e.ID {
			return 0, fmt.Errorf("%w: object %s does not match its slice", ErrBadPack, e.ID)
		}
	}

	// Cheap early reject so an over-quota upload does not write a pack file it will
	// discard. The authoritative check runs inside the transaction below.
	if quotaBytes > 0 {
		if existed, err := s.packExists(owner, packID); err != nil {
			return 0, err
		} else if !existed {
			used, err := s.OwnerPackBytes(owner)
			if err != nil {
				return 0, err
			}
			if used+int64(len(data)) > quotaBytes {
				return 0, ErrQuotaExceeded
			}
		}
	}

	if err := s.writePack(owner, packID, data); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	// DO NOTHING (not DO UPDATE) so RowsAffected distinguishes a first store from a
	// re-PUT: only a first store counts against the quota and re-arms nothing here.
	res, err := tx.Exec(
		`INSERT INTO packs(owner_handle, pack_id, length, created_at) VALUES(?,?,?,?)
		 ON CONFLICT(owner_handle, pack_id) DO NOTHING`,
		owner, packID, len(data), now,
	)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	inserted, _ := res.RowsAffected()
	if inserted == 0 {
		// The pack already exists; re-arm its GC age guard so a concurrent read of it
		// is not reaped, exactly as the prior DO UPDATE did.
		if _, err := tx.Exec(
			`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`, now, owner, packID,
		); err != nil {
			tx.Rollback()
			return 0, err
		}
	} else {
		if quotaBytes > 0 {
			var used int64
			if err := tx.QueryRow(`SELECT pack_bytes FROM accounts WHERE owner_handle = ?`, owner).Scan(&used); err != nil {
				tx.Rollback()
				return 0, err
			}
			if used+int64(len(data)) > quotaBytes {
				tx.Rollback()
				_ = os.Remove(s.packPath(owner, packID))
				return 0, ErrQuotaExceeded
			}
		}
		if err := addOwnerPackBytes(tx, owner, int64(len(data))); err != nil {
			tx.Rollback()
			return 0, err
		}
	}
	stored, err := insertObjects(tx, owner, packID, index)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	if maxObjects > 0 {
		var count int64
		if err := tx.QueryRow(`SELECT count(*) FROM objects WHERE owner_handle = ?`, owner).Scan(&count); err != nil {
			tx.Rollback()
			return 0, err
		}
		if count > int64(maxObjects) {
			tx.Rollback()
			if inserted > 0 {
				_ = os.Remove(s.packPath(owner, packID))
			}
			return 0, &LimitExceededError{Kind: "objects", Current: count - int64(stored), Limit: int64(maxObjects)}
		}
	}
	// The new rows change this pack's obj_count. They cannot be live yet — a root's
	// FK requires a pre-existing object row, so a just-inserted object is unrooted
	// until a later manifest PUT — but recounting keeps one code path.
	if err := recountPacks(tx, owner, []string{packID}); err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return stored, nil
}

// objectInsertBatch is how many object rows ride in one multi-row INSERT. At five
// bound variables per row this stays far under SQLite's variable limit while cutting
// the statement count — and its per-Exec parse/plan overhead — ~200x versus one
// INSERT per chunk, the dominant SQLite cost when ingesting a pack of many small
// chunks (a 16 MiB pack of 8 KiB chunks is ~2000 rows).
const objectInsertBatch = 200

// insertObjects writes a pack's object index into the objects table in batched
// multi-row INSERTs and returns how many rows were newly stored — dedup skips the
// rest via ON CONFLICT DO NOTHING, and RowsAffected on a multi-row INSERT counts only
// the rows actually inserted. It runs inside the caller's transaction; rollback on
// error is the caller's job.
func insertObjects(tx *sql.Tx, owner, packID string, index []api.PackIndexEntry) (int, error) {
	stored := 0
	for start := 0; start < len(index); start += objectInsertBatch {
		end := start + objectInsertBatch
		if end > len(index) {
			end = len(index)
		}
		group := index[start:end]

		var sb strings.Builder
		sb.WriteString(`INSERT INTO objects(owner_handle, chunk_id, pack_id, "offset", length) VALUES `)
		args := make([]any, 0, len(group)*5)
		for i, e := range group {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString("(?,?,?,?,?)")
			args = append(args, owner, e.ID, packID, e.Off, e.Len)
		}
		sb.WriteString(` ON CONFLICT(owner_handle, chunk_id) DO NOTHING`)

		res, err := tx.Exec(sb.String(), args...)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		stored += int(n)
	}
	return stored, nil
}

// parsePackIndex reads a pack's trailing index. Layout:
//
//	[ objects... ][ index JSON ][ uint32 BE indexLen ]
//
// It returns the parsed index and objectsEnd (the first byte past the object
// region, i.e. where the index begins), against which the caller bounds-checks
// every object slice. A structurally invalid pack is an ErrBadPack.
func parsePackIndex(data []byte) (index []api.PackIndexEntry, objectsEnd int, err error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("%w: shorter than the index length trailer", ErrBadPack)
	}
	indexLen := int(binary.BigEndian.Uint32(data[len(data)-4:]))
	objectsEnd = len(data) - 4 - indexLen
	if objectsEnd < 0 {
		return nil, 0, fmt.Errorf("%w: index length %d exceeds the pack", ErrBadPack, indexLen)
	}
	if err := json.Unmarshal(data[objectsEnd:len(data)-4], &index); err != nil {
		return nil, 0, fmt.Errorf("%w: index json: %v", ErrBadPack, err)
	}
	return index, objectsEnd, nil
}

// LocateObjects resolves object ids to their pack and byte range so a client can
// range-fetch them, and re-arms the GC age guard on every pack it resolves. Ids the
// owner does not store are silently skipped (the caller errors if it needed one).
//
// The touch is what keeps a concurrent GC from reaping a pack a download is mid-read
// of: the same defense MissingChunks applies to a writer's dedup hits, applied here
// to a reader's in-flight fetch. Without it a sync that supersedes the version being
// read (unrooting its now-aged manifest/file objects) plus a GC could 404 the
// in-flight read.
func (s *Store) LocateObjects(owner string, ids []string) ([]api.ObjectLocation, error) {
	out := make([]api.ObjectLocation, 0, len(ids))
	seenPack := map[string]bool{}
	var packs []string
	const batch = 400 // keep the IN clause well under SQLite's bound-variable limit
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id, pack_id, "offset", length FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, ids, batch,
		func(rows *sql.Rows) error {
			var (
				id, packID  string
				off, length int64
			)
			if err := rows.Scan(&id, &packID, &off, &length); err != nil {
				return err
			}
			out = append(out, api.ObjectLocation{ID: id, PackID: packID, Off: off, Len: length})
			if !seenPack[packID] {
				seenPack[packID] = true
				packs = append(packs, packID)
			}
			return nil
		},
	); err != nil {
		return nil, err
	}
	if err := s.touchPacks(owner, packs); err != nil {
		return nil, err
	}
	return out, nil
}

// PublicObjectSlices resolves object ids to their pack byte ranges for the
// unauthenticated public-read endpoint, gated on a public resource. It enforces two
// invariants that make a public share link safe to hand object fetch to:
//
//   - A private or unknown resource is indistinguishable: both return ErrNotFound, so
//     the endpoint never confirms a private id's existence (matching GetResource).
//   - Every requested id must be referenced by THIS resource. An id the owner stores
//     but this resource does not reference fails the whole request with ErrNotFound,
//     so a public link cannot be used as an oracle for the owner's unrelated objects.
//
// Locations are returned in request order, one per requested id (a duplicate id
// yields a duplicate entry — the wire framing is positional), and every resolved
// pack is touched so a concurrent GC cannot reap a pack this download is mid-read of.
func (s *Store) PublicObjectSlices(resourceID string, ids []string) (string, []api.ObjectLocation, error) {
	var (
		owner, vis  string
		expiresAt   sql.NullInt64
		exhaustedAt sql.NullInt64
		reclaimed   bool
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, visibility, expires_at, exhausted_at, reclaimed FROM resources WHERE id = ?`, resourceID,
	).Scan(&owner, &vis, &expiresAt, &exhaustedAt, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	if api.Visibility(vis) != api.Public {
		return "", nil, ErrNotFound
	}
	// Expiry and reclamation gate object reads. Exhaustion does not gate them
	// immediately: the root fetch is the per-link-holder gate, and refusing objects
	// the moment the last permit is spent would break that very pull mid-flight (it
	// fetches its objects after the root read that spent it). It is bounded instead
	// by a grace window from the moment of exhaustion — long enough for the pull it
	// protects, short enough that the link does not keep serving until the GC sweep
	// (up to AQT_GC_INTERVAL + gcMinAge, ~7h at the defaults) notices.
	if reclaimed || (expiresAt.Valid && time.Now().Unix() >= expiresAt.Int64) {
		return "", nil, ErrGone
	}
	if exhaustedAt.Valid && time.Now().Unix() >= exhaustedAt.Int64+int64(exhaustedObjectGrace/time.Second) {
		return "", nil, ErrGone
	}
	out, err := s.orderedObjectSlices(owner, resourceID, ids)
	if err != nil {
		return "", nil, err
	}
	return owner, out, nil
}

// orderedObjectSlices resolves a resource's referenced object ids to pack slices in
// request order, enforcing membership: every id must be a chunk root of THIS
// resource, so neither the public endpoint nor a grantee can probe the owner's
// unrelated objects. Callers gate access (visibility or grant) before calling.
func (s *Store) orderedObjectSlices(owner, resourceID string, ids []string) ([]api.ObjectLocation, error) {
	distinct := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			distinct = append(distinct, id)
		}
	}

	const batch = 400 // keep the IN clause well under SQLite's bound-variable limit

	// Membership: every requested id must be a chunk root of this resource. A miss on
	// any id fails the whole request without revealing which one.
	member := map[string]bool{}
	for start := 0; start < len(distinct); start += batch {
		end := min(start+batch, len(distinct))
		group := distinct[start:end]
		args := make([]any, 0, len(group)+1)
		args = append(args, resourceID)
		for _, id := range group {
			args = append(args, id)
		}
		rows, err := s.rdb.Query(
			`SELECT chunk_id FROM resource_chunks WHERE resource_id = ? AND chunk_id IN (`+placeholders(len(group))+`)`,
			args...,
		)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			member[id] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	for _, id := range distinct {
		if !member[id] {
			return nil, ErrNotFound
		}
	}

	// Resolve locations for the owner (same query shape as LocateObjects), indexed by
	// id so the response can be assembled in request order.
	locByID := make(map[string]api.ObjectLocation, len(distinct))
	seenPack := map[string]bool{}
	var packs []string
	for start := 0; start < len(distinct); start += batch {
		end := min(start+batch, len(distinct))
		group := distinct[start:end]
		args := make([]any, 0, len(group)+1)
		args = append(args, owner)
		for _, id := range group {
			args = append(args, id)
		}
		rows, err := s.rdb.Query(
			`SELECT chunk_id, pack_id, "offset", length FROM objects WHERE owner_handle = ? AND chunk_id IN (`+placeholders(len(group))+`)`,
			args...,
		)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				id, packID  string
				off, length int64
			)
			if err := rows.Scan(&id, &packID, &off, &length); err != nil {
				rows.Close()
				return nil, err
			}
			locByID[id] = api.ObjectLocation{ID: id, PackID: packID, Off: off, Len: length}
			if !seenPack[packID] {
				seenPack[packID] = true
				packs = append(packs, packID)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	// The resource_chunks -> objects FK guarantees a membership-verified id locates;
	// treat any miss as not-found rather than serving a short framing.
	out := make([]api.ObjectLocation, 0, len(ids))
	for _, id := range ids {
		loc, ok := locByID[id]
		if !ok {
			return nil, ErrNotFound
		}
		out = append(out, loc)
	}

	if err := s.touchPacks(owner, packs); err != nil {
		return nil, err
	}
	return out, nil
}

// touchPacks re-arms the GC age guard on the named packs. The id list is batched so
// the IN clause stays well under SQLite's bound-variable limit even for a clone that
// resolves many packs at once.
func (s *Store) touchPacks(owner string, packIDs []string) error {
	const batch = 400
	now := time.Now().Unix()
	for start := 0; start < len(packIDs); start += batch {
		end := start + batch
		if end > len(packIDs) {
			end = len(packIDs)
		}
		group := packIDs[start:end]
		args := make([]any, 0, len(group)+2)
		args = append(args, now, owner)
		for _, id := range group {
			args = append(args, id)
		}
		if _, err := s.db.Exec(
			`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id IN (`+placeholders(len(group))+`)`,
			args...,
		); err != nil {
			return err
		}
	}
	return nil
}

// PackFileForOwner returns the on-disk path of a pack the owner stores, or
// ErrNotFound. Used by the download handler to serve raw (range-able) pack bytes
// without ever loading the whole pack into memory.
func (s *Store) PackFileForOwner(owner, packID string) (string, error) {
	var one int
	err := s.rdb.QueryRow(
		`SELECT 1 FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, packID,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return s.packPath(owner, packID), nil
}

// packExists reports whether the owner has a committed pack row for id. RepackOwner
// uses it before deleting a stale new-pack file, so a content-addressed id that
// coincides with a live pack is never removed out from under a committed swap.
func (s *Store) packExists(owner, id string) (bool, error) {
	var one int
	err := s.rdb.QueryRow(
		`SELECT 1 FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, id,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SweepExpired ends the life of the owner's public links whose lifecycle has run out:
// expired ones immediately, and exhausted ones only after a grace window (gcMinAge) so
// an in-flight permitted streamed pull can finish fetching its objects before they
// unroot. What "ending" means is the resource's own on_expiry action — see endOfLife.
// Returns how many rows it acted on. now is passed so tests can drive the clock.
func (s *Store) SweepExpired(owner string, now int64) (int, error) {
	graceCutoff := now - int64(gcMinAge/time.Second)
	rows, err := s.rdb.Query(
		`SELECT id FROM resources
		 WHERE owner_handle = ? AND reclaimed = 0
		   AND ((expires_at IS NOT NULL AND expires_at <= ?)
		     OR (exhausted_at IS NOT NULL AND exhausted_at < ?))`,
		owner, now, graceCutoff,
	)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	var swept int
	for _, id := range ids {
		if err := s.endOfLife(owner, id, now, graceCutoff); err != nil {
			return swept, err
		}
		swept++
	}
	return swept, nil
}

// endOfLife applies one resource's on_expiry action, now that its lifecycle policy has
// fired.
//
// Retire takes the link down and keeps the resource: visibility flips back to private
// and the policy clears, so the link stops resolving while the blobs, objects and the
// owner's wrapped key stay exactly as they were. This is what a link over an existing
// resource means — a shared synced folder is still the authoritative copy every other
// device pulls from, and an expiring link must not delete it.
//
// Reclaim destroys the content, which is what an ephemeral upload (`push --public
// --burn`) asks for: it drops the GC roots (so the objects become collectable), removes
// the ciphertext blob files, clears the owner's wrapped key, marks the row reclaimed,
// and bumps the version. The encrypted metadata is left intact so the owner can still
// see (and `aqt rm`) the tombstone.
//
// Held under the resource lock so it serializes against a concurrent update/delete of
// the same id. now/graceCutoff are the sweep's, so the under-lock re-check tests the
// same lifecycle predicate the scan used.
func (s *Store) endOfLife(owner, id string, now, graceCutoff int64) error {
	defer s.resLocks.lock(id)()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// A concurrent SetVisibility or version-pinned re-PUT can resurrect the link between
	// the unlocked scan and this lock — resetting expires_at/reads/exhausted_at while
	// leaving reclaimed = 0 — so re-testing reclaimed alone would still tombstone a
	// freshly re-shared link and destroy its only wrapped key. Re-run the full lifecycle
	// predicate under the lock and skip if the row no longer matches. The action is read
	// in the same statement, so it is the one the surviving policy was written with.
	var (
		stillExpired bool
		action       string
	)
	if err := tx.QueryRow(
		`SELECT reclaimed = 0
		   AND ((expires_at IS NOT NULL AND expires_at <= ?)
		     OR (exhausted_at IS NOT NULL AND exhausted_at < ?)), on_expiry
		 FROM resources WHERE id = ? AND owner_handle = ?`,
		now, graceCutoff, id, owner,
	).Scan(&stillExpired, &action); err != nil {
		tx.Rollback()
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if !stillExpired {
		tx.Rollback()
		return nil
	}
	if api.OnExpiry(action) == api.ExpiryRetire {
		if _, err := tx.Exec(
			`UPDATE resources SET visibility = ?, expires_at = NULL, max_reads = NULL, reads = 0,
			   exhausted_at = NULL, version = version + 1
			 WHERE id = ?`,
			string(api.Private), id,
		); err != nil {
			tx.Rollback()
			return err
		}
		return tx.Commit()
	}
	dropped, err := resourceChunkIDs(tx, id)
	if err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, id); err != nil {
		tx.Rollback()
		return err
	}
	if err := recountPacksForChunks(tx, owner, dropped); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(
		`UPDATE resources SET reclaimed = 1, wrapped_key = NULL, blob_size = 0, version = version + 1 WHERE id = ?`, id,
	); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeStaleBlobs(id, nil) // drop every blob file; the content is reclaimed
	return nil
}

// GC reclaims the owner's dead pack space under one owner-scoped lock: it sweeps
// fully-dead packs (GCPacks), then compacts the dead objects trapped in still-live
// ones (RepackOwner). The lock serializes the whole sequence so two concurrent passes
// — two folders syncing at once, two devices, or a manual sync racing the watch
// daemon, each of which triggers a GC — cannot both pick the same repack candidate and
// have the loser's stale-plan branch delete the winner's now-live compacted pack. The
// single DB connection serializes the transactions, but not the pack-file writes and
// removes around them, so this lock is what makes the swap safe.
func (s *Store) GC(owner string, minAge time.Duration) (api.GCResponse, error) {
	defer s.gcLocks.lock(owner)()
	// Reclaim expired/exhausted links first, so the objects they unroot become dead and
	// are eligible for the pack sweep in this same pass (still subject to the pack age
	// guard, which is the point of the grace window on exhaustion).
	if _, err := s.SweepExpired(owner, time.Now().Unix()); err != nil {
		return api.GCResponse{}, err
	}
	if err := s.sweepIdempotencyKeys(owner, time.Now()); err != nil {
		return api.GCResponse{}, err
	}
	deleted, freed, err := s.GCPacks(owner, minAge)
	if err != nil {
		return api.GCResponse{}, err
	}
	repacked, reclaimed, err := s.RepackOwner(owner, minAge)
	if err != nil {
		return api.GCResponse{}, err
	}
	return api.GCResponse{
		DeletedPacks:   deleted,
		FreedBytes:     freed,
		RepackedPacks:  repacked,
		ReclaimedBytes: reclaimed,
	}, nil
}

// RunGCAll runs the owner-scoped GC for every account and returns the aggregate,
// so space reclamation does not depend on a client happening to sync (the
// POST /v1/gc trigger). A per-owner failure must not block the rest of the sweep;
// the first error is returned for logging after the loop has done what it could,
// mirroring RunAutoSnapshots.
func (s *Store) RunGCAll(minAge time.Duration) (api.GCResponse, error) {
	owners, err := s.Owners()
	if err != nil {
		return api.GCResponse{}, err
	}
	var total api.GCResponse
	var firstErr error
	for _, owner := range owners {
		res, err := s.GC(owner, minAge)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("gc owner %s: %w", owner, err)
			}
			continue
		}
		total.DeletedPacks += res.DeletedPacks
		total.FreedBytes += res.FreedBytes
		total.RepackedPacks += res.RepackedPacks
		total.ReclaimedBytes += res.ReclaimedBytes
	}
	return total, firstErr
}

// GCPacks deletes the owner's packs none of whose objects any live resource
// references and that were uploaded longer ago than minAge. The age guard keeps an
// in-flight push's freshly uploaded packs from being reaped before its manifest
// commits. v1 only deletes fully-dead packs; dead objects inside a still-live pack
// are tolerated until a future repack. Returns the pack count and bytes reclaimed.
//
// The dead-pack selection and the row deletes run in one transaction. On the single
// writer connection a transaction monopolizes the connection for its duration, so a
// concurrent CheckChunks touch or a resource PUT cannot interleave between the
// SELECT and the DELETEs: it either commits before this sweep began (and the touched
// pack reads as young, so it is not selected) or serializes after it. Without that,
// a touch landing after the SELECT was invisible to the in-flight sweep, which would
// then reap a pack a concurrent push was about to root — turning the FK backstop
// into a spurious push failure instead of a clean dedup hit.
func (s *Store) GCPacks(owner string, minAge time.Duration) (int, int64, error) {
	cutoff := time.Now().Add(-minAge).Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	// A pack is dead only if none of its objects are rooted by a live resource OR a
	// snapshot. live_count folds both root tables in and is maintained inside every
	// transaction that moves objects or roots (see recountPacks), so selection reads
	// the packs table alone instead of joining every object row per sweep.
	rows, err := tx.Query(
		`SELECT pack_id, length FROM packs
		 WHERE owner_handle = ? AND created_at < ? AND live_count = 0`,
		owner, cutoff,
	)
	if err != nil {
		tx.Rollback()
		return 0, 0, err
	}
	type deadPack struct {
		id     string
		length int64
	}
	var dead []deadPack
	for rows.Next() {
		var d deadPack
		if err := rows.Scan(&d.id, &d.length); err != nil {
			rows.Close()
			tx.Rollback()
			return 0, 0, err
		}
		dead = append(dead, d)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		tx.Rollback()
		return 0, 0, err
	}
	rows.Close()

	var freed int64
	for _, d := range dead {
		// Objects FK-reference the pack, so they go first. A dead pack's objects are
		// by definition unreferenced by resource_chunks, so removing them cannot
		// violate that backstop.
		if _, err := tx.Exec(`DELETE FROM objects WHERE owner_handle = ? AND pack_id = ?`, owner, d.id); err != nil {
			tx.Rollback()
			return 0, 0, err
		}
		if _, err := tx.Exec(`DELETE FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, d.id); err != nil {
			tx.Rollback()
			return 0, 0, err
		}
		freed += d.length
	}
	if freed > 0 {
		if err := addOwnerPackBytes(tx, owner, -freed); err != nil {
			tx.Rollback()
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}

	// Remove the pack files only after the rows are durably gone: a crash here leaks
	// an unreferenced file (reclaimable later), never a live row pointing at a
	// deleted file. Best-effort, matching the blob store.
	for _, d := range dead {
		if err := os.Remove(s.packPath(owner, d.id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return len(dead), freed, err
		}
	}
	return len(dead), freed, nil
}

// repackMaxLiveFraction bounds which packs RepackOwner rewrites: a pack whose live
// bytes are more than this fraction of its size is left alone, since rewriting a
// nearly-full pack to reclaim a sliver of dead space costs more IO than it frees.
const repackMaxLiveFraction = 0.5

// repackBudgetBytes caps the live bytes RepackOwner copies per call, so one GC (a
// sync triggers it) never rewrites an unbounded amount of data; the next call picks
// up where this one stopped.
const repackBudgetBytes = 64 << 20

// liveObj is one root-referenced object inside a pack: its content id and its byte
// slice in that pack.
type liveObj struct {
	id          string
	off, length int64
}

// repackCand is a pack worth compacting: it holds both live and dead objects, so
// GCPacks (which only sweeps fully-dead packs) cannot reclaim its dead bytes.
type repackCand struct {
	packID    string
	length    int64
	liveBytes int64
}

// RepackOwner compacts the owner's partially-dead packs. GCPacks reclaims a pack only
// when none of its objects is rooted; a pack that mixes live and dead objects stays
// whole, so its dead bytes leak. RepackOwner copies just the live objects of such a
// pack into a fresh dense pack, re-points them, and drops the old pack with its dead
// bytes. Candidates are older than minAge (so an in-flight upload's packs are not
// disturbed) and at most repackMaxLiveFraction live; at most repackBudgetBytes of
// live data moves per call. Returns the packs rewritten and the bytes reclaimed.
//
// Planning (the SELECTs and the slow pack-file reads) runs outside any transaction;
// the swap re-validates the pack's age and live set inside one, so a concurrent root
// or age-guard touch that lands mid-call makes the swap skip that pack rather than
// strand a now-live object or a reader mid-fetch.
func (s *Store) RepackOwner(owner string, minAge time.Duration) (repacked int, reclaimed int64, err error) {
	cutoff := time.Now().Add(-minAge).Unix()
	candidates, err := s.repackCandidates(owner, cutoff)
	if err != nil {
		return 0, 0, err
	}
	var movedBytes int64
	for _, cand := range candidates {
		if movedBytes >= repackBudgetBytes {
			break
		}
		// The live object list is loaded per candidate, only for packs this pass
		// actually processes within the budget; candidate selection itself never
		// reads object rows.
		live, liveBytes, err := s.packLiveObjects(owner, cand.packID)
		if err != nil {
			return repacked, reclaimed, err
		}
		if len(live) == 0 {
			continue // went fully dead since planning; the next sweep reclaims it
		}
		oldBytes, err := os.ReadFile(s.packPath(owner, cand.packID))
		if err != nil {
			// A missing/unreadable pack file is left for a later pass rather than
			// failing the whole sweep; skip it.
			continue
		}
		newID, newPack, newIndex := buildLivePack(oldBytes, live)
		if newID == cand.packID {
			continue // no dead bytes to reclaim (a candidate should always have some)
		}
		if err := s.writePack(owner, newID, newPack); err != nil {
			return repacked, reclaimed, err
		}
		ok, freed, err := s.commitRepack(owner, cutoff, cand, newID, len(newPack), newIndex)
		if err != nil {
			return repacked, reclaimed, err
		}
		if !ok {
			// The plan went stale (the pack was touched, rooted differently, or
			// vanished). The new file is normally an orphan we just wrote, but a
			// content address can coincide with a pack a prior swap already committed,
			// so drop it only when no row references it — never a live pack's file.
			if exists, cerr := s.packExists(owner, newID); cerr == nil && !exists {
				_ = os.Remove(s.packPath(owner, newID))
			}
			continue
		}
		_ = os.Remove(s.packPath(owner, cand.packID))
		repacked++
		reclaimed += freed
		movedBytes += liveBytes
	}
	return repacked, reclaimed, nil
}

// repackCandidates returns the owner's compaction-worthy packs, selected from the
// maintained per-pack counters alone: aged past cutoff, mixing live and dead objects
// (0 < live_count < obj_count), and at most repackMaxLiveFraction live. No object
// row is read here; the caller loads each candidate's live objects only when it
// actually processes that pack.
func (s *Store) repackCandidates(owner string, cutoff int64) ([]repackCand, error) {
	rows, err := s.rdb.Query(
		`SELECT pack_id, length, live_bytes FROM packs
		 WHERE owner_handle = ? AND created_at < ?
		   AND live_count > 0 AND live_count < obj_count
		 ORDER BY pack_id`,
		owner, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repackCand
	for rows.Next() {
		var c repackCand
		if err := rows.Scan(&c.packID, &c.length, &c.liveBytes); err != nil {
			return nil, err
		}
		// Rewriting a nearly-full pack costs more IO than the sliver it frees; the
		// fraction check stays in Go so the constant is the single source of truth.
		if float64(c.liveBytes) > repackMaxLiveFraction*float64(c.length) {
			continue
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// packLiveObjects returns a pack's rooted objects in ascending offset order, plus
// their total bytes. Planning reads run on the read pool; commitRepack re-validates
// the live set inside its transaction, so a root change between the two only makes
// the swap skip the pack.
func (s *Store) packLiveObjects(owner, packID string) ([]liveObj, int64, error) {
	rows, err := s.rdb.Query(
		`SELECT o.chunk_id, o."offset", o.length FROM objects o
		 WHERE o.owner_handle = ? AND o.pack_id = ? AND `+objectIsLive+`
		 ORDER BY o."offset"`,
		owner, packID,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var (
		live  []liveObj
		total int64
	)
	for rows.Next() {
		var o liveObj
		if err := rows.Scan(&o.id, &o.off, &o.length); err != nil {
			return nil, 0, err
		}
		live = append(live, o)
		total += o.length
	}
	return live, total, rows.Err()
}

// buildLivePack assembles a fresh pack from the live slices of an old pack's bytes,
// mirroring the [objects][index json][uint32 len] wire format the client writes and
// PutPack verifies. The returned index carries each object's new offset in the dense
// pack.
func buildLivePack(oldBytes []byte, live []liveObj) (id string, pack []byte, index []api.PackIndexEntry) {
	var buf []byte
	index = make([]api.PackIndexEntry, 0, len(live))
	for _, o := range live {
		off := len(buf)
		buf = append(buf, oldBytes[o.off:o.off+o.length]...)
		index = append(index, api.PackIndexEntry{ID: o.id, Off: off, Len: int(o.length)})
	}
	indexJSON, err := json.Marshal(index)
	if err != nil {
		panic("server: marshal pack index: " + err.Error()) // a []PackIndexEntry always marshals
	}
	buf = append(buf, indexJSON...)
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(indexJSON)))
	buf = append(buf, lenbuf[:]...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), buf, index
}

// commitRepack performs the row swap for one compacted pack under a single
// transaction, re-checking the old pack's age and live set first. It returns ok=false
// (and makes no change) when the plan has gone stale: the pack vanished, its age guard
// was re-armed by an in-flight read, or its set of rooted objects changed since
// planning. freed is the bytes the swap reclaimed (old pack size minus new).
func (s *Store) commitRepack(owner string, cutoff int64, cand repackCand, newID string, newLen int, newIndex []api.PackIndexEntry) (ok bool, freed int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, 0, err
	}
	var curCreated, curLen int64
	err = tx.QueryRow(`SELECT created_at, length FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID).Scan(&curCreated, &curLen)
	if errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return false, 0, nil
	}
	if err != nil {
		tx.Rollback()
		return false, 0, err
	}
	if curCreated >= cutoff {
		tx.Rollback()
		return false, 0, nil // re-armed age guard: an in-flight read may still use this pack
	}
	liveNow := map[string]bool{}
	lrows, err := tx.Query(
		`SELECT o.chunk_id FROM objects o
		 WHERE o.owner_handle = ? AND o.pack_id = ? AND `+objectIsLive,
		owner, cand.packID,
	)
	if err != nil {
		tx.Rollback()
		return false, 0, err
	}
	for lrows.Next() {
		var id string
		if err := lrows.Scan(&id); err != nil {
			lrows.Close()
			tx.Rollback()
			return false, 0, err
		}
		liveNow[id] = true
	}
	if err := lrows.Err(); err != nil {
		lrows.Close()
		tx.Rollback()
		return false, 0, err
	}
	lrows.Close()

	// The new pack was built from the planned live set; if the rooted set changed,
	// the new pack no longer matches the objects to move, so abandon this pack.
	if len(liveNow) != len(newIndex) {
		tx.Rollback()
		return false, 0, nil
	}
	for _, e := range newIndex {
		if !liveNow[e.ID] {
			tx.Rollback()
			return false, 0, nil
		}
	}

	now := time.Now().Unix()
	if _, err := tx.Exec(
		`INSERT INTO packs(owner_handle, pack_id, length, created_at) VALUES(?,?,?,?)
		 ON CONFLICT(owner_handle, pack_id) DO UPDATE SET created_at = excluded.created_at`,
		owner, newID, newLen, now,
	); err != nil {
		tx.Rollback()
		return false, 0, err
	}
	// Re-point each live object onto the new pack before deleting the old one, so the
	// objects FK never dangles. chunk_id is unchanged, so resource_chunks stays valid.
	for _, e := range newIndex {
		if _, err := tx.Exec(
			`UPDATE objects SET pack_id = ?, "offset" = ?, length = ? WHERE owner_handle = ? AND chunk_id = ?`,
			newID, e.Off, e.Len, owner, e.ID,
		); err != nil {
			tx.Rollback()
			return false, 0, err
		}
	}
	// The old pack now holds only dead objects (the live ones moved); remove them and
	// the pack row.
	if _, err := tx.Exec(`DELETE FROM objects WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID); err != nil {
		tx.Rollback()
		return false, 0, err
	}
	if _, err := tx.Exec(`DELETE FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID); err != nil {
		tx.Rollback()
		return false, 0, err
	}
	// The moved objects now count against the new pack (which may pre-exist with
	// other objects, via the ON CONFLICT above), so recount it in the same tx.
	if err := recountPacks(tx, owner, []string{newID}); err != nil {
		tx.Rollback()
		return false, 0, err
	}
	// The swap added newLen and dropped curLen; keep the byte counter in step within
	// the same transaction.
	if err := addOwnerPackBytes(tx, owner, int64(newLen)-curLen); err != nil {
		tx.Rollback()
		return false, 0, err
	}
	if err := tx.Commit(); err != nil {
		return false, 0, err
	}
	return true, curLen - int64(newLen), nil
}

// --- blob store ---
//
// A resource's blob is stored as one immutable file per nonce
// (blobs/<id>.<hex-nonce>.bin). Each reseal draws a fresh nonce, so a content
// change writes a new file and never mutates an existing one; the resource's row
// (which carries the live blob_nonce) selects the authoritative file. A
// half-applied write can therefore only orphan a new file, never pair the row's
// nonce with mismatched bytes. A visibility flip keeps the nonce, so it needs no
// blob rewrite. Superseded files are reclaimed after the row that supersedes
// them commits.

// blobPath addresses a resource's blob by id+nonce. Like packPath, it fans the file
// out by id prefix (blobs/<ab>/<cd>/<id>.<nonce>.bin) so blobs/ never grows into one
// flat directory whose every entry a glob (removeStaleBlobs) must scan.
func (s *Store) blobPath(id string, nonce []byte) string {
	return filepath.Join(s.blobDir(id), id+"."+hex.EncodeToString(nonce)+".bin")
}

// blobDir is the fan-out directory that holds id's blob file(s). Resource ids are
// fixed-length (newID(8)), so the prefix slice is always in range.
func (s *Store) blobDir(id string) string {
	return filepath.Join(s.blobsDir, id[0:2], id[2:4])
}

// writeBlob writes a blob to its nonce-addressed file and fsyncs it, so the bytes
// are durable before the referencing row commits.
func (s *Store) writeBlob(id string, nonce, ciphertext []byte) error {
	if err := os.MkdirAll(s.blobDir(id), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.blobPath(id, nonce), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Flush the directory entry so the new blob file's name is durable before the
	// referencing row commits, not just its bytes (see fsyncDir).
	return fsyncDir(s.blobDir(id))
}

// removeStaleBlobs deletes every blob file of id except the one for keepNonce
// (pass nil to drop them all). Best-effort: a leak here costs only disk, never
// correctness.
func (s *Store) removeStaleBlobs(id string, keepNonce []byte) {
	keep := s.blobPath(id, keepNonce)
	matches, _ := filepath.Glob(filepath.Join(s.blobDir(id), id+".*.bin"))
	for _, m := range matches {
		if m != keep {
			_ = os.Remove(m)
		}
	}
}

func (s *Store) readBlob(id string, nonce []byte) ([]byte, error) {
	b, err := os.ReadFile(s.blobPath(id, nonce))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// packPath fans out content-addressed packs by their id prefix to keep any one
// directory small: packs/<owner>/<ab>/<cd>/<id>.bin. The id is hex, so the path is
// safe on case-insensitive filesystems.
func (s *Store) packPath(owner, id string) string {
	return filepath.Join(s.packsDir, owner, id[0:2], id[2:4], id+".bin")
}

// writePack writes a pack to its content-addressed file via temp+fsync+rename, so
// the bytes are durable before the row that references them commits (a committed
// manifest must never point at a pack the kernel has not flushed).
func (s *Store) writePack(owner, id string, data []byte) error {
	path := s.packPath(owner, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Flush the directory entry too: the renamed file's data is durable, but the
	// rename itself (the entry pointing at it) is not until the dir is fsynced, so a
	// committed manifest could otherwise reference a pack the kernel loses on a crash.
	return fsyncDir(filepath.Dir(path))
}

// newID returns a URL-safe random identifier encoding nBytes of entropy.
func newID(nBytes int) string {
	return encodeID(randomBytes(nBytes))
}

// newIDFrom encodes given bytes in the newID shape, so a deterministic decoy
// handle is indistinguishable from a freshly minted one.
func newIDFrom(b []byte) string {
	return encodeID(b)
}

// encodeID is the one id spelling both generators share. base64url's alphabet
// includes '-', and a leading one makes the id unaddressable as a bare CLI
// positional (cobra reads it as a flag cluster), so it is folded to 'A'. Doing the
// fold here rather than by re-drawing keeps newIDFrom byte-deterministic and leaves
// the two generators' output distributions identical, so a leading character can
// never distinguish a decoy handle from a minted one.
func encodeID(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	if strings.HasPrefix(s, "-") {
		return "A" + s[1:]
	}
	return s
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return b
}

func isUnique(err error) bool {
	// modernc.org/sqlite surfaces constraint violations in the error string;
	// matching on it avoids depending on the driver's internal error type.
	return err != nil && strings.Contains(err.Error(), "constraint failed")
}
