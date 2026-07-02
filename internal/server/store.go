package server

import (
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

// ErrDropsRoots is returned when a replace would clear every GC root of a resource
// that still has some: an object-backed resource (folder/streamed file) re-PUT with
// no ChunkRefs. Committing it would orphan the still-referenced objects for the next
// GC, so the store refuses it rather than lose data.
var ErrDropsRoots = errors.New("replace drops all chunk roots")

// Store persists accounts, devices, and resource metadata in SQLite, with the
// ciphertext blobs and packs on the filesystem. It holds no plaintext and no live
// keys.
type Store struct {
	db       *sql.DB
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
	dsn := filepath.Join(dataDir, "aqt.db") +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
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
	s := &Store{db: db, blobsDir: blobsDir, packsDir: packsDir, gcLocks: newKeyedMutex(), resLocks: newKeyedMutex()}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

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
}

// migrate applies the migrations a data dir has not yet run, then validates the
// resulting schema. PRAGMA user_version records how many steps have run.
func (s *Store) migrate() error {
	var applied int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&applied); err != nil {
		return err
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
// already taken. The new account starts at auth epoch 1.
func (s *Store) CreateAccount(email string, kdf crypto.KdfParams, publicKey []byte, wrappedRoot crypto.SealedBlob, authVerifier []byte) (Account, error) {
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
	_, err = s.db.Exec(
		`INSERT INTO accounts(owner_handle, email, kdf, public_key, wrapped_root, auth_verifier, auth_epoch)
		 VALUES(?,?,?,?,?,?,1)`,
		handle, email, string(kdfJSON), publicKey, string(rootJSON), vh[:],
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
	err := s.db.QueryRow(
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
	err = s.db.QueryRow(
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
	return newEpoch, nil
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
func (s *Store) CreateDevice(ownerHandle, name string, epoch int) (deviceID, token string, err error) {
	deviceID = newID(10)
	token = newID(32)
	h := sha256.Sum256([]byte(token))
	_, err = s.db.Exec(
		`INSERT INTO devices(device_id, owner_handle, name, token_hash, auth_epoch) VALUES(?,?,?,?,?)`,
		deviceID, ownerHandle, name, h[:], epoch,
	)
	if err != nil {
		return "", "", err
	}
	return deviceID, token, nil
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
func (s *Store) AuthByToken(token string) (owner, deviceID string, err error) {
	h := sha256.Sum256([]byte(token))
	err = s.db.QueryRow(
		`SELECT d.owner_handle, d.device_id FROM devices d
		   JOIN accounts a ON a.owner_handle = d.owner_handle
		 WHERE d.token_hash = ? AND d.auth_epoch = a.auth_epoch`, h[:],
	).Scan(&owner, &deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return owner, deviceID, err
}

// ListDevices returns the owner's attached devices (id + name). Token hashes never
// leave the store.
func (s *Store) ListDevices(owner string) ([]api.Device, error) {
	rows, err := s.db.Query(
		`SELECT device_id, name FROM devices WHERE owner_handle = ? ORDER BY device_id`, owner,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := []api.Device{}
	for rows.Next() {
		var d api.Device
		if err := rows.Scan(&d.ID, &d.Name); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
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
	return nil
}

// --- Resources ---

// PutResource creates a resource (req.ID empty) or replaces one in place
// (req.ID set, ownership-checked, version bumped). The DB write and the blob
// write are coupled so a failure of either leaves no half-written resource:
// the row is committed only after the blob lands, and the blob is written
// atomically so a failed replace keeps the previous content intact.
func (s *Store) PutResource(owner string, req api.PutResourceRequest) (id string, version int, err error) {
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
	return s.updateResource(owner, req, string(metaJSON), wrappedJSON)
}

func (s *Store) createResource(owner string, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
	id := newID(8)
	const version = 1

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
	if _, err := tx.Exec(
		`INSERT INTO resources(id, owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version)
		 VALUES(?,?,?,?,?,?,?)`,
		id, owner, string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, version,
	); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := replaceResourceChunks(tx, id, owner, req.ChunkRefs); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	committed = true
	return id, version, nil
}

func (s *Store) updateResource(owner string, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
	defer s.resLocks.lock(req.ID)()
	var current int
	err := s.db.QueryRow(
		`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, req.ID, owner,
	).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
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
	res, err := tx.Exec(
		`UPDATE resources SET visibility=?, encrypted_meta=?, wrapped_key=?, blob_nonce=?, version=?
		 WHERE id=? AND owner_handle=? AND version=?`,
		string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, version, req.ID, owner, current,
	)
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
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	committed = true
	s.removeStaleBlobs(req.ID, req.Blob.Nonce) // reclaim the superseded blob(s)
	return req.ID, version, nil
}

// GetResource loads a resource by id. requireOwner, when non-empty, restricts
// access to that owner; a mismatch returns ErrNotFound (private resources never
// confirm their own existence to non-owners).
func (s *Store) GetResource(id, requireOwner string) (api.GetResourceResponse, error) {
	var (
		out         api.GetResourceResponse
		owner       string
		visibility  string
		metaJSON    string
		wrappedJSON sql.NullString
		nonce       []byte
		version     int
	)
	err := s.db.QueryRow(
		`SELECT owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version
		 FROM resources WHERE id = ?`, id,
	).Scan(&owner, &visibility, &metaJSON, &wrappedJSON, &nonce, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}

	vis := api.Visibility(visibility)
	if vis == api.Private && (requireOwner == "" || requireOwner != owner) {
		return out, ErrNotFound
	}

	ciphertext, err := s.readBlob(id, nonce)
	if err != nil {
		return out, err
	}
	out = api.GetResourceResponse{
		ID:         id,
		Visibility: vis,
		Blob:       crypto.SealedBlob{Nonce: nonce, Ciphertext: ciphertext},
		Version:    version,
	}
	if err := json.Unmarshal([]byte(metaJSON), &out.EncryptedMeta); err != nil {
		return out, err
	}
	// The wrapped key is the owner's recovery path and is meaningless to anyone
	// else (it is ciphertext under the owner's master key). Only return it to the
	// owner; a public resource read by anyone else carries no wrapped key.
	if wrappedJSON.Valid && requireOwner == owner {
		var wk crypto.WrappedKey
		if err := json.Unmarshal([]byte(wrappedJSON.String), &wk); err != nil {
			return out, err
		}
		out.WrappedKey = &wk
	}
	return out, nil
}

// ResourceVisibility returns a resource's visibility without loading its blob.
// The web landing page uses it to decide whether to render (public) or 404
// (private or unknown), so a private resource's existence is never confirmed.
func (s *Store) ResourceVisibility(id string) (api.Visibility, error) {
	var vis string
	err := s.db.QueryRow(`SELECT visibility FROM resources WHERE id = ?`, id).Scan(&vis)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return api.Visibility(vis), nil
}

// SetVisibility flips a resource public/private in place (owner-checked, version
// bumped) without touching the blob or its wrapped key.
func (s *Store) SetVisibility(owner, id string, vis api.Visibility) (int, error) {
	defer s.resLocks.lock(id)()
	res, err := s.db.Exec(
		`UPDATE resources SET visibility = ?, version = version + 1 WHERE id = ? AND owner_handle = ?`,
		string(vis), id, owner,
	)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	var version int
	if err := s.db.QueryRow(`SELECT version FROM resources WHERE id = ?`, id).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func (s *Store) ListResources(owner string) ([]api.ResourceListItem, error) {
	rows, err := s.db.Query(
		`SELECT id, visibility, encrypted_meta, wrapped_key, version, auto_snapshot FROM resources WHERE owner_handle = ? ORDER BY id`, owner,
	)
	if err != nil {
		return nil, err
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
		if err := rows.Scan(&item.ID, &vis, &metaJSON, &wrappedJSON, &item.Version, &item.AutoSnapshot); err != nil {
			return nil, err
		}
		item.Visibility = api.Visibility(vis)
		if err := json.Unmarshal([]byte(metaJSON), &item.EncryptedMeta); err != nil {
			return nil, err
		}
		// The owner's recovery key, so they can decrypt their own resource names in
		// `ls`/`find`. This endpoint is owner-only (authed), so returning it leaks
		// nothing a per-resource GET would not.
		if wrappedJSON.Valid {
			var wk crypto.WrappedKey
			if err := json.Unmarshal([]byte(wrappedJSON.String), &wk); err != nil {
				return nil, err
			}
			item.WrappedKey = &wk
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteResource(owner, id string) error {
	defer s.resLocks.lock(id)()
	res, err := s.db.Exec(`DELETE FROM resources WHERE id = ? AND owner_handle = ?`, id, owner)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	// Drop the GC roots; the chunks themselves are reclaimed by a later sweep
	// (they may still be referenced by another of the owner's resources).
	if _, err := s.db.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, id); err != nil {
		return err
	}
	s.removeStaleBlobs(id, nil) // drop every blob file for this resource
	return nil
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
// sealed user label stored opaquely alongside.
func (s *Store) CreateSnapshot(owner, resourceID string, label *crypto.SealedBlob) (api.SnapshotInfo, error) {
	return s.createSnapshot(owner, resourceID, label, false)
}

// createSnapshot is CreateSnapshot plus the scheduled marker: the scheduled job's
// snapshots are tagged so retention can prune them without touching manual ones.
func (s *Store) createSnapshot(owner, resourceID string, label *crypto.SealedBlob, scheduled bool) (api.SnapshotInfo, error) {
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
	)
	err := s.db.QueryRow(
		`SELECT visibility, encrypted_meta, wrapped_key, blob_nonce, version
		 FROM resources WHERE id = ? AND owner_handle = ?`, resourceID, owner,
	).Scan(&visibility, &metaJSON, &wrappedJSON, &nonce, &version)
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
	createdAt := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return api.SnapshotInfo{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO snapshots(snapshot_id, owner_handle, resource_id, visibility, encrypted_meta, encrypted_label, wrapped_key, blob_nonce, version_captured, created_at, scheduled)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		snapID, owner, resourceID, visibility, metaJSON, labelJSON, wrappedJSON, nonce, version, createdAt, sched,
	); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	// Pin every object the live resource references now. The FK to objects holds
	// because the resource still roots them, and copying inside the tx makes the pin
	// atomic against a concurrent GC (the single writer connection serializes the two
	// transactions).
	if _, err := tx.Exec(
		`INSERT INTO snapshot_chunks(snapshot_id, owner_handle, chunk_id)
		 SELECT ?, owner_handle, chunk_id FROM resource_chunks WHERE resource_id = ?`,
		snapID, resourceID,
	); err != nil {
		tx.Rollback()
		return api.SnapshotInfo{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.SnapshotInfo{}, err
	}
	committed = true

	info := api.SnapshotInfo{ID: snapID, ResourceID: resourceID, Version: version, CreatedAt: createdAt, EncryptedLabel: label}
	if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
		return api.SnapshotInfo{}, err
	}
	return info, nil
}

// ListSnapshots returns the owner's snapshots, newest first. A non-empty
// resourceID restricts the list to one resource's history.
func (s *Store) ListSnapshots(owner, resourceID string) ([]api.SnapshotInfo, error) {
	query := `SELECT snapshot_id, resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key
	          FROM snapshots WHERE owner_handle = ?`
	args := []any{owner}
	if resourceID != "" {
		query += ` AND resource_id = ?`
		args = append(args, resourceID)
	}
	query += ` ORDER BY created_at DESC, snapshot_id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
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
		if err := rows.Scan(&info.ID, &info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON); err != nil {
			return nil, err
		}
		if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
			return nil, err
		}
		if info.EncryptedLabel, err = decodeLabel(labelJSON); err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, rows.Err()
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
	err := s.db.QueryRow(
		`SELECT resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key, blob_nonce
		 FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner,
	).Scan(&info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON, &nonce)
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
	return out, nil
}

// DeleteSnapshot removes a snapshot and its chunk roots. Objects it pinned that no
// live resource or other snapshot still roots become unreferenced and are reclaimed
// by a later GC sweep/repack; the snapshot's own blob copy is dropped here.
func (s *Store) DeleteSnapshot(owner, snapshotID string) error {
	var nonce []byte
	err := s.db.QueryRow(
		`SELECT blob_nonce FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner,
	).Scan(&nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
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
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeStaleBlobs(snapshotID, nil)
	return nil
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
	// wrapped_key IS NOT NULL skips public resources: their content key only lives in
	// a share URL fragment, so a keyless snapshot of one could never be restored, yet
	// would pin its chunks forever. A manual snapshot stays the owner's call.
	rows, err := s.db.Query(
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
	rows.Close() // the single writer connection can't take CreateSnapshot's writes with this cursor open

	// Snapshot each due resource independently: a per-resource failure (e.g. the rare
	// row/blob race a concurrent update can cause, which GetResource also tolerates)
	// must not block the rest of the batch. The first error is returned for logging
	// after the loop has done what it could.
	created := 0
	var firstErr error
	for _, r := range due {
		if _, err := s.createSnapshot(r.owner, r.id, nil, true); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("auto-snapshot %s: %w", r.id, err)
			}
			continue
		}
		created++
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
	rows, err := s.db.Query(
		`SELECT snapshot_id, owner_handle FROM snapshots s
		 WHERE s.scheduled = 1
		   AND (SELECT COUNT(*) FROM snapshots n
		        WHERE n.owner_handle = s.owner_handle AND n.resource_id = s.resource_id
		          AND n.scheduled = 1
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
	return nil
}

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
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		group := ids[start:end]
		args := make([]any, 0, len(group)+1)
		args = append(args, owner)
		for _, id := range group {
			args = append(args, id)
		}
		rows, err := s.db.Query(
			`SELECT chunk_id FROM objects WHERE owner_handle = ? AND chunk_id IN (`+placeholders(len(group))+`)`,
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
			present[id] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
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

// PutPack stores one self-describing pack for the owner. It verifies the pack
// address (pack_id = sha256 of the bytes) and every object slice against its id,
// then writes the file and inserts the pack + object rows in one transaction.
//
// Idempotent in two ways: re-uploading the same pack re-arms its age guard, and an
// object already stored (in this or another pack, by content address) is left where
// it is — dedup keys on chunk_id, so a second home is just harmless dead space.
// Returns how many objects were newly stored.
func (s *Store) PutPack(owner, packID string, data []byte) (int, error) {
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

	if err := s.writePack(owner, packID, data); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(
		`INSERT INTO packs(owner_handle, pack_id, length, created_at) VALUES(?,?,?,?)
		 ON CONFLICT(owner_handle, pack_id) DO UPDATE SET created_at = excluded.created_at`,
		owner, packID, len(data), now,
	); err != nil {
		tx.Rollback()
		return 0, err
	}
	stored, err := insertObjects(tx, owner, packID, index)
	if err != nil {
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
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		group := ids[start:end]
		args := make([]any, 0, len(group)+1)
		args = append(args, owner)
		for _, id := range group {
			args = append(args, id)
		}
		rows, err := s.db.Query(
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
			out = append(out, api.ObjectLocation{ID: id, PackID: packID, Off: off, Len: length})
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
	err := s.db.QueryRow(
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
	err := s.db.QueryRow(
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
	// snapshot. snapshot_chunks is unioned in so a snapshot pinning a chunk in this
	// pack keeps the whole pack from being swept.
	rows, err := tx.Query(
		`SELECT pack_id, length FROM packs
		 WHERE owner_handle = ? AND created_at < ?
		   AND pack_id NOT IN (
		     SELECT o.pack_id FROM objects o
		     JOIN resource_chunks rc ON rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id
		     WHERE o.owner_handle = ?
		     UNION
		     SELECT o.pack_id FROM objects o
		     JOIN snapshot_chunks sc ON sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id
		     WHERE o.owner_handle = ?
		   )`,
		owner, cutoff, owner, owner,
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
	live      []liveObj // in ascending offset order
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
		oldBytes, err := os.ReadFile(s.packPath(owner, cand.packID))
		if err != nil {
			// A missing/unreadable pack file is left for a later pass rather than
			// failing the whole sweep; skip it.
			continue
		}
		newID, newPack, newIndex := buildLivePack(oldBytes, cand.live)
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
		movedBytes += cand.liveBytes
	}
	return repacked, reclaimed, nil
}

// repackCandidates returns the owner's compaction-worthy packs (see repackCand),
// reading every object once and grouping by pack. Objects come back ordered by pack
// and offset, so each candidate's live slice is already offset-sorted.
func (s *Store) repackCandidates(owner string, cutoff int64) ([]repackCand, error) {
	packLen := map[string]int64{}
	prows, err := s.db.Query(`SELECT pack_id, length FROM packs WHERE owner_handle = ? AND created_at < ?`, owner, cutoff)
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var id string
		var length int64
		if err := prows.Scan(&id, &length); err != nil {
			prows.Close()
			return nil, err
		}
		packLen[id] = length
	}
	if err := prows.Err(); err != nil {
		prows.Close()
		return nil, err
	}
	prows.Close()
	if len(packLen) == 0 {
		return nil, nil
	}

	cands := map[string]*repackCand{}
	deadSeen := map[string]bool{}
	var order []string
	// An object is live if a resource OR a snapshot roots it; a repack must copy every
	// live object forward, so snapshot_chunks is unioned into the liveness test.
	rows, err := s.db.Query(
		`SELECT o.pack_id, o.chunk_id, o."offset", o.length,
		        (EXISTS(SELECT 1 FROM resource_chunks rc
		                WHERE rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id)
		         OR EXISTS(SELECT 1 FROM snapshot_chunks sc
		                   WHERE sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id))
		 FROM objects o WHERE o.owner_handle = ?
		 ORDER BY o.pack_id, o."offset"`,
		owner,
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			pack, id    string
			off, length int64
			live        bool
		)
		if err := rows.Scan(&pack, &id, &off, &length, &live); err != nil {
			rows.Close()
			return nil, err
		}
		plen, ok := packLen[pack]
		if !ok {
			continue // a pack younger than the age guard, not a candidate
		}
		c := cands[pack]
		if c == nil {
			c = &repackCand{packID: pack, length: plen}
			cands[pack] = c
			order = append(order, pack)
		}
		if live {
			c.live = append(c.live, liveObj{id: id, off: off, length: length})
			c.liveBytes += length
		} else {
			deadSeen[pack] = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	var out []repackCand
	for _, pid := range order {
		c := cands[pid]
		switch {
		case !deadSeen[pid]: // nothing to reclaim
		case c.liveBytes == 0: // fully dead — GCPacks handles it
		case float64(c.liveBytes) > repackMaxLiveFraction*float64(c.length): // too full to bother
		default:
			out = append(out, *c)
		}
	}
	return out, nil
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
		 WHERE o.owner_handle = ? AND o.pack_id = ?
		   AND (EXISTS(SELECT 1 FROM resource_chunks rc
		              WHERE rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id)
		        OR EXISTS(SELECT 1 FROM snapshot_chunks sc
		                 WHERE sc.owner_handle = o.owner_handle AND sc.chunk_id = o.chunk_id))`,
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
	return base64.RawURLEncoding.EncodeToString(randomBytes(nBytes))
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
