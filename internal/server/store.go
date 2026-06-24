package server

import (
	"crypto/rand"
	"crypto/sha256"
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

// Store persists accounts, devices, and resource metadata in SQLite, with the
// ciphertext blobs and packs on the filesystem. It holds no plaintext and no live
// keys.
type Store struct {
	db       *sql.DB
	blobsDir string
	packsDir string
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
	s := &Store{db: db, blobsDir: blobsDir, packsDir: packsDir}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
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
CREATE INDEX IF NOT EXISTS idx_resource_chunks_chunk ON resource_chunks(chunk_id);`
	if _, err := s.db.Exec(schema); err != nil {
		return err
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
}

// CreateAccount registers an account with its Ed25519 public key and returns it.
// Returns ErrConflict if the email is already taken.
func (s *Store) CreateAccount(email string, kdf crypto.KdfParams, publicKey []byte) (Account, error) {
	handle := newID(12)
	kdfJSON, err := json.Marshal(kdf)
	if err != nil {
		return Account{}, err
	}
	_, err = s.db.Exec(
		`INSERT INTO accounts(owner_handle, email, kdf, public_key) VALUES(?,?,?,?)`,
		handle, email, string(kdfJSON), publicKey,
	)
	if err != nil {
		if isUnique(err) {
			return Account{}, ErrConflict
		}
		return Account{}, err
	}
	return Account{OwnerHandle: handle, Email: email, Kdf: kdf}, nil
}

func (s *Store) AccountByEmail(email string) (Account, error) {
	var (
		acc     Account
		kdfJSON string
	)
	err := s.db.QueryRow(
		`SELECT owner_handle, email, kdf FROM accounts WHERE email = ?`, email,
	).Scan(&acc.OwnerHandle, &acc.Email, &kdfJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, err
	}
	if err := json.Unmarshal([]byte(kdfJSON), &acc.Kdf); err != nil {
		return Account{}, err
	}
	return acc, nil
}

// AccountForAuth returns the owner handle and Ed25519 public key for an email,
// or ErrNotFound. Used to verify a device-attach signature.
func (s *Store) AccountForAuth(email string) (ownerHandle string, publicKey []byte, err error) {
	err = s.db.QueryRow(
		`SELECT owner_handle, public_key FROM accounts WHERE email = ?`, email,
	).Scan(&ownerHandle, &publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	return ownerHandle, publicKey, nil
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

// CreateDevice issues a device token. It returns the plaintext token once; only
// its hash is stored.
func (s *Store) CreateDevice(ownerHandle, name string) (deviceID, token string, err error) {
	deviceID = newID(10)
	token = newID(32)
	h := sha256.Sum256([]byte(token))
	_, err = s.db.Exec(
		`INSERT INTO devices(device_id, owner_handle, name, token_hash) VALUES(?,?,?,?)`,
		deviceID, ownerHandle, name, h[:],
	)
	if err != nil {
		return "", "", err
	}
	return deviceID, token, nil
}

// OwnerByToken resolves a bearer token to its owning account handle.
func (s *Store) OwnerByToken(token string) (string, error) {
	h := sha256.Sum256([]byte(token))
	var owner string
	err := s.db.QueryRow(`SELECT owner_handle FROM devices WHERE token_hash = ?`, h[:]).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return owner, err
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
	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	_, err = tx.Exec(
		`INSERT INTO resources(id, owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version)
		 VALUES(?,?,?,?,?,?,?)`,
		id, owner, string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, version,
	)
	if err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := replaceResourceChunks(tx, id, owner, req.ChunkRefs); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := s.writeBlob(id, req.Blob.Nonce, req.Blob.Ciphertext); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		_ = os.Remove(s.blobPath(id, req.Blob.Nonce)) // row never committed; drop the now-orphan blob
		return "", 0, err
	}
	return id, version, nil
}

func (s *Store) updateResource(owner string, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
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
	// is rejected so a concurrent write is never lost. (The per-resource server
	// lock makes this check-then-update atomic; the WHERE version=? on the UPDATE
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
		`SELECT id, visibility, encrypted_meta, wrapped_key, version FROM resources WHERE owner_handle = ? ORDER BY id`, owner,
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
		if err := rows.Scan(&item.ID, &vis, &metaJSON, &wrappedJSON, &item.Version); err != nil {
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
	for _, id := range refs {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO resource_chunks(resource_id, owner_handle, chunk_id) VALUES(?,?,?)`,
			resourceID, owner, id,
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
	var missing, present []string
	for _, id := range ids {
		var one int
		err := s.db.QueryRow(
			`SELECT 1 FROM objects WHERE owner_handle = ? AND chunk_id = ?`, owner, id,
		).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, id)
			continue
		}
		if err != nil {
			return nil, err
		}
		present = append(present, id)
	}
	if err := s.touchPacksFor(owner, present); err != nil {
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
	stored := 0
	for _, e := range index {
		res, err := tx.Exec(
			`INSERT INTO objects(owner_handle, chunk_id, pack_id, "offset", length) VALUES(?,?,?,?,?)
			 ON CONFLICT(owner_handle, chunk_id) DO NOTHING`,
			owner, e.ID, packID, e.Off, e.Len,
		)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			stored++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
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
	for _, id := range ids {
		var (
			packID      string
			off, length int64
		)
		err := s.db.QueryRow(
			`SELECT pack_id, "offset", length FROM objects WHERE owner_handle = ? AND chunk_id = ?`, owner, id,
		).Scan(&packID, &off, &length)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, api.ObjectLocation{ID: id, PackID: packID, Off: off, Len: length})
		if !seenPack[packID] {
			seenPack[packID] = true
			packs = append(packs, packID)
		}
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
	rows, err := tx.Query(
		`SELECT pack_id, length FROM packs
		 WHERE owner_handle = ? AND created_at < ?
		   AND pack_id NOT IN (
		     SELECT DISTINCT o.pack_id FROM objects o
		     JOIN resource_chunks rc ON rc.owner_handle = o.owner_handle AND rc.chunk_id = o.chunk_id
		     WHERE o.owner_handle = ?
		   )`,
		owner, cutoff, owner,
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

func (s *Store) blobPath(id string, nonce []byte) string {
	return filepath.Join(s.blobsDir, id+"."+hex.EncodeToString(nonce)+".bin")
}

// writeBlob writes a blob to its nonce-addressed file and fsyncs it, so the bytes
// are durable before the referencing row commits.
func (s *Store) writeBlob(id string, nonce, ciphertext []byte) error {
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
	return f.Close()
}

// removeStaleBlobs deletes every blob file of id except the one for keepNonce
// (pass nil to drop them all). Best-effort: a leak here costs only disk, never
// correctness.
func (s *Store) removeStaleBlobs(id string, keepNonce []byte) {
	keep := s.blobPath(id, keepNonce)
	matches, _ := filepath.Glob(filepath.Join(s.blobsDir, id+".*.bin"))
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
	return nil
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
