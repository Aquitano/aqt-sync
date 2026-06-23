package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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
// ciphertext blobs on the filesystem. It holds no plaintext and no live keys.
type Store struct {
	db        *sql.DB
	blobsDir  string
	chunksDir string
}

func OpenStore(dataDir string) (*Store, error) {
	blobsDir := filepath.Join(dataDir, "blobs")
	chunksDir := filepath.Join(dataDir, "chunks")
	for _, d := range []string{blobsDir, chunksDir} {
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
	s := &Store{db: db, blobsDir: blobsDir, chunksDir: chunksDir}
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
CREATE TABLE IF NOT EXISTS chunks (
    owner_handle TEXT NOT NULL,
    chunk_id     TEXT NOT NULL,
    length       INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY(owner_handle, chunk_id)
);
-- Which chunks a resource's current manifest references; the GC roots. Replaced
-- in full on every resource write, so it always reflects the live manifest. The
-- FK to chunks (with foreign_keys on) is the backstop for the GC/dedup race: a
-- manifest that references a chunk the owner no longer stores is rejected at PUT
-- rather than committing a dangling reference that a later clone/pull can't read.
CREATE TABLE IF NOT EXISTS resource_chunks (
    resource_id  TEXT NOT NULL,
    owner_handle TEXT NOT NULL,
    chunk_id     TEXT NOT NULL,
    PRIMARY KEY(resource_id, chunk_id),
    FOREIGN KEY(owner_handle, chunk_id) REFERENCES chunks(owner_handle, chunk_id)
);
CREATE INDEX IF NOT EXISTS idx_resource_chunks_chunk ON resource_chunks(chunk_id);`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	return s.checkSchema()
}

// checkSchema guards against a data dir created by an older build whose
// resource_chunks predates the owner_handle column + FK. CREATE TABLE IF NOT
// EXISTS silently no-ops over such a table, after which every chunked write fails
// the INSERT with an opaque error and the FK backstop is absent. There is no
// versioned migration yet (this feature is pre-release), so fail loudly with a
// recoverable instruction instead of limping along corrupt.
func (s *Store) checkSchema() error {
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
		`SELECT id, visibility, encrypted_meta, version FROM resources WHERE owner_handle = ? ORDER BY id`, owner,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []api.ResourceListItem
	for rows.Next() {
		var (
			item     api.ResourceListItem
			vis      string
			metaJSON string
		)
		if err := rows.Scan(&item.ID, &vis, &metaJSON, &item.Version); err != nil {
			return nil, err
		}
		item.Visibility = api.Visibility(vis)
		if err := json.Unmarshal([]byte(metaJSON), &item.EncryptedMeta); err != nil {
			return nil, err
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

// --- chunk store ---
//
// Chunks are opaque, content-addressed (id = hex sha256 of the ciphertext), and
// scoped to one owner. The server verifies the address on upload and otherwise
// never inspects them.

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

// MissingChunks returns the subset of ids the owner does not already store, and
// re-arms the GC age guard on the ids it does (the dedup-hit set).
//
// A chunk present here is one the caller will reference in its imminent manifest
// PUT but will not re-upload. Without the touch, a concurrent GC could reap an
// old, momentarily-unreferenced chunk in the window between this check and that
// PUT, leaving the committed manifest pointing at a deleted blob. Bumping
// created_at keeps such a chunk past the age guard until the PUT roots it.
func (s *Store) MissingChunks(owner string, ids []string) ([]string, error) {
	var missing, present []string
	for _, id := range ids {
		var one int
		err := s.db.QueryRow(
			`SELECT 1 FROM chunks WHERE owner_handle = ? AND chunk_id = ?`, owner, id,
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
	if err := s.touchChunks(owner, present); err != nil {
		return nil, err
	}
	return missing, nil
}

// touchChunks resets created_at to now for the owner's given chunks, re-arming
// the GC age guard so a sync that is about to reference them has time to commit.
func (s *Store) touchChunks(owner string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, 0, len(ids)+2)
	args = append(args, time.Now().Unix())
	for _, id := range ids {
		args = append(args, id)
	}
	args = append(args, owner)
	_, err := s.db.Exec(
		`UPDATE chunks SET created_at = ? WHERE chunk_id IN (`+placeholders(len(ids))+`) AND owner_handle = ?`,
		args...,
	)
	return err
}

// placeholders returns "?,?,..." with n entries for an IN clause.
func placeholders(n int) string {
	return strings.TrimPrefix(strings.Repeat(",?", n), ",")
}

// PutChunks stores chunks for the owner, verifying that each id is the hex sha256
// of its data. Storage is idempotent: re-uploading a present chunk bumps its
// created_at, re-arming the GC age guard for a sync about to reference it.
func (s *Store) PutChunks(owner string, chunks []api.ChunkData) (int, error) {
	now := time.Now().Unix()
	stored := 0
	for _, ch := range chunks {
		sum := sha256.Sum256(ch.Data)
		if hex.EncodeToString(sum[:]) != ch.ID {
			return stored, fmt.Errorf("chunk %s: data does not match its id", ch.ID)
		}
		if err := s.writeChunk(owner, ch.ID, ch.Data); err != nil {
			return stored, err
		}
		if _, err := s.db.Exec(
			`INSERT INTO chunks(owner_handle, chunk_id, length, created_at) VALUES(?,?,?,?)
			 ON CONFLICT(owner_handle, chunk_id) DO UPDATE SET created_at = excluded.created_at`,
			owner, ch.ID, len(ch.Data), now,
		); err != nil {
			return stored, err
		}
		stored++
	}
	return stored, nil
}

// GetChunks returns the owner's chunks for the given ids. Ids the owner does not
// have are silently skipped (the caller treats a short result as missing data).
func (s *Store) GetChunks(owner string, ids []string) ([]api.ChunkData, error) {
	out := make([]api.ChunkData, 0, len(ids))
	for _, id := range ids {
		var one int
		err := s.db.QueryRow(
			`SELECT 1 FROM chunks WHERE owner_handle = ? AND chunk_id = ?`, owner, id,
		).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(s.chunkPath(owner, id))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, api.ChunkData{ID: id, Data: data})
	}
	return out, nil
}

// GCChunks deletes the owner's chunks that no live resource references and that
// were uploaded longer ago than minAge. The age guard keeps an in-flight push's
// freshly uploaded chunks from being reaped before its manifest commits.
func (s *Store) GCChunks(owner string, minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge).Unix()
	rows, err := s.db.Query(
		`SELECT chunk_id FROM chunks
		 WHERE owner_handle = ? AND created_at < ?
		   AND chunk_id NOT IN (
		     SELECT resource_chunks.chunk_id FROM resource_chunks WHERE resource_chunks.owner_handle = ?
		   )`,
		owner, cutoff, owner,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var dead []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		dead = append(dead, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	deleted := 0
	for _, id := range dead {
		if _, err := s.db.Exec(`DELETE FROM chunks WHERE owner_handle = ? AND chunk_id = ?`, owner, id); err != nil {
			return deleted, err
		}
		if err := os.Remove(s.chunkPath(owner, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
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

// chunkPath fans out content-addressed chunks by their id prefix to keep any one
// directory small: chunks/<owner>/<ab>/<cd>/<id>.bin. The id is hex, so the path
// is safe on case-insensitive filesystems.
func (s *Store) chunkPath(owner, id string) string {
	return filepath.Join(s.chunksDir, owner, id[0:2], id[2:4], id+".bin")
}

func (s *Store) writeChunk(owner, id string, data []byte) error {
	path := s.chunkPath(owner, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
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
