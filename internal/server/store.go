package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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

// Store persists accounts, devices, and resource metadata in SQLite, with the
// ciphertext blobs on the filesystem. It holds no plaintext and no live keys.
type Store struct {
	db       *sql.DB
	blobsDir string
}

func OpenStore(dataDir string) (*Store, error) {
	blobsDir := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(blobsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "aqt.db"))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	s := &Store{db: db, blobsDir: blobsDir}
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
);`
	_, err := s.db.Exec(schema)
	return err
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
	expiresAt := time.Now().Add(challengeTTL).Unix()
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
	if err := s.writeBlob(id, req.Blob.Ciphertext); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		_ = os.Remove(s.blobPath(id)) // row never committed; drop the now-orphan blob
		return "", 0, err
	}
	return id, version, nil
}

func (s *Store) updateResource(owner string, req api.PutResourceRequest, metaJSON string, wrappedJSON sql.NullString) (string, int, error) {
	var version int
	err := s.db.QueryRow(
		`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, req.ID, owner,
	).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	version++

	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	_, err = tx.Exec(
		`UPDATE resources SET visibility=?, encrypted_meta=?, wrapped_key=?, blob_nonce=?, version=?
		 WHERE id=? AND owner_handle=?`,
		string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, version, req.ID, owner,
	)
	if err != nil {
		tx.Rollback()
		return "", 0, err
	}
	// Atomic blob replace: on failure the temp file is discarded and the old
	// blob stays, so rolling back the row leaves a consistent resource.
	if err := s.writeBlob(req.ID, req.Blob.Ciphertext); err != nil {
		tx.Rollback()
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
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

	ciphertext, err := s.readBlob(id)
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
	if err := os.Remove(s.blobPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// --- blob store ---

func (s *Store) blobPath(id string) string { return filepath.Join(s.blobsDir, id+".bin") }

// writeBlob writes ciphertext via a temp file then rename, so a replace either
// fully swaps in the new content or leaves the old blob untouched.
func (s *Store) writeBlob(id string, ciphertext []byte) error {
	final := s.blobPath(id)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		// Windows MoveFile fails when the destination exists; replace it. The
		// brief non-atomic window is acceptable for v1.
		_ = os.Remove(final)
		if err := os.Rename(tmp, final); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

func (s *Store) readBlob(id string) ([]byte, error) {
	b, err := os.ReadFile(s.blobPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
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
