package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
    auth_hash    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    device_id    TEXT PRIMARY KEY,
    owner_handle TEXT NOT NULL REFERENCES accounts(owner_handle),
    name         TEXT NOT NULL,
    token_hash   BLOB NOT NULL
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

// CreateAccount registers an account and returns it. The auth key is stored only
// as a hash. Returns ErrConflict if the email is already taken.
func (s *Store) CreateAccount(email string, kdf crypto.KdfParams, authKey []byte) (Account, error) {
	handle := newID(12)
	kdfJSON, err := json.Marshal(kdf)
	if err != nil {
		return Account{}, err
	}
	h := sha256.Sum256(authKey)
	_, err = s.db.Exec(
		`INSERT INTO accounts(owner_handle, email, kdf, auth_hash) VALUES(?,?,?,?)`,
		handle, email, string(kdfJSON), h[:],
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

// VerifyAuthKey reports whether authKey matches the account's stored hash, using
// a constant-time comparison.
func (s *Store) VerifyAuthKey(email string, authKey []byte) (Account, bool, error) {
	var (
		acc      Account
		kdfJSON  string
		authHash []byte
	)
	err := s.db.QueryRow(
		`SELECT owner_handle, email, kdf, auth_hash FROM accounts WHERE email = ?`, email,
	).Scan(&acc.OwnerHandle, &acc.Email, &kdfJSON, &authHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	if err := json.Unmarshal([]byte(kdfJSON), &acc.Kdf); err != nil {
		return Account{}, false, err
	}
	want := sha256.Sum256(authKey)
	ok := subtle.ConstantTimeCompare(want[:], authHash) == 1
	return acc, ok, nil
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

// PutResource stores a new resource for owner: ciphertext to the blob store, the
// rest to SQLite. It only ever creates — each call mints a fresh id, version is
// always 1, and re-pushing an edited file orphans the previous blob. In-place
// update and versioning are not built yet (DESIGN.md section 5).
func (s *Store) PutResource(owner string, req api.PutResourceRequest) (id string, version int, err error) {
	id = newID(8)
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
	if err := s.writeBlob(id, req.Blob.Ciphertext); err != nil {
		return "", 0, err
	}
	version = 1
	_, err = s.db.Exec(
		`INSERT INTO resources(id, owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version)
		 VALUES(?,?,?,?,?,?,?)`,
		id, owner, string(req.Visibility), string(metaJSON), wrappedJSON, req.Blob.Nonce, version,
	)
	if err != nil {
		return "", 0, err
	}
	return id, version, nil
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
	if wrappedJSON.Valid {
		var wk crypto.WrappedKey
		if err := json.Unmarshal([]byte(wrappedJSON.String), &wk); err != nil {
			return out, err
		}
		out.WrappedKey = &wk
	}
	return out, nil
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
	return os.Remove(s.blobPath(id))
}

// --- blob store ---

func (s *Store) blobPath(id string) string { return filepath.Join(s.blobsDir, id+".bin") }

func (s *Store) writeBlob(id string, ciphertext []byte) error {
	return os.WriteFile(s.blobPath(id), ciphertext, 0o600)
}

func (s *Store) readBlob(id string) ([]byte, error) {
	b, err := os.ReadFile(s.blobPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// newID returns a URL-safe random identifier of roughly n characters.
func newID(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func isUnique(err error) bool {
	// modernc.org/sqlite surfaces constraint violations in the error string;
	// matching on it avoids depending on the driver's internal error type.
	return err != nil && strings.Contains(err.Error(), "constraint failed")
}
