// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

type Account struct {
	OwnerHandle string
	Email       string
	Kdf         crypto.KdfParams
	WrappedRoot crypto.SealedBlob
}

// CreateAccount registers an account with its Ed25519 public key, wrapped root key,
// and passphrase-verifier hash, and returns it. Returns ErrConflict if the email is
// already taken. The new account starts at auth epoch 1. encPublicKey/encKeySig are
// the published X25519 key and its identity self-signature; the handler requires and
// verifies them, and the empty case is stored NULL only for a keyless row a test or
// a pre-grants dir carries.
func (s *Store) CreateAccount(email string, kdf crypto.KdfParams, publicKey []byte, wrappedRoot crypto.SealedBlob, authVerifier, encPublicKey, encKeySig []byte) (Account, error) {
	email = api.NormalizeEmail(email)
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
	// The UNIQUE(email) index is binary, so a row written before emails were
	// normalized would not block a lower-cased twin of the same mailbox; check
	// case-insensitively first. Concurrent signups of the same normalized email
	// still serialize on the unique index below.
	var exists int
	if err := s.db.QueryRow(`SELECT 1 FROM accounts WHERE email = ? COLLATE NOCASE`, email).Scan(&exists); err == nil {
		return Account{}, ErrConflict
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Account{}, err
	}
	_, err = s.db.Exec(
		`INSERT INTO accounts(owner_handle, email, kdf, public_key, wrapped_root, auth_verifier, auth_epoch, enc_public_key, enc_key_sig, created_at)
		 VALUES(?,?,?,?,?,?,1,?,?,?)`,
		handle, email, string(kdfJSON), publicKey, string(rootJSON), vh[:], encPub, encSig, time.Now().Unix(),
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
	// COLLATE NOCASE serves rows written before emails were normalized; new rows
	// are stored lower-cased, and the unique index keeps twins from being created.
	err := s.rdb.QueryRow(
		`SELECT owner_handle, email, kdf, wrapped_root FROM accounts WHERE email = ? COLLATE NOCASE`, api.NormalizeEmail(email),
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
		`SELECT owner_handle, public_key, auth_verifier, auth_epoch FROM accounts WHERE email = ? COLLATE NOCASE`, api.NormalizeEmail(email),
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
	defer func() { _ = tx.Rollback() }()
	var (
		curEpoch    int
		curVerifier []byte
	)
	if err := tx.QueryRow(
		`SELECT auth_epoch, auth_verifier FROM accounts WHERE owner_handle = ?`, owner,
	).Scan(&curEpoch, &curVerifier); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	oldHash := sha256.Sum256(oldVerifier)
	if subtle.ConstantTimeCompare(oldHash[:], curVerifier) != 1 {
		return 0, ErrNotFound // wrong current passphrase
	}
	if expectedEpoch != curEpoch {
		return 0, ErrVersionConflict
	}
	newEpoch := curEpoch + 1
	newHash := sha256.Sum256(newVerifier)
	if _, err := tx.Exec(
		`UPDATE accounts SET kdf = ?, wrapped_root = ?, auth_verifier = ?, auth_epoch = ? WHERE owner_handle = ?`,
		string(kdfJSON), string(rootJSON), newHash[:], newEpoch, owner,
	); err != nil {
		return 0, err
	}
	// Keep the initiating device usable; every other device stays on the old epoch
	// and its token now fails the epoch check.
	if _, err := tx.Exec(
		`UPDATE devices SET auth_epoch = ? WHERE owner_handle = ? AND device_id = ?`,
		newEpoch, owner, deviceID,
	); err != nil {
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
	defer func() { _ = tx.Rollback() }()
	fail := func(e error) (string, int, error) { return "", 0, e }
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
		// The version bump is what makes rotation atomic against in-flight resource
		// writes: every write path (resource update, snapshot create) predicates its
		// commit on the version it read, so a request that authenticated before this
		// transaction but commits after it loses with ErrVersionConflict instead of
		// pinning a wrapped_key sealed under the root this rotation destroys.
		if _, err := tx.Exec(`UPDATE resources SET wrapped_key = ?, version = version + 1, updated_at = unixepoch() WHERE id = ? AND owner_handle = ?`, string(b), m.ID, owner); err != nil {
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
	email = api.NormalizeEmail(email)
	id = newID(16)
	nonce = randomBytes(32)
	now := time.Now()
	// Opportunistic sweep: challenges are deleted on consume, but an unconsumed one
	// would otherwise linger forever. Reaping expired rows on each issue keeps the
	// table bounded without a background job.
	_, _ = s.db.Exec(`DELETE FROM challenges WHERE expires_at < ?`, now.Unix())
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
		`SELECT nonce, expires_at FROM challenges WHERE id = ? AND email = ?`, id, api.NormalizeEmail(email),
	).Scan(&nonce, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_, _ = s.db.Exec(`DELETE FROM challenges WHERE id = ?`, id) // single-use, regardless of validity
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
	defer func() { _ = tx.Rollback() }()
	if maxDevices > 0 {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM devices WHERE owner_handle = ?`, ownerHandle).Scan(&count); err != nil {
			return "", "", err
		}
		if count >= maxDevices {
			return "", "", ErrDeviceLimit
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO devices(device_id, owner_handle, name, token_hash, auth_epoch) VALUES(?,?,?,?,?)`,
		deviceID, ownerHandle, name, h[:], epoch,
	); err != nil {
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

// addOwnerObjectCount adjusts the owner's object-row counter by delta (may be
// negative) inside the caller's transaction, mirroring addOwnerPackBytes: the
// counter moves atomically with the object rows it accounts for, and floors at
// zero as a backstop against drift.
func addOwnerObjectCount(tx *sql.Tx, owner string, delta int64) error {
	if delta == 0 {
		return nil
	}
	_, err := tx.Exec(
		`UPDATE accounts SET object_count = MAX(0, object_count + ?) WHERE owner_handle = ?`,
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

// accountUsageQuery returns raw per-table components; AccountUsage assembles
// StorageBytes in Go so no table is aggregated twice just for the arithmetic,
// and the object term reads accounts.object_count — maintained incrementally by
// every object-row write — instead of counting the owner's largest table on the
// hottest write path.
const accountUsageQuery = `SELECT
	a.owner_handle,
	a.pack_bytes,
	a.object_count,
	COALESCE((SELECT SUM(length(r.encrypted_meta) + COALESCE(length(r.wrapped_key), 0) + length(r.blob_nonce) + 256) FROM resources r WHERE r.owner_handle = a.owner_handle AND r.reclaimed = 0), 0),
	(SELECT COUNT(*) FROM resources r WHERE r.owner_handle = a.owner_handle AND r.reclaimed = 0),
	COALESCE((SELECT SUM(length(sn.encrypted_meta) + COALESCE(length(sn.encrypted_label), 0) + COALESCE(length(sn.wrapped_key), 0) + length(sn.blob_nonce) + 256) FROM snapshots sn WHERE sn.owner_handle = a.owner_handle), 0),
	(SELECT COUNT(*) FROM snapshots sn WHERE sn.owner_handle = a.owner_handle),
	COALESCE((SELECT SUM(length(g.wrapped_key) + 128) FROM grants g WHERE g.owner_handle = a.owner_handle), 0),
	(SELECT COUNT(*) FROM packs p WHERE p.owner_handle = a.owner_handle),
	(SELECT COUNT(*) FROM devices d WHERE d.owner_handle = a.owner_handle)
FROM accounts a WHERE a.owner_handle = ?`

// AccountUsage returns the storage summary for one account.
func (s *Store) AccountUsage(owner string) (AccountUsage, error) {
	var (
		u                                        AccountUsage
		resourceBytes, snapshotBytes, grantBytes int64
	)
	err := s.usageStmt.QueryRow(owner).Scan(
		&u.Owner, &u.StorageBytes, &u.Objects,
		&resourceBytes, &u.Resources, &snapshotBytes, &u.Snapshots, &grantBytes,
		&u.Packs, &u.Devices,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AccountUsage{}, ErrNotFound
	}
	if err != nil {
		return AccountUsage{}, err
	}
	u.StorageBytes += resourceBytes + snapshotBytes + grantBytes + 96*u.Objects + 64*u.Devices
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

// ResourceCreateKeyRecorded reports whether req's Idempotency-Key was already
// recorded for a create. A replay stores nothing new, so charging it against the
// quota would answer 507 for a resource that exists — defeating the retry the key
// exists for. The probe deliberately checks only key existence, not the payload
// digest: a recorded key with a different payload fails with ErrIdempotencyConflict
// inside PutResource and stores nothing either, so skipping the quota check is
// safe there too — and the probe stays a point query instead of hashing the
// complete request (blob included).
//
// The age bound is load-bearing: a true answer skips the quota check on the
// strength of createResource's own key lookup later refusing to store anything —
// but that lookup runs on the writer after this probe on the read pool, and a
// row the GC sweep deletes in between would let a create land unmetered. Only
// rows with at least an hour of TTL left count, so a row this probe accepts
// cannot be swept mid-request; an older row just falls back to the normal
// quota-checked path (where a genuine replay still replays).
func (s *Store) ResourceCreateKeyRecorded(owner string, req api.PutResourceRequest) bool {
	if req.IdempotencyKey == "" || req.ID != "" {
		return false
	}
	minCreatedAt := time.Now().Add(-(idempotencyTTL - time.Hour)).Unix()
	var one int
	err := s.rdb.QueryRow(`SELECT 1 FROM idempotency_keys WHERE owner_handle = ? AND kind = ? AND key = ? AND created_at >= ?`,
		owner, "resource.create", req.IdempotencyKey, minCreatedAt).Scan(&one)
	return err == nil
}

// ownerBlobBytes totals the resource and snapshot blob bytes an account holds.
// Every row records its own size — written on insert since migration 16, and
// backfilled at startup for rows older than it — so this is one aggregate query
// on a path (metrics, pack/resource puts, auto-snapshots) that runs constantly.
const ownerBlobBytesQuery = `SELECT COALESCE(SUM(blob_size), 0) FROM (
	SELECT blob_size FROM resources WHERE owner_handle = ? AND reclaimed = 0
	UNION ALL
	SELECT blob_size FROM snapshots WHERE owner_handle = ?
)`

func (s *Store) ownerBlobBytes(owner string) (int64, error) {
	var total int64
	err := s.blobBytesStmt.QueryRow(owner, owner).Scan(&total)
	return total, err
}

// backfillBlobSizes records a size for every row that predates migration 16, which
// added the column with a -1 ("not recorded") default. It runs once per data dir,
// at startup: after it, blob_size is authoritative and usage never has to stat a
// blob. A row whose file is missing (operator deletion, crash window) records 0
// rather than failing the boot — it holds no bytes.
func (s *Store) backfillBlobSizes() error {
	for _, t := range []struct{ table, idColumn string }{
		{"resources", "id"},
		{"snapshots", "snapshot_id"},
	} {
		// Collect first: the store runs a single writer connection, so the UPDATEs
		// cannot share it with an open cursor.
		type sized struct {
			id   string
			size int64
		}
		rows, err := s.db.Query(`SELECT ` + t.idColumn + `, blob_nonce FROM ` + t.table + ` WHERE blob_size < 0`)
		if err != nil {
			return err
		}
		var pending []sized
		for rows.Next() {
			var id string
			var nonce []byte
			if err := rows.Scan(&id, &nonce); err != nil {
				_ = rows.Close()
				return err
			}
			var size int64
			switch info, err := os.Stat(s.blobPath(id, nonce)); {
			case err == nil:
				size = info.Size()
			case errors.Is(err, os.ErrNotExist):
			default:
				_ = rows.Close()
				return err
			}
			pending = append(pending, sized{id: id, size: size})
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, row := range pending {
			if _, err := s.db.Exec(
				`UPDATE `+t.table+` SET blob_size = ? WHERE `+t.idColumn+` = ?`, row.size, row.id,
			); err != nil {
				return err
			}
		}
	}
	return nil
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
			_ = rows.Close()
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
// Suspension is checked separately from the memoized resolution: an operator
// suspends through `aqt-server admin`, a different process, so this server's token
// cache cannot be invalidated from there. See suspensionTTL.
func (s *Store) AuthByToken(token string) (owner, deviceID string, err error) {
	h := sha256.Sum256([]byte(token))
	owner, deviceID, ok := s.auth.get(h)
	if !ok {
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
	}
	disabled, err := s.accountSuspended(owner)
	if err != nil {
		// A cached resolution can outlive the account an operator just erased.
		// ErrNotFound maps to 401, which is the truth: the credential is gone.
		return "", "", err
	}
	if disabled {
		return "", "", ErrAccountDisabled
	}
	return owner, deviceID, nil
}

// accountSuspended answers from a short-lived cache so a sync's request burst does
// not pay a database round trip per request, while an operator's suspension still
// lands within suspensionTTL.
func (s *Store) accountSuspended(owner string) (bool, error) {
	if disabled, ok := s.suspended.get(owner); ok {
		return disabled, nil
	}
	disabled, err := s.AccountDisabled(owner)
	if err != nil {
		return false, err
	}
	s.suspended.put(owner, disabled)
	return disabled, nil
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
	defer func() { _ = rows.Close() }()

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
	defer func() { _ = rows.Close() }()
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

func idempotencyDigest(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

func lookupIdempotency(q queryer, owner, kind, key string, digest []byte, out any) (bool, error) {
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

// --- handlers ---

func (s *Server) handleCreateAccount(c *gin.Context) {
	var req api.CreateAccountRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Email == "" || len(req.PublicKey) != ed25519.PublicKeySize {
		abort(c, http.StatusBadRequest, "email and a valid public key are required")
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.AuthVerifier) == 0 {
		abort(c, http.StatusBadRequest, "wrapped root and auth verifier are required")
		return
	}
	// Invite mode gates every signup on a server-issued token, so an attacker cannot
	// register (and thereby squat) an unclaimed email. The response is uniform whether
	// the token is missing or wrong, so it leaks nothing about the token set.
	if s.cfg.Registration == RegistrationInvite && !s.cfg.inviteAccepted(req.InviteToken) {
		abortCode(c, http.StatusForbidden, "a valid invite token is required to register on this server", api.ErrCodeInviteRequired)
		return
	}
	// The enc key is what makes the account a grant target, so it is registered at
	// signup rather than backfilled later. Its identity self-signature must verify,
	// or a bad key would poison every future grant.
	if len(req.EncPublicKey) != crypto.EncPublicKeySize ||
		!crypto.VerifyEncKey(req.PublicKey, req.EncPublicKey, req.EncKeySig) {
		abort(c, http.StatusBadRequest, "enc public key must be 32 bytes and self-signed by the identity key")
		return
	}
	acc, err := s.store.CreateAccount(req.Email, req.Kdf, req.PublicKey, req.WrappedRoot, req.AuthVerifier, req.EncPublicKey, req.EncKeySig)
	if errors.Is(err, ErrConflict) {
		// The email is taken. Tell the caller so only if they prove they are its owner
		// by presenting the account's passphrase verifier; anyone else gets the decoy,
		// a success-shaped response whose token authenticates nothing. The existing
		// account is untouched either way — a duplicate signup creates no device on it.
		//
		// Note this does not make open registration unenumerable, and no server-side
		// response shape can: signing up for a free email must succeed, so "the token
		// worked" still means "the email was free". Registration=invite is the setting
		// that actually closes it. What the decoy buys is that a prober cannot confirm
		// a *specific* address without also taking it. See docs/threat-model.md.
		if s.signupProvesOwnership(req.Email, req.AuthVerifier) {
			abortCode(c, http.StatusConflict, "an account already exists for this email; use `aqt login` to attach this device", api.ErrCodeAccountExists)
			return
		}
		c.JSON(http.StatusCreated, s.decoyAuthResponse())
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "create account failed")
		return
	}
	deviceID, token, err := s.store.CreateDevice(acc.OwnerHandle, deviceName(req.DeviceName), 1, s.cfg.MaxDevices)
	if err != nil {
		abort(c, http.StatusInternalServerError, "create device failed")
		return
	}
	c.JSON(http.StatusCreated, api.AuthResponse{
		OwnerHandle: acc.OwnerHandle, DeviceID: deviceID, Token: token, Epoch: 1,
	})
}

// signupProvesOwnership reports whether a duplicate signup carried the existing
// account's own passphrase verifier. Only then is it safe to confirm the account
// exists: the caller already knows the secret that would let them log in, so the
// confirmation tells them nothing they could not learn from `aqt login`.
func (s *Server) signupProvesOwnership(email string, verifier []byte) bool {
	_, _, storedHash, _, err := s.store.AccountForAuth(email)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(verifier)
	return subtle.ConstantTimeCompare(sum[:], storedHash) == 1
}

// decoyAuthResponse builds a success-shaped auth response whose fields match a real
// one's lengths but authenticate nothing. It backs the enumeration-safe duplicate
// signup path: the handle/device/token are random, so the response is
// indistinguishable on the wire from a genuine account creation.
func (s *Server) decoyAuthResponse() api.AuthResponse {
	return api.AuthResponse{
		OwnerHandle: newID(12),
		DeviceID:    newID(10),
		Token:       newID(32),
		Epoch:       1,
	}
}

// handleAccountSalt is the new-device bootstrap: it returns the KDF params and wrapped
// root key for an email. An unknown email gets a deterministic decoy (200, not 404)
// so the endpoint does not reveal which emails have accounts; only someone who knows
// the passphrase can tell a decoy from a real account (the decoy never unwraps).
func (s *Server) handleAccountSalt(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		abort(c, http.StatusBadRequest, "email query param required")
		return
	}
	acc, err := s.store.AccountByEmail(email)
	if errors.Is(err, ErrNotFound) {
		decoy, derr := s.decoyBootstrap(email)
		if derr != nil {
			abort(c, http.StatusInternalServerError, "lookup failed")
			return
		}
		c.JSON(http.StatusOK, decoy)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	c.JSON(http.StatusOK, api.SaltResponse{Kdf: acc.Kdf, WrappedRoot: acc.WrappedRoot})
}

// decoyBootstrap synthesizes a bootstrap response for an unknown email,
// deterministically from the server secret so the same email always yields the same
// decoy. The salt and wrapped-root bytes are indistinguishable from a real account's
// to anyone without the passphrase, so a registered and an unregistered email look
// identical on the wire.
func (s *Server) decoyBootstrap(email string) (api.SaltResponse, error) {
	email = api.NormalizeEmail(email)
	secret, err := s.store.ServerSecret()
	if err != nil {
		return api.SaltResponse{}, err
	}
	stream := func(label string, n int) []byte { return s.decoyStream(secret, email, label, n) }
	// Derive the decoy's Argon2id costs from the same value set a real moderate
	// calibration produces, seeded deterministically per email. The package-default
	// (3, 64 MiB, 4) marked every decoy identically; drawing from the realistic
	// distribution instead means a decoy's params are indistinguishable from a
	// calibrated account's.
	timeCost, memoryKiB, threads := crypto.DecoyKdfCosts(stream("aqt-decoy-costs", 2))
	def, err := crypto.ManualKdfParams(timeCost, memoryKiB, threads)
	if err != nil {
		return api.SaltResponse{}, err
	}
	def.Salt = stream("aqt-decoy-salt", len(def.Salt))
	// A real wrapped root is a 32-byte key sealed with XChaCha20-Poly1305: a 24-byte
	// nonce and 48 bytes of ciphertext+tag. Match those lengths exactly.
	return api.SaltResponse{
		Kdf: def,
		WrappedRoot: crypto.SealedBlob{
			Nonce:      stream("aqt-decoy-nonce", crypto.NonceSize),
			Ciphertext: stream("aqt-decoy-ct", crypto.KeySize+16),
		},
	}, nil
}

func (s *Server) handleAuthChallenge(c *gin.Context) {
	var req api.ChallengeRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Email == "" {
		abort(c, http.StatusBadRequest, "email required")
		return
	}
	id, nonce, err := s.store.CreateChallenge(req.Email)
	if err != nil {
		abort(c, http.StatusInternalServerError, "challenge failed")
		return
	}
	c.JSON(http.StatusOK, api.ChallengeResponse{ChallengeID: id, Nonce: nonce})
}

func (s *Server) handleAttachDevice(c *gin.Context) {
	var req api.AttachDeviceRequest
	if !bindJSON(c, &req) {
		return
	}
	// Consume the challenge first so a bad attempt can't be replayed against it.
	nonce, err := s.store.ConsumeChallenge(req.ChallengeID, req.Email)
	if errors.Is(err, ErrNotFound) {
		abortCode(c, http.StatusUnauthorized, "invalid or expired challenge", api.ErrCodeInvalidChallenge)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "challenge lookup failed")
		return
	}
	owner, pub, verifierHash, epoch, err := s.store.AccountForAuth(req.Email)
	// Attaching needs both the signing key (proves the master key) and the passphrase
	// verifier (proves the current passphrase), so a stale passphrase or a cached
	// master key alone cannot attach. A missing account, a bad signature, and a bad
	// verifier all return the same 401: no oracle.
	sigOK := err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, nonce, req.Signature)
	verifierOK := err == nil && verifierMatches(req.AuthVerifier, verifierHash)
	if sigOK && verifierOK {
		deviceID, token, err := s.store.CreateDevice(owner, deviceName(req.DeviceName), epoch, s.cfg.MaxDevices)
		if errors.Is(err, ErrDeviceLimit) {
			u, _ := s.store.AccountUsage(owner)
			c.AbortWithStatusJSON(http.StatusForbidden, api.ErrorResponse{Error: "device limit reached; revoke a device before attaching another", Code: api.ErrCodeDeviceLimit, LimitKind: "devices", Current: u.Devices, Limit: int64(s.cfg.MaxDevices)})
			return
		}
		if err != nil {
			abort(c, http.StatusInternalServerError, "create device failed")
			return
		}
		c.JSON(http.StatusCreated, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Token: token, Epoch: epoch})
		return
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	abortCode(c, http.StatusUnauthorized, "invalid credentials", api.ErrCodeInvalidCredentials)
}

// verifierMatches reports whether the presented auth verifier hashes to the stored
// hash, in constant time.
func verifierMatches(verifier, storedHash []byte) bool {
	if len(verifier) == 0 || len(storedHash) != sha256.Size {
		return false
	}
	h := sha256.Sum256(verifier)
	return subtle.ConstantTimeCompare(h[:], storedHash) == 1
}

// handleChangePassphrase re-wraps the account's root key under a new passphrase. The store
// verifies the caller knows the current passphrase and bumps the account epoch, so
// every other device's token stops authenticating (they re-login with the new
// passphrase); the calling device keeps working.
func (s *Server) handleChangePassphrase(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	deviceID := c.GetString(deviceContextKey)
	var req api.PassphraseChangeRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.OldAuthVerifier) == 0 || len(req.NewAuthVerifier) == 0 {
		abort(c, http.StatusBadRequest, "wrapped root and both verifiers are required")
		return
	}
	newEpoch, err := s.store.ChangePassphrase(owner, deviceID, req.Kdf, req.WrappedRoot, req.OldAuthVerifier, req.NewAuthVerifier, req.ExpectedEpoch)
	if errors.Is(err, ErrNotFound) {
		abortCode(c, http.StatusForbidden, "current passphrase proof did not match", api.ErrCodeProofMismatch)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "the passphrase changed on another device; re-run with the current one", api.ErrCodeVersionConflict)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "passphrase change failed")
		return
	}
	// The calling device's token is unchanged (its epoch was advanced with the
	// account's), so no new token is issued; the client keeps using it.
	c.JSON(http.StatusOK, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Epoch: newEpoch})
}

// handleRotateRootKey performs the account-wide recovery operation: it mints a new account
// identity and re-wraps everything derived from the old one.
func (s *Server) handleRotateRootKey(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	deviceID := c.GetString(deviceContextKey)
	var req api.RootKeyRotationRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.WrappedRoot.Ciphertext) == 0 || len(req.OldAuthVerifier) == 0 || len(req.NewAuthVerifier) == 0 || len(req.PublicKey) != ed25519.PublicKeySize || len(req.EncPublicKey) != crypto.EncPublicKeySize || !crypto.VerifyEncKey(ed25519.PublicKey(req.PublicKey), req.EncPublicKey, req.EncKeySig) {
		abort(c, http.StatusBadRequest, "complete, self-consistent new account identity is required")
		return
	}
	token, epoch, err := s.store.RotateRootKey(owner, deviceID, req)
	if errors.Is(err, ErrNotFound) {
		abortCode(c, http.StatusForbidden, "current passphrase proof did not match", api.ErrCodeProofMismatch)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "account or a protected key changed while rotating; re-run root-key rotation", api.ErrCodeVersionConflict)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "root-key rotation failed")
		return
	}
	c.JSON(http.StatusOK, api.AuthResponse{OwnerHandle: owner, DeviceID: deviceID, Token: token, Epoch: epoch})
}

// handleDeleteAccount erases the calling account and everything stored under it. It
// requires the passphrase proof, not just a device token: a token is a credential
// the account holder may have lost control of, and this is the one operation no
// backup can undo. The server holds no plaintext, so there is nothing to hand back
// first — the client is expected to have pulled anything it wants to keep.
func (s *Server) handleDeleteAccount(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.DeleteAccountRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.AuthVerifier) == 0 {
		abort(c, http.StatusBadRequest, "passphrase proof is required")
		return
	}
	// Read the storage total before erasing it, so the receipt can quote the number
	// the caller confirmed against. DeletedAccount.Bytes counts only the blob and
	// pack files unlinked, which is a fraction of what `aqt usage` reports (that
	// total also models the account's database rows), so it is not a substitute: a
	// failed read omits the total rather than quietly swapping in a smaller one, and
	// never blocks the deletion.
	usage, usageErr := s.store.AccountUsage(owner)

	acct, err := s.store.DeleteAccountWithProof(owner, req.AuthVerifier)
	if errors.Is(err, ErrNotFound) {
		abortCode(c, http.StatusForbidden, "passphrase proof did not match", api.ErrCodeProofMismatch)
		return
	}
	// The middleware answered this from a cache an operator suspending in another
	// process cannot invalidate; the store re-read the row, so a hold that landed
	// inside that window still holds.
	if errors.Is(err, ErrAccountDisabled) {
		abortCode(c, http.StatusForbidden, ErrAccountDisabled.Error(), api.ErrCodeAccountDisabled)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "account deletion failed")
		return
	}
	var freed *int64
	if usageErr == nil {
		freed = &usage.StorageBytes
	}
	// The rows are gone, so the account is deleted whatever happened to the files.
	// The paths are operator detail and must not go back to a client, so they are
	// logged here; the caller is told only how many, which is enough to know their
	// ciphertext may still be on disk and to ask.
	for _, e := range acct.FileErrors {
		log.Printf("delete account %s: %s", owner, e)
	}
	c.JSON(http.StatusOK, api.DeleteAccountResponse{
		OwnerHandle: acct.OwnerHandle,
		Resources:   acct.Resources,
		Snapshots:   acct.Snapshots,
		Devices:     acct.Devices,
		Packs:       acct.Packs,
		Objects:     acct.Objects,
		Grants:      acct.Grants,
		Bytes:       freed,
		FileErrors:  len(acct.FileErrors),
	})
}

func (s *Server) handleAccountUsage(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	u, err := s.store.AccountUsage(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "usage lookup failed")
		return
	}
	// Report the cap that actually applies, so `aqt usage` on an account with an
	// operator-set override does not show the server-wide default it is exempt from.
	quota, err := s.effectiveQuota(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "usage lookup failed")
		return
	}
	c.JSON(http.StatusOK, api.UsageResponse{
		StorageBytes: u.StorageBytes,
		QuotaBytes:   quota,
		Packs:        u.Packs,
		Objects:      u.Objects,
		Resources:    u.Resources,
		Snapshots:    u.Snapshots,
		Devices:      u.Devices,
		MaxResources: int64(s.cfg.MaxResources), MaxSnapshots: int64(s.cfg.MaxSnapshots),
		MaxObjects: int64(s.cfg.MaxObjects), MaxDevices: int64(s.cfg.MaxDevices),
	})
}

func (s *Server) handleListDevices(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	devices, next, err := s.store.ListDevices(owner, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list devices failed")
		return
	}
	c.JSON(http.StatusOK, api.ListDevicesResponse{Devices: devices, NextCursor: next})
}

func (s *Server) handleDeleteDevice(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	err := s.store.DeleteDevice(owner, c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete device failed")
		return
	}
	c.Status(http.StatusNoContent)
}

func deviceName(name string) string {
	if name == "" {
		return "unnamed-device"
	}
	return name
}
