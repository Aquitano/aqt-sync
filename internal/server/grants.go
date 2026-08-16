// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/hkdf"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// Account-to-account grants. A grant row is one resource's content key
// HPKE-wrapped to one grantee, sealed entirely client-side; the server
// stores and serves it opaquely, so zero-knowledge is unchanged. Grants confer
// READ access only: the read paths below accept a grantee where they would
// accept the owner, while every mutation keeps its owner-scoped predicate.

// maxGrantsPerResource bounds the grant rows one resource can accumulate; far
// above any real sharing fan-out, it only stops a runaway client from growing
// the table unboundedly.
const maxGrantsPerResource = 256

// maxGrantWrapSize bounds a stored wrap. An HPKE X25519+ChaCha20-Poly1305 wrap
// of a 32-byte key is 80 bytes; the cap leaves format headroom while keeping the
// column from becoming a blob dump.
const maxGrantWrapSize = 1024

// maxShareBlocks bounds one account's block list. Blocking needs an incoming
// grant to remove, so the list cannot grow faster than other accounts grant to
// this one; the cap only keeps a pathological case from becoming a table dump.
const maxShareBlocks = 1024

// ErrGrantLimit is returned when a resource already carries maxGrantsPerResource
// grants. Handlers map it to 400.
var ErrGrantLimit = errors.New("grant limit reached for this resource")

// ErrSenderBlocked is returned when the grantee has blocked incoming grants from
// the granting account. Handlers map it to 403.
var ErrSenderBlocked = errors.New("the recipient is not accepting shares from this account")

// ErrBlockLimit is returned when an account's block list is full. Handlers map it
// to 400.
var ErrBlockLimit = errors.New("block list is full")

// --- store ---

// SetEncKey stores (or replaces) the account's published X25519 key and its
// identity self-signature. The handler verifies the signature first.
func (s *Store) SetEncKey(owner string, encPub, sig []byte) error {
	res, err := s.db.Exec(
		`UPDATE accounts SET enc_public_key = ?, enc_key_sig = ? WHERE owner_handle = ?`,
		encPub, sig, owner,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AccountPublicKey returns the account's Ed25519 identity public key.
func (s *Store) AccountPublicKey(owner string) ([]byte, error) {
	var pub []byte
	err := s.rdb.QueryRow(`SELECT public_key FROM accounts WHERE owner_handle = ?`, owner).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return pub, err
}

// AccountKeysByEmail returns the grant-target lookup fields for an email:
// ErrNotFound both for an unknown email and for an account that has not
// published an enc key yet, so the handler's decoy covers the two cases
// identically (distinguishing them would be the oracle).
func (s *Store) AccountKeysByEmail(email string) (api.AccountKeysResponse, error) {
	var (
		out    api.AccountKeysResponse
		encPub []byte
		encSig []byte
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, public_key, enc_public_key, enc_key_sig FROM accounts WHERE email = ? COLLATE NOCASE`, email,
	).Scan(&out.Handle, &out.PublicKey, &encPub, &encSig)
	if errors.Is(err, sql.ErrNoRows) {
		return api.AccountKeysResponse{}, ErrNotFound
	}
	if err != nil {
		return api.AccountKeysResponse{}, err
	}
	if len(encPub) == 0 {
		return api.AccountKeysResponse{}, ErrNotFound
	}
	out.EncPublicKey, out.EncKeySig = encPub, encSig
	return out, nil
}

// PutGrant stores (or replaces) a grant on a resource the caller owns. The
// grantee handle is not validated against accounts: a wrap to a decoy handle
// (unknown-email lookup) must be accepted indistinguishably from a real one.
//
// resources.version deliberately covers the grant set, not just content: the
// bump here is what makes ExpectedVersion a CAS over grant mutations. The cost
// is that a content writer's If-Match can 409 on a concurrent grant change; its
// refetch-and-retry resolves that like any other conflict.
func (s *Store) PutGrant(owner, resourceID, grantee string, wrapped []byte, expectedVersions ...int) error {
	defer s.resLocks.lock(resourceID)()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resOwner string
	var version, compactAt int
	if err := tx.QueryRow(`SELECT owner_handle, version, compact_at FROM resources WHERE id = ?`, resourceID).Scan(&resOwner, &version, &compactAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if resOwner != owner {
		return ErrNotFound
	}
	if compactAt > 0 {
		return ErrGitRemotePolicy
	}
	if len(expectedVersions) > 0 && expectedVersions[0] > 0 && expectedVersions[0] != version {
		return ErrVersionConflict
	}
	var blocked int
	if err := tx.QueryRow(
		`SELECT count(*) FROM share_blocks WHERE grantee_handle = ? AND owner_handle = ?`, grantee, owner,
	).Scan(&blocked); err != nil {
		return err
	}
	if blocked > 0 {
		return ErrSenderBlocked
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM grants WHERE resource_id = ?`, resourceID).Scan(&count); err != nil {
		return err
	}
	if count >= maxGrantsPerResource {
		// A replace of an existing grantee still fits; only net-new rows hit the cap.
		var exists int
		if err := tx.QueryRow(
			`SELECT count(*) FROM grants WHERE resource_id = ? AND grantee_handle = ?`, resourceID, grantee,
		).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrGrantLimit
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO grants(resource_id, owner_handle, grantee_handle, wrapped_key, created_at)
		 VALUES(?,?,?,?,?)
		 ON CONFLICT(resource_id, grantee_handle) DO UPDATE SET wrapped_key = excluded.wrapped_key`,
		resourceID, owner, grantee, wrapped, time.Now().Unix(),
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE resources SET version = version + 1, updated_at = unixepoch() WHERE id = ? AND version = ?`, resourceID, version); err != nil {
		return err
	}
	return tx.Commit()
}

// ListResourceGrants returns one page of a resource's grants for its owner, ordered
// by (created_at, grantee_handle), plus the cursor for the next page.
func (s *Store) ListResourceGrants(owner, resourceID string, page pageParams) ([]api.GrantEntry, string, error) {
	var resOwner string
	err := s.rdb.QueryRow(`SELECT owner_handle FROM resources WHERE id = ?`, resourceID).Scan(&resOwner)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && resOwner != owner) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	limit := page.effectiveLimit()
	where := "resource_id = ?"
	args := []any{resourceID}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 2)
		if err != nil {
			return nil, "", err
		}
		createdAt, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, "", errBadCursor
		}
		where += " AND (created_at > ? OR (created_at = ? AND grantee_handle > ?))"
		args = append(args, createdAt, createdAt, parts[1])
	}
	args = append(args, limit+1)
	rows, err := s.rdb.Query(
		`SELECT grantee_handle, created_at FROM grants WHERE `+where+` ORDER BY created_at, grantee_handle LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []api.GrantEntry
	for rows.Next() {
		var g api.GrantEntry
		if err := rows.Scan(&g.GranteeHandle, &g.CreatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(strconv.FormatInt(last.CreatedAt, 10), last.GranteeHandle)
	}
	return out, next, nil
}

// DeleteGrant removes one grant from a resource the caller owns. ErrNotFound
// covers a missing resource, foreign ownership, and a missing grant alike.
// Bumps resources.version for the same reason PutGrant does.
func (s *Store) DeleteGrant(owner, resourceID, grantee string, expectedVersions ...int) error {
	defer s.resLocks.lock(resourceID)()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow(`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, resourceID, owner).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if len(expectedVersions) > 0 && expectedVersions[0] > 0 && expectedVersions[0] != version {
		return ErrVersionConflict
	}
	res, err := tx.Exec(
		`DELETE FROM grants WHERE resource_id = ? AND owner_handle = ? AND grantee_handle = ?`,
		resourceID, owner, grantee,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE resources SET version = version + 1, updated_at = unixepoch() WHERE id = ? AND version = ?`, resourceID, version); err != nil {
		return err
	}
	return tx.Commit()
}

// ListShares lists the caller's incoming grants: one row per live resource
// granted to them, with the sealed metadata so the client can show names after
// unwrapping. Reclaimed tombstones are skipped (their ciphertext is gone).
func (s *Store) ListShares(grantee string, page pageParams) ([]api.ShareItem, string, error) {
	limit := page.effectiveLimit()
	where := "g.grantee_handle = ? AND r.reclaimed = 0"
	args := []any{grantee}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 2)
		if err != nil {
			return nil, "", err
		}
		createdAt, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, "", errBadCursor
		}
		where += " AND (g.created_at > ? OR (g.created_at = ? AND g.resource_id > ?))"
		args = append(args, createdAt, createdAt, parts[1])
	}
	args = append(args, limit+1)
	rows, err := s.rdb.Query(
		`SELECT g.resource_id, g.owner_handle, g.wrapped_key, g.created_at, r.encrypted_meta
		 FROM grants g JOIN resources r ON r.id = g.resource_id
		 WHERE `+where+`
		 ORDER BY g.created_at, g.resource_id LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []api.ShareItem
	for rows.Next() {
		var (
			item     api.ShareItem
			metaJSON string
		)
		if err := rows.Scan(&item.ResourceID, &item.OwnerHandle, &item.WrappedKey, &item.CreatedAt, &metaJSON); err != nil {
			return nil, "", err
		}
		if err := json.Unmarshal([]byte(metaJSON), &item.EncryptedMeta); err != nil {
			return nil, "", err
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(strconv.FormatInt(last.CreatedAt, 10), last.ResourceID)
	}
	return out, next, nil
}

// DeleteShare drops one incoming grant on the caller's own behalf: the predicate is
// grantee_handle, so it can only ever remove the caller's own row. block additionally
// refuses that grantor's future grants — which is what makes the removal stick, since
// they could otherwise re-add the row a second later — and clears their other shares
// to this account in the same transaction; refusing new grants while leaving old ones
// listed is a half-measure the recipient did not ask for. Returns the grantor's handle
// and how many rows went.
//
// Deliberately does NOT bump resources.version, unlike the owner-side grant writes it
// mirrors. Version is the owner's CAS token; letting a grantee move it would hand any
// account that was ever granted anything a way to 409 the owner's writes at will.
func (s *Store) DeleteShare(grantee, resourceID string, block bool) (string, int, error) {
	// The lock is resource-scoped while the block path's DELETE spans every resource
	// of that owner, so it is not what keeps a concurrent PutGrant on a sibling
	// resource from landing after the block: the single write connection is (see
	// Store.db). This lock only orders this removal against the other mutations of
	// the resource it names.
	defer s.resLocks.lock(resourceID)()
	tx, err := s.db.Begin()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	var owner string
	err = tx.QueryRow(
		`SELECT owner_handle FROM grants WHERE resource_id = ? AND grantee_handle = ?`, resourceID, grantee,
	).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	stmt, args := `DELETE FROM grants WHERE resource_id = ? AND grantee_handle = ?`, []any{resourceID, grantee}
	if block {
		if err := insertShareBlock(tx, grantee, owner); err != nil {
			return "", 0, err
		}
		stmt, args = `DELETE FROM grants WHERE owner_handle = ? AND grantee_handle = ?`, []any{owner, grantee}
	}
	res, err := tx.Exec(stmt, args...)
	if err != nil {
		return "", 0, err
	}
	removed, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return owner, int(removed), nil
}

// insertShareBlock records a (grantee, grantor) block, enforcing the per-account cap.
// Re-blocking an already-blocked grantor keeps the original timestamp.
func insertShareBlock(tx *sql.Tx, grantee, owner string) error {
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM share_blocks WHERE grantee_handle = ?`, grantee).Scan(&count); err != nil {
		return err
	}
	if count >= maxShareBlocks {
		var exists int
		if err := tx.QueryRow(
			`SELECT count(*) FROM share_blocks WHERE grantee_handle = ? AND owner_handle = ?`, grantee, owner,
		).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrBlockLimit
		}
	}
	_, err := tx.Exec(
		`INSERT INTO share_blocks(grantee_handle, owner_handle, created_at) VALUES(?,?,?)
		 ON CONFLICT(grantee_handle, owner_handle) DO NOTHING`,
		grantee, owner, time.Now().Unix(),
	)
	return err
}

// ListShareBlocks returns one page of the caller's blocked grantors, ordered by
// (created_at, owner_handle), plus the cursor for the next page.
func (s *Store) ListShareBlocks(grantee string, page pageParams) ([]api.ShareBlock, string, error) {
	limit := page.effectiveLimit()
	where := "grantee_handle = ?"
	args := []any{grantee}
	if page.cursor != "" {
		parts, err := decodeCursor(page.cursor, 2)
		if err != nil {
			return nil, "", err
		}
		createdAt, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, "", errBadCursor
		}
		where += " AND (created_at > ? OR (created_at = ? AND owner_handle > ?))"
		args = append(args, createdAt, createdAt, parts[1])
	}
	args = append(args, limit+1)
	rows, err := s.rdb.Query(
		`SELECT owner_handle, created_at FROM share_blocks WHERE `+where+`
		 ORDER BY created_at, owner_handle LIMIT ?`, args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []api.ShareBlock
	for rows.Next() {
		var b api.ShareBlock
		if err := rows.Scan(&b.OwnerHandle, &b.CreatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(strconv.FormatInt(last.CreatedAt, 10), last.OwnerHandle)
	}
	return out, next, nil
}

// DeleteShareBlock lifts one block, so that account can share with the caller again.
func (s *Store) DeleteShareBlock(grantee, owner string) error {
	res, err := s.db.Exec(
		`DELETE FROM share_blocks WHERE grantee_handle = ? AND owner_handle = ?`, grantee, owner,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// grantWrappedKey returns the wrap for (resource, grantee), if one exists.
func (s *Store) grantWrappedKey(resourceID, grantee string) ([]byte, bool, error) {
	var wrapped []byte
	err := s.rdb.QueryRow(
		`SELECT wrapped_key FROM grants WHERE resource_id = ? AND grantee_handle = ?`,
		resourceID, grantee,
	).Scan(&wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return wrapped, true, nil
}

// ResourceObjectSlices is the grant-read counterpart of PublicObjectSlices: exact
// per-object slices for the resource's referenced set, served to its owner or a
// grantee. A grantee must never get raw pack ranges — packs interleave the owner's
// other resources — so this shares the membership-checked slice resolution with the
// public endpoint. Link lifecycle (expiry/max-reads) does not gate it: a grant is a
// per-account credential, not a link; only a reclaimed tombstone is ErrGone.
func (s *Store) ResourceObjectSlices(resourceID, caller string, ids []string) (string, []api.ObjectLocation, error) {
	var (
		owner     string
		reclaimed bool
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, reclaimed FROM resources WHERE id = ?`, resourceID,
	).Scan(&owner, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	if caller != owner {
		_, ok, err := s.grantWrappedKey(resourceID, caller)
		if err != nil {
			return "", nil, err
		}
		if !ok {
			return "", nil, ErrNotFound
		}
	}
	if reclaimed {
		return "", nil, ErrGone
	}
	out, err := s.orderedObjectSlices(owner, resourceID, ids)
	if err != nil {
		return "", nil, err
	}
	return owner, out, nil
}

// --- handlers ---

// accountKeys is the grant-target lookup (GET /v1/account/keys?email=...). Like
// the bootstrap endpoint, an unknown email — or an account that has not published
// an enc key — gets a deterministic decoy (200, not 404): a real keypair derived
// from the server secret, self-signed like a genuine one, so the response is
// indistinguishable on the wire and a grant wrapped to it simply never decrypts.
func (s *Server) accountKeys(c *gin.Context) {
	// Normalize before both the real lookup and the decoy derivation: if only
	// the lookup folded case, "X@a.com" and "x@a.com" would agree for real
	// accounts but produce two different decoys — a case-probe oracle.
	email := api.NormalizeEmail(c.Query("email"))
	if email == "" {
		abort(c, http.StatusBadRequest, "email query param required")
		return
	}
	keys, err := s.store.AccountKeysByEmail(email)
	if errors.Is(err, ErrNotFound) {
		decoy, derr := s.decoyAccountKeys(email)
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
	c.JSON(http.StatusOK, keys)
}

// decoyAccountKeys synthesizes a valid, deterministic keyset for an unknown email:
// both keypairs are derived from the server secret (so repeated lookups agree) and
// the enc key is genuinely self-signed, exactly as a real account's would be.
func (s *Server) decoyAccountKeys(email string) (api.AccountKeysResponse, error) {
	secret, err := s.store.ServerSecret()
	if err != nil {
		return api.AccountKeysResponse{}, err
	}
	stream := func(label string, n int) []byte {
		out := make([]byte, n)
		r := hkdf.New(sha256.New, secret, []byte(email), []byte(label))
		if _, err := io.ReadFull(r, out); err != nil {
			panic("hkdf decoy: " + err.Error()) // unreachable for an in-memory reader
		}
		return out
	}
	identity := ed25519.NewKeyFromSeed(stream("aqt-decoy-ed25519", ed25519.SeedSize))
	encPub := crypto.DeriveEncKeyFromSeed(stream("aqt-decoy-x25519", 32)).Public()
	return api.AccountKeysResponse{
		Handle:       newIDFrom(stream("aqt-decoy-handle", 12)),
		PublicKey:    identity.Public().(ed25519.PublicKey),
		EncPublicKey: encPub,
		EncKeySig:    crypto.SignEncKey(identity, encPub),
	}, nil
}

// publishEncKey backfills the caller's X25519 key (PUT /v1/account/enc-key). The
// self-signature is verified against the account's registered Ed25519 key, so a
// stolen token alone cannot repoint future grants at an attacker key without also
// holding the master key that signs the binding.
func (s *Server) publishEncKey(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.PublishEncKeyRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.EncPublicKey) != crypto.EncPublicKeySize {
		abort(c, http.StatusBadRequest, "enc public key must be 32 bytes")
		return
	}
	identityPub, err := s.store.AccountPublicKey(owner)
	if err != nil {
		abort(c, http.StatusInternalServerError, "lookup failed")
		return
	}
	if !crypto.VerifyEncKey(identityPub, req.EncPublicKey, req.EncKeySig) {
		abort(c, http.StatusBadRequest, "enc key signature does not verify against the account identity key")
		return
	}
	if err := s.store.SetEncKey(owner, req.EncPublicKey, req.EncKeySig); err != nil {
		abort(c, http.StatusInternalServerError, "store failed")
		return
	}
	c.Status(http.StatusNoContent)
}

// createGrant stores a client-sealed grant on a resource the caller owns
// (POST /v1/resources/:id/grants). Upserting an existing grantee replaces the
// wrap, which is how key rotation re-wraps for remaining grantees.
func (s *Server) createGrant(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.CreateGrantRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.GranteeHandle == "" || len(req.WrappedKey) == 0 || len(req.WrappedKey) > maxGrantWrapSize {
		abort(c, http.StatusBadRequest, "granteeHandle and a bounded wrappedKey are required")
		return
	}
	if req.GranteeHandle == owner {
		abort(c, http.StatusBadRequest, "cannot grant a resource to its own account")
		return
	}
	err := s.store.PutGrant(owner, c.Param("id"), req.GranteeHandle, req.WrappedKey, req.ExpectedVersion)
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource or grants changed since you last fetched it", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGrantLimit) {
		abortCode(c, http.StatusBadRequest, "grant limit reached for this resource", api.ErrCodeGrantLimit)
		return
	}
	if errors.Is(err, ErrSenderBlocked) {
		abortCode(c, http.StatusForbidden, ErrSenderBlocked.Error(), api.ErrCodeSenderBlocked)
		return
	}
	if errors.Is(err, ErrGitRemotePolicy) {
		abortCode(c, http.StatusBadRequest, ErrGitRemotePolicy.Error(), api.ErrCodeGitRemotePolicy)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "store failed")
		return
	}
	s.metrics.grantWrites.Inc()
	c.Status(http.StatusCreated)
}

// listResourceGrants lists a resource's grants for its owner.
func (s *Server) listResourceGrants(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	grants, next, err := s.store.ListResourceGrants(owner, c.Param("id"), page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListGrantsResponse{Grants: grants, NextCursor: next})
}

// deleteGrant revokes one grant (DELETE /v1/resources/:id/grants/:grantee).
func (s *Server) deleteGrant(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	expected, ok := parseIfMatch(c)
	if !ok {
		return
	}
	err := s.store.DeleteGrant(owner, c.Param("id"), c.Param("grantee"), expected)
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource or grants changed since you last fetched it", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.Status(http.StatusNoContent)
}

// listShares lists the caller's incoming grants (GET /v1/shares).
func (s *Server) listShares(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	shares, next, err := s.store.ListShares(owner, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListSharesResponse{Shares: shares, NextCursor: next})
}

// deleteShare drops one of the caller's incoming grants (DELETE /v1/shares/:id),
// optionally blocking the account that made it (?block=true). The grantee side of
// `unshare --with`: the owner could otherwise put a row in anyone's share list and
// be the only one able to take it out.
func (s *Server) deleteShare(c *gin.Context) {
	grantee := c.GetString(ownerContextKey)
	block := c.Query("block") == "true" || c.Query("block") == "1"
	owner, removed, err := s.store.DeleteShare(grantee, c.Param("id"), block)
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrBlockLimit) {
		abortCode(c, http.StatusBadRequest, "block list is full; lift a block before adding another", api.ErrCodeBlockLimit)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete failed")
		return
	}
	// The grantor's handle is the only address a later unblock can name, and the
	// grantee has just seen it in their own share list either way.
	c.JSON(http.StatusOK, api.RemoveShareResponse{OwnerHandle: owner, Removed: removed, Blocked: block})
}

// listShareBlocks lists the accounts the caller refuses grants from (GET /v1/share-blocks).
func (s *Server) listShareBlocks(c *gin.Context) {
	grantee := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	blocks, next, err := s.store.ListShareBlocks(grantee, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListShareBlocksResponse{Blocks: blocks, NextCursor: next})
}

// deleteShareBlock lifts one block (DELETE /v1/share-blocks/:owner).
func (s *Server) deleteShareBlock(c *gin.Context) {
	grantee := c.GetString(ownerContextKey)
	err := s.store.DeleteShareBlock(grantee, c.Param("owner"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "delete failed")
		return
	}
	c.Status(http.StatusNoContent)
}

// grantObjects serves exact object slices of a granted (or owned) resource to an
// authenticated caller (POST /v1/resources/:id/objects), the read path a grantee's
// clone/pull uses. Same request shape and positional framing as the public
// endpoint; access is the grant check instead of public visibility.
func (s *Server) grantObjects(c *gin.Context) {
	caller := c.GetString(ownerContextKey)
	var req api.PublicObjectsRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.IDs) > maxPublicObjectIDs {
		abortCode(c, http.StatusBadRequest, "too many object ids in one request", api.ErrCodeTooManyIDs)
		return
	}
	owner, locs, err := s.store.ResourceObjectSlices(c.Param("id"), caller, req.IDs)
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "locate failed")
		return
	}
	s.writeObjectFrames(c, owner, locs, s.metrics.grantObjectBytes)
}
