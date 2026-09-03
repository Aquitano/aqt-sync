// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

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
	compactAt, err := validateGitRemotePolicy(req, 0)
	if err != nil {
		return "", 0, err
	}
	// The digest covers the complete request, blob included, so it is only worth
	// computing when a key makes it usable; this is the single hash for the whole
	// create (the quota preflight probes key existence without one).
	var digest []byte
	var prior api.PutResourceResponse
	if req.IdempotencyKey != "" {
		if digest, err = idempotencyDigest(req); err != nil {
			return "", 0, err
		}
		if found, err := lookupIdempotency(s.rdb, owner, "resource.create", req.IdempotencyKey, digest, &prior); err != nil {
			return "", 0, err
		} else if found {
			return prior.ID, prior.Version, nil
		}
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
	defer func() { _ = tx.Rollback() }()
	// Authoritative duplicate check: the pre-tx lookup on the read pool may see a
	// stale WAL snapshot; only this re-check on the single writer connection is
	// race-free. Do not remove it as redundant.
	if found, err := lookupIdempotency(tx, owner, "resource.create", req.IdempotencyKey, digest, &prior); err != nil {
		return "", 0, err
	} else if found {
		return prior.ID, prior.Version, nil
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(
		`INSERT INTO resources(id, owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, blob_size, version, min_client, expires_at, max_reads, on_expiry, created_at, updated_at, compact_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, owner, string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, int64(len(req.Blob.Ciphertext)), version, req.MinClient, expiresAt, maxReads, onExpiry, now, now, compactAt,
	); err != nil {
		return "", 0, err
	}
	if err := replaceResourceChunks(tx, id, owner, req.ChunkRefs); err != nil {
		return "", 0, err
	}
	if err := recordIdempotency(tx, owner, "resource.create", req.IdempotencyKey, digest, api.PutResourceResponse{ID: id, Version: version}); err != nil {
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
		current         int
		storedMin       int
		storedCompactAt int
		reclaimed       bool
		storedNonce     []byte
	)
	err = s.db.QueryRow(
		`SELECT version, min_client, compact_at, reclaimed, blob_nonce FROM resources WHERE id = ? AND owner_handle = ?`, req.ID, owner,
	).Scan(&current, &storedMin, &storedCompactAt, &reclaimed, &storedNonce)
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
	compactAt, err := validateGitRemotePolicy(req, storedCompactAt)
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
	// The immutable-per-nonce blob layout is what makes the write below safe, and it
	// rests entirely on the nonce being new. A request repeating the live nonce
	// addresses the live file: writeBlob would truncate it, and any failure exit before
	// the commit would then delete a file the committed row still names, leaving the
	// resource undecryptable. Every reseal draws a fresh nonce, so no correct client
	// trips this.
	if bytes.Equal(storedNonce, req.Blob.Nonce) {
		return "", 0, ErrNonceReuse
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
	defer func() { _ = tx.Rollback() }()
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
	const setContent = `visibility=?, encrypted_meta=?, wrapped_key=?, blob_nonce=?, blob_size=?, version=?, min_client=?, compact_at=?, updated_at=unixepoch()`
	replacePolicy := req.Visibility != api.Public || req.ExpireSeconds > 0 || req.MaxReads > 0 || reclaimed

	set := setContent
	args := []any{
		string(req.Visibility), metaJSON, wrappedJSON, req.Blob.Nonce, int64(len(req.Blob.Ciphertext)), version, req.MinClient, compactAt,
	}
	if replacePolicy {
		set += `,
		   expires_at=?, max_reads=?, on_expiry=?, reads=0, exhausted_at=NULL, reclaimed=0`
		args = append(args, expiresAt, maxReads, onExpiry)
	}
	args = append(args, req.ID, owner, current)

	res, err := tx.Exec(
		`UPDATE resources SET `+set+`
		 WHERE id=? AND owner_handle=? AND version=?`,
		args...,
	)
	if err != nil {
		return "", 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", 0, ErrVersionConflict
	}
	if len(req.ChunkRefs) == 0 {
		// A refs-less update of a resource that has refs is the private fast path:
		// the rows are left untouched, since they only matter as a non-owner read
		// scope. A shared resource is the one place stale rows would bite — its
		// readers could fetch nothing pushed since — so there the write is refused.
		// An inline resource (no rows) passes either way; the server cannot tell it
		// from a folder, and does not need to.
		var existing int
		if err := tx.QueryRow(
			`SELECT count(*) FROM resource_chunks WHERE resource_id = ?`, req.ID,
		).Scan(&existing); err != nil {
			return "", 0, err
		}
		if existing > 0 {
			var shared bool
			if err := tx.QueryRow(
				`SELECT ? OR EXISTS(SELECT 1 FROM grants WHERE resource_id = ? AND owner_handle = ?)`,
				req.Visibility == api.Public, req.ID, owner,
			).Scan(&shared); err != nil {
				return "", 0, err
			}
			if shared {
				return "", 0, ErrSharedNeedsRefs
			}
		}
	} else if err := replaceResourceChunks(tx, req.ID, owner, req.ChunkRefs); err != nil {
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
	out, countRead, err := s.getResourceUncounted(id, requireOwner)
	// An update unlinks the superseded blob only after its row commits, so a read
	// that loaded the old row can find the file already gone. The row now names the
	// new nonce; re-read instead of failing a live resource with a transient 404.
	if errors.Is(err, errStaleBlob) {
		out, countRead, err = s.getResourceUncounted(id, requireOwner)
	}
	if errors.Is(err, errStaleBlob) {
		// Twice in a row is no longer the unlink race; surface it as the internal
		// inconsistency it is rather than a 404 for a resource whose row exists.
		err = fmt.Errorf("resource %s: row names a blob that does not exist", id)
	}
	return out, countRead, err
}

// errStaleBlob marks a row whose blob file is missing: either the read raced an
// update's unlink of the superseded blob (retryable) or the store is inconsistent.
var errStaleBlob = errors.New("resource blob missing for stored nonce")

func (s *Store) getResourceUncounted(id, requireOwner string) (api.GetResourceResponse, bool, error) {
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
		compactAt   int
	)
	err := s.rdb.QueryRow(
		`SELECT owner_handle, visibility, encrypted_meta, wrapped_key, blob_nonce, version, min_client, expires_at, max_reads, reads, reclaimed, created_at, updated_at, compact_at
		 FROM resources WHERE id = ?`, id,
	).Scan(&owner, &visibility, &metaJSON, &wrappedJSON, &nonce, &version, &minClient, &expiresAt, &maxReads, &reads, &reclaimed, &createdAt, &updatedAt, &compactAt)
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
	if errors.Is(err, ErrNotFound) {
		return out, false, errStaleBlob
	}
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
		CompactAt:  compactAt,
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
	defer func() { _ = tx.Rollback() }()
	var (
		reads     int64
		maxReads  sql.NullInt64
		reclaimed bool
	)
	if err := tx.QueryRow(
		`SELECT reads, max_reads, reclaimed FROM resources WHERE id = ?`, id,
	).Scan(&reads, &maxReads, &reclaimed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if reclaimed {
		return 0, ErrGone
	}
	if !maxReads.Valid {
		return reads, nil
	}
	if reads >= maxReads.Int64 {
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
		maxReads  sql.NullInt64
		reads     int64
		reclaimed bool
	)
	err = s.rdb.QueryRow(
		`SELECT visibility, expires_at, max_reads, reads, reclaimed FROM resources WHERE id = ?`, id,
	).Scan(&visStr, &expiresAt, &maxReads, &reads, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	// The same exhaustion predicate PublicResourcePreflight applies: a burned or
	// read-exhausted link is gone the moment its last permit is spent, not when the
	// GC sweep tombstones it hours later.
	gone = reclaimed ||
		(expiresAt.Valid && time.Now().Unix() >= expiresAt.Int64) ||
		(maxReads.Valid && reads >= maxReads.Int64)
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
	var current, compactAt int
	var reclaimed bool
	err = s.db.QueryRow(`SELECT version, compact_at, reclaimed FROM resources WHERE id = ? AND owner_handle = ?`, id, owner).Scan(&current, &compactAt, &reclaimed)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	// A reclaimed tombstone has no ciphertext to expose; flipping its visibility
	// (and resetting its read counters) would fabricate a live-looking link over
	// nothing. Only a full content re-push resurrects it — the guard the update
	// path already enforces.
	if reclaimed {
		return 0, ErrGone
	}
	if compactAt > 0 && req.Visibility != api.Private {
		return 0, ErrGitRemotePolicy
	}
	if req.ExpectedVersion > 0 && req.ExpectedVersion != current {
		return 0, ErrVersionConflict
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(
		`UPDATE resources SET visibility = ?, version = version + 1, updated_at = unixepoch(),
		   expires_at = ?, max_reads = ?, on_expiry = ?, reads = 0, exhausted_at = NULL
		 WHERE id = ? AND owner_handle = ? AND reclaimed = 0`,
		string(req.Visibility), expiresAt, maxReadsCol, onExpiry, id, owner,
	)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	// The stored refs can be stale on a client-GC account (private pushes omit
	// them), so the flip that mints readers may carry the current set.
	if len(req.ChunkRefs) > 0 {
		if err := replaceResourceChunks(tx, id, owner, req.ChunkRefs); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
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
		`SELECT id, visibility, encrypted_meta, wrapped_key, version, auto_snapshot, compact_at, min_client,
		        COALESCE(expires_at, 0), COALESCE(max_reads, 0), COALESCE(reads, 0), created_at, updated_at, reclaimed,
		        (SELECT COUNT(*) FROM grants g WHERE g.resource_id = resources.id)
		 FROM resources WHERE `+where+` ORDER BY id LIMIT ?`, args...,
	)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()

	var items []api.ResourceListItem
	for rows.Next() {
		var (
			item        api.ResourceListItem
			vis         string
			metaJSON    string
			wrappedJSON sql.NullString
		)
		if err := rows.Scan(&item.ID, &vis, &metaJSON, &wrappedJSON, &item.Version, &item.AutoSnapshot, &item.CompactAt,
			&item.MinClient, &item.ExpiresAt, &item.MaxReads, &item.Reads, &item.CreatedAt, &item.UpdatedAt, &item.Reclaimed,
			&item.GrantCount); err != nil {
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
	defer func() { _ = tx.Rollback() }()
	if expectedVersion > 0 {
		var current int
		err := tx.QueryRow(`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, id, owner).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if current != expectedVersion {
			return ErrVersionConflict
		}
	}
	res, err := tx.Exec(`DELETE FROM resources WHERE id = ? AND owner_handle = ?`, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// Drop the read-scope rows; the chunks themselves stay until a client prune
	// determines they are unreachable from every remaining root.
	if _, err := tx.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, id); err != nil {
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

// --- handlers ---

func (s *Server) handlePutResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	capability := requestCapability(c)
	req, ok := decodePutResource(c)
	if !ok {
		return
	}
	// Create is POST, so it can be replayed under an Idempotency-Key without the
	// client having to guess an id; PUT names the resource it replaces.
	if c.Request.Method == http.MethodPut && req.ID == "" {
		abort(c, http.StatusBadRequest, "PUT /v1/resources requires the id of the resource to replace; POST to create one")
		return
	}
	if key := c.GetHeader("Idempotency-Key"); len(key) > 128 {
		abort(c, http.StatusBadRequest, "Idempotency-Key must be at most 128 bytes")
		return
	} else {
		req.IdempotencyKey = key
	}
	// A client cannot declare content unreadable by itself: that would be a resource
	// it just wrote but could never read back. Reject it as a client bug.
	if req.MinClient > capability {
		abort(c, http.StatusBadRequest, "declared min_client exceeds this client's capability")
		return
	}
	// Nor can it declare less than the format every release reads. Every client
	// declares its own capability, so a lower value is a client bug rather than
	// something for the server to quietly floor.
	if req.MinClient < api.CapabilityBaseline {
		abort(c, http.StatusBadRequest, fmt.Sprintf("declared min_client is below the capability baseline (%d)", api.CapabilityBaseline))
		return
	}
	if req.CompactAt < 0 {
		abort(c, http.StatusBadRequest, "compactAt must be non-negative")
		return
	}
	switch req.Visibility {
	case api.Private:
		if req.WrappedKey == nil {
			abort(c, http.StatusBadRequest, "private resource requires a wrapped key")
			return
		}
	case api.Public:
		// A wrapped key is optional and welcome: it is the owner's recovery path
		// (so they can later share/rotate), and GetResource strips it from
		// non-owner reads.
	default:
		abort(c, http.StatusBadRequest, "visibility must be private or public")
		return
	}
	// An in-place update writes just as many physical bytes as a create, so it is
	// charged too; it replaces the resource's current bytes rather than adding to
	// them, so only the difference counts, and it adds no row (no count check).
	// A replayed create is already stored and must not be charged again.
	if !s.store.ResourceCreateKeyRecorded(owner, req) {
		defer s.accountLimits.lock(owner)()
		added, kind := estimatedResourceBytes(req), "resources"
		if req.ID != "" {
			kind = ""
			stored, err := s.store.ResourceStoredBytes(owner, req.ID)
			if err != nil {
				abort(c, http.StatusInternalServerError, "usage lookup failed")
				return
			}
			added = max(0, added-stored)
		}
		if err := s.checkAccountLimit(owner, kind, added); err != nil {
			if !abortLimit(c, err) {
				abort(c, http.StatusInternalServerError, "usage lookup failed")
			}
			return
		}
	}
	id, version, err := s.store.PutResource(owner, capability, req)
	var upgrade *UpgradeRequiredError
	if errors.As(err, &upgrade) {
		abortUpgradeRequired(c, upgrade.MinClient, capability)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; re-sync", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrIdempotencyConflict) {
		abortCode(c, http.StatusConflict, "Idempotency-Key was already used for another request", api.ErrCodeIdempotencyConflict)
		return
	}
	if errors.Is(err, ErrSharedNeedsRefs) {
		abortCode(c, http.StatusBadRequest, "a public or granted resource must carry its chunk refs (they scope what its readers may fetch); re-push with refs before sharing", api.ErrCodeSharedNeedsRefs)
		return
	}
	if errors.Is(err, ErrDanglingRefs) {
		abortCode(c, http.StatusBadRequest, "manifest references chunks the server no longer stores (they were garbage-collected before this push committed); re-run sync to re-upload them", api.ErrCodeMissingChunks)
		return
	}
	if errors.Is(err, ErrNonceReuse) {
		abort(c, http.StatusBadRequest, "blob nonce matches the stored one; every reseal must draw a fresh nonce")
		return
	}
	if errors.Is(err, ErrPolicyOnPrivate) || errors.Is(err, ErrBadPolicy) {
		abortCode(c, http.StatusBadRequest, policyErrorMessage(err), api.ErrCodeInvalidPolicy)
		return
	}
	if errors.Is(err, ErrGitRemotePolicy) {
		abortCode(c, http.StatusBadRequest, ErrGitRemotePolicy.Error(), api.ErrCodeGitRemotePolicy)
		return
	}
	if errors.Is(err, ErrNotFound) {
		// Update targeting an id the caller doesn't own (or that doesn't exist).
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "store failed")
		return
	}
	status := http.StatusCreated
	if req.ID != "" {
		status = http.StatusOK
	}
	expiresAt, maxReads := policyExpiresAt(req), policyMaxReads(req)
	c.JSON(status, api.PutResourceResponse{
		ID: id, Version: version,
		ExpiresAt: expiresAt, MaxReads: maxReads,
		OnExpiry: echoedOnExpiry(req.OnExpiry, expiresAt, maxReads),
	})
}

// policyExpiresAt is the absolute expiry the server just stored, echoed so a new client
// can confirm an old server did not silently drop the policy. It recomputes now + TTL;
// the microsecond drift from the store's own clock is immaterial (the client's sanity
// check tolerates it). Zero unless a policy was accepted on a public resource.
func policyExpiresAt(req api.PutResourceRequest) int64 {
	if req.Visibility == api.Public && req.ExpireSeconds > 0 {
		return time.Now().Unix() + req.ExpireSeconds
	}
	return 0
}

func policyMaxReads(req api.PutResourceRequest) int64 {
	if req.Visibility == api.Public {
		return req.MaxReads
	}
	return 0
}

// echoedOnExpiry reports the end-of-life action the server just stored, so a client that
// asked to retire the link can fail closed against a server that would instead destroy
// the content behind it. A server that predates the field echoes nothing at all, which
// is how the client tells the two apart. Empty when no policy was accepted: there is
// then no end of life to act on.
//
// The value comes from storedOnExpiry, the same mapping the write used, rather than a
// second reading of the request: an action mapped one way into the row and another way
// into the echo is exactly the mismatch the client's check exists to catch.
func echoedOnExpiry(requested api.OnExpiry, expiresAt, maxReads int64) api.OnExpiry {
	if expiresAt == 0 && maxReads == 0 {
		return ""
	}
	action, err := storedOnExpiry(requested)
	if err != nil {
		// Unreachable: the same error already rejected the write with a 400.
		return ""
	}
	return api.OnExpiry(action)
}

func (s *Server) handlePublicResourcePreflight(c *gin.Context) {
	preflight, err := s.store.PublicResourcePreflight(c.Param("id"))
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "preflight failed")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, preflight)
}

func (s *Server) handleGetResource(c *gin.Context) {
	// An authenticated owner can read their private resources; anyone can read a
	// public one. We pass the owner (empty if unauthenticated) to the store so a
	// private id returns 404 to everyone else.
	var owner string
	if token, ok := bearerToken(c); ok {
		if o, err := s.store.OwnerByToken(token); err == nil {
			owner = o
		}
	}
	// Negotiate before the resource is touched at all: a request whose Accept we
	// cannot satisfy must not spend one of a `--burn` link's reads.
	format, ok := negotiateResourceResponse(c.GetHeader("Accept"))
	if !ok {
		abort(c, http.StatusNotAcceptable, "no acceptable resource representation; request version=1 JSON or envelope media type")
		return
	}
	res, countRead, err := s.store.GetResourceUncounted(c.Param("id"), owner)
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if errors.Is(err, ErrGone) {
		abortGone(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "fetch failed")
		return
	}
	// Gate the read on the requester's capability before any payload is written: a
	// client too old to open the sealed format gets an actionable 426 instead of the
	// bytes and a downstream AEAD failure. This route is public, so the check lives
	// here rather than in the authed middleware. It precedes the read count for the
	// same reason the Accept check does.
	if capability := requestCapability(c); capability < res.MinClient {
		abortUpgradeRequired(c, res.MinClient, capability)
		return
	}
	// Everything that could refuse this read has passed, so the permit is spent now.
	// This is also what enforces exhaustion: an already-spent link answers 410 here.
	if countRead {
		if err := s.store.CountResourceRead(c.Param("id")); err != nil {
			if errors.Is(err, ErrGone) {
				abortGone(c)
			} else {
				abort(c, http.StatusInternalServerError, "fetch failed")
			}
			return
		}
	}
	if format == resourceEnvelope {
		body, err := api.EncodeResourceDownload(res)
		if err != nil {
			abort(c, http.StatusInternalServerError, "encode failed")
			return
		}
		c.Data(http.StatusOK, api.ResourceEnvelopeMediaType, body)
		return
	}
	c.Header("Content-Type", api.ResourceJSONMediaType)
	c.JSON(http.StatusOK, res)
}

// decodePutResource reads a resource upload. The body is always the raw envelope
// (JSON header + blob ciphertext, single-buffered and never JSON-decoded), so it
// must declare the envelope media type; it sits behind the maxResourceBody cap.
// Responses are still negotiated — see negotiateResourceResponse — because the
// browser share page reads the JSON form.
func decodePutResource(c *gin.Context) (api.PutResourceRequest, bool) {
	if !isResourceEnvelope(c.GetHeader("Content-Type")) {
		abort(c, http.StatusUnsupportedMediaType, "resource uploads must be sent as "+api.ResourceEnvelopeMediaType)
		return api.PutResourceRequest{}, false
	}
	req, err := api.DecodeResourceUpload(c.Request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			abort(c, http.StatusRequestEntityTooLarge, "resource body exceeds limit")
		case errors.Is(err, api.ErrHeaderTooLarge):
			// 400 rather than 413: the request as a whole is within the cap, it is the
			// manifest's chunk-ref set that cannot be expressed in one upload. The code
			// and the message name that instead of saying "invalid resource body".
			abortCode(c, http.StatusBadRequest,
				"resource header exceeds the 32 MiB request cap; the chunk-ref set of this manifest is too large to upload in one request",
				api.ErrCodeResourceTooLarge)
		default:
			abort(c, http.StatusBadRequest, "invalid resource body")
		}
		return api.PutResourceRequest{}, false
	}
	return req, true
}

// isResourceEnvelope reports whether a request Content-Type declares the version=1
// resource envelope. Nothing else is accepted on a write: an unlabelled or
// generically-labelled body is a client that has not been taught the format.
func isResourceEnvelope(header string) bool {
	mediaType, params, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	return mediaType == "application/vnd.aqt.resource+octet-stream" && params["version"] == "1"
}

type resourceFormat int

const (
	resourceJSON resourceFormat = iota
	resourceEnvelope
)

func negotiateResourceResponse(header string) (resourceFormat, bool) {
	if strings.TrimSpace(header) == "" {
		return resourceJSON, true
	}
	bestQ, bestSpecificity, best := -1.0, -1, resourceJSON
	for _, item := range strings.Split(header, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(item))
		if err != nil {
			continue
		}
		q := 1.0
		if raw := params["q"]; raw != "" {
			q, err = strconv.ParseFloat(raw, 64)
			if err != nil || q < 0 || q > 1 {
				continue
			}
		}
		if q == 0 {
			continue
		}
		var format resourceFormat
		specificity := 2
		switch mediaType {
		case "application/vnd.aqt.resource+octet-stream":
			if params["version"] != "1" {
				continue
			}
			format = resourceEnvelope
		case "application/vnd.aqt.resource+json":
			if params["version"] != "1" {
				continue
			}
			format = resourceJSON
		case "application/octet-stream":
			format = resourceEnvelope
		case "application/json":
			format = resourceJSON
		case "application/*":
			format, specificity = resourceJSON, 1
		case "*/*":
			format, specificity = resourceJSON, 0
		default:
			continue
		}
		if q > bestQ || q == bestQ && specificity > bestSpecificity {
			bestQ, bestSpecificity, best = q, specificity, format
		}
	}
	return best, bestQ >= 0
}

// handleListResources is the owner's own inventory, and the one read path that does not
// gate on the requester's capability: 426ing the whole listing because one row is
// too new would hide every other resource the client can read. Each row carries its
// min_client instead, so an under-capable client names the release a row needs.
func (s *Server) handleListResources(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	page, ok := parsePage(c)
	if !ok {
		return
	}
	items, next, err := s.store.ListResources(owner, page)
	if errors.Is(err, errBadCursor) {
		abortCode(c, http.StatusBadRequest, "invalid pagination cursor", api.ErrCodeInvalidCursor)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "list failed")
		return
	}
	c.JSON(http.StatusOK, api.ListResourcesResponse{Resources: items, NextCursor: next})
}

func (s *Server) handleUpdateResourceMetadata(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.UpdateResourceMetadataRequest
	if !bindJSON(c, &req) {
		return
	}
	if len(req.EncryptedMeta.Nonce) == 0 || len(req.EncryptedMeta.Ciphertext) == 0 || req.ExpectedVersion <= 0 {
		abort(c, http.StatusBadRequest, "encrypted metadata and expectedVersion are required")
		return
	}
	capability := requestCapability(c)
	version, err := s.store.UpdateResourceMetadata(owner, c.Param("id"), capability, req)
	var upgrade *UpgradeRequiredError
	if errors.As(err, &upgrade) {
		abortUpgradeRequired(c, upgrade.MinClient, capability)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the rename", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "metadata update failed")
		return
	}
	c.JSON(http.StatusOK, api.PutResourceResponse{ID: c.Param("id"), Version: version})
}

func (s *Server) handleSetVisibility(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	var req api.SetVisibilityRequest
	if !bindJSON(c, &req) {
		return
	}
	if req.Visibility != api.Private && req.Visibility != api.Public {
		abort(c, http.StatusBadRequest, "visibility must be private or public")
		return
	}
	version, err := s.store.SetVisibility(owner, c.Param("id"), req)
	if errors.Is(err, ErrGone) {
		// A reclaimed tombstone: nothing left to expose or hide.
		abortGone(c)
		return
	}
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the visibility change", api.ErrCodeVersionConflict)
		return
	}
	if errors.Is(err, ErrPolicyOnPrivate) || errors.Is(err, ErrBadPolicy) {
		abortCode(c, http.StatusBadRequest, policyErrorMessage(err), api.ErrCodeInvalidPolicy)
		return
	}
	if errors.Is(err, ErrGitRemotePolicy) {
		abortCode(c, http.StatusBadRequest, ErrGitRemotePolicy.Error(), api.ErrCodeGitRemotePolicy)
		return
	}
	if errors.Is(err, ErrNotFound) {
		abortNotFound(c)
		return
	}
	if err != nil {
		abort(c, http.StatusInternalServerError, "update failed")
		return
	}
	resp := api.PutResourceResponse{ID: c.Param("id"), Version: version}
	if req.Visibility == api.Public {
		if req.ExpireSeconds > 0 {
			resp.ExpiresAt = time.Now().Unix() + req.ExpireSeconds
		}
		resp.MaxReads = req.MaxReads
		resp.OnExpiry = echoedOnExpiry(req.OnExpiry, resp.ExpiresAt, resp.MaxReads)
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleDeleteResource(c *gin.Context) {
	owner := c.GetString(ownerContextKey)
	expected, ok := parseIfMatch(c)
	if !ok {
		return
	}
	err := s.store.DeleteResourceVersion(owner, c.Param("id"), expected)
	if errors.Is(err, ErrVersionConflict) {
		abortCode(c, http.StatusConflict, "resource changed since you last fetched it; retry the delete", api.ErrCodeVersionConflict)
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

// policyErrorMessage maps the two lifecycle-policy validation errors to fixed,
// user-facing messages, so the handler answers a stable string (and a stable Code)
// rather than echoing the raw error value.
func policyErrorMessage(err error) string {
	if errors.Is(err, ErrPolicyOnPrivate) {
		return "a link lifecycle policy can only be set on a public resource"
	}
	return "link lifecycle policy values must be non-negative"
}
