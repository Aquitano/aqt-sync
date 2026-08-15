// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

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

// CreateSnapshotIdempotent is CreateSnapshot driven by the request shape, so a
// caller can carry the scheduled marker, the anchor flag, and an idempotency key
// that replays the original response instead of taking a second snapshot.
func (s *Store) CreateSnapshotIdempotent(owner string, req api.CreateSnapshotRequest) (api.SnapshotInfo, error) {
	return s.createSnapshot(owner, req.ResourceID, req.EncryptedLabel, req.Automatic, req.Anchor, req.IdempotencyKey)
}

// createSnapshot is CreateSnapshot plus the scheduled marker: the scheduled job's
// snapshots are tagged so retention can prune them without touching manual ones.
// anchored pins the snapshot against every retention path.
func (s *Store) createSnapshot(owner, resourceID string, label *crypto.SealedBlob, scheduled, anchored bool, idempotencyKey string) (api.SnapshotInfo, error) {
	digest, err := idempotencyDigest(struct {
		ResourceID string
		Label      *crypto.SealedBlob
		Anchored   bool
		Automatic  bool
	}{resourceID, label, anchored, scheduled})
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
	defer tx.Rollback()
	// Authoritative duplicate check; see the matching re-check in createResource.
	if found, err := lookupIdempotency(tx, owner, "snapshot.create", idempotencyKey, digest, &prior); err != nil {
		return api.SnapshotInfo{}, err
	} else if found {
		return prior, nil
	}
	// Revalidate the source inside the write transaction. Account deletion runs in
	// another process and cannot take this process's resource lock; without this
	// check it could delete the resource after the copy above, then this INSERT
	// would recreate an ownerless snapshot because snapshots has no account FK.
	var currentVersion int
	err = tx.QueryRow(
		`SELECT version FROM resources WHERE id = ? AND owner_handle = ?`, resourceID, owner,
	).Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return api.SnapshotInfo{}, ErrNotFound
	}
	if err != nil {
		return api.SnapshotInfo{}, err
	}
	if currentVersion != version {
		return api.SnapshotInfo{}, ErrVersionConflict
	}
	info := api.SnapshotInfo{ID: snapID, ResourceID: resourceID, Version: version, CreatedAt: createdAt, EncryptedLabel: label, Anchored: anchored, Automatic: scheduled}
	if err := decodeMetaKey(metaJSON, wrappedJSON, &info.EncryptedMeta, &info.WrappedKey); err != nil {
		return api.SnapshotInfo{}, err
	}
	if _, err := tx.Exec(
		`INSERT INTO snapshots(snapshot_id, owner_handle, resource_id, visibility, encrypted_meta, encrypted_label, wrapped_key, blob_nonce, blob_size, version_captured, created_at, scheduled, min_client, anchored)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		snapID, owner, resourceID, visibility, metaJSON, labelJSON, wrappedJSON, nonce, blobSize, version, createdAt, sched, minClient, anchor,
	); err != nil {
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
		return api.SnapshotInfo{}, err
	}
	if err := recordIdempotency(tx, owner, "snapshot.create", idempotencyKey, digest, info); err != nil {
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
	query := `SELECT snapshot_id, resource_id, version_captured, created_at, encrypted_meta, encrypted_label, wrapped_key, anchored, scheduled
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
		if err := rows.Scan(&info.ID, &info.ResourceID, &info.Version, &info.CreatedAt, &metaJSON, &labelJSON, &wrappedJSON, &info.Anchored, &info.Automatic); err != nil {
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
	defer tx.Rollback()
	// Unpinning can flip objects dead (if no resource or other snapshot still roots
	// them), so the affected packs' counters are recomputed in the same transaction.
	dropped, err := snapshotChunkIDs(tx, snapshotID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM snapshot_chunks WHERE snapshot_id = ?`, snapshotID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM snapshots WHERE snapshot_id = ? AND owner_handle = ?`, snapshotID, owner); err != nil {
		return err
	}
	if err := recountPacksForChunks(tx, owner, dropped); err != nil {
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
	quotaByOwner := map[string]int64{}
	created := 0
	var firstErr error
	for _, r := range due {
		quota, ok := quotaByOwner[r.owner]
		if !ok {
			quota = quotaBytes
			override, err := s.AccountQuota(r.owner)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if override.Valid {
				quota = override.Int64
			}
			quotaByOwner[r.owner] = quota
		}

		var u *AccountUsage
		var added int64
		if maxSnapshots > 0 || quota > 0 {
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
			if quota > 0 {
				res, err := s.GetResource(r.id, r.owner)
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				added = estimatedResourceBytes(api.PutResourceRequest{Blob: res.Blob, EncryptedMeta: res.EncryptedMeta, WrappedKey: res.WrappedKey})
				if u.StorageBytes+added > quota {
					if firstErr == nil {
						firstErr = &LimitExceededError{Kind: "storageBytes", Current: u.StorageBytes, Limit: quota}
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
