// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

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

// ErrDanglingRefs marks a manifest write whose chunk refs name objects the owner no
// longer stores — a GC sweep reaped an uploaded-but-unrooted pack before the push's
// manifest PUT could root it (a push slower than the GC age guard). The FK from
// resource_chunks to objects is what catches it; handlers map this to a named 4xx
// telling the client to re-run sync (which re-uploads exactly the missing chunks)
// instead of an opaque 500.
var ErrDanglingRefs = errors.New("manifest references chunks the server no longer stores")

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
			// OR IGNORE does not soften FK failures, so a ref to a swept object lands
			// here rather than committing dangling.
			if isForeignKeyViolation(err) {
				return ErrDanglingRefs
			}
			return err
		}
	}
	return nil
}

// recountPacks recomputes obj_count/live_bytes for the named packs from the
// object rows as they stand inside the caller's transaction. A stored object is
// live until its owner deletes its row (reachability is the client's job), so the
// counters are simply the rows' count and total length; the sweep and repack
// select on them so their plans never scan the objects table.
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
			   live_bytes = COALESCE((SELECT sum(o.length) FROM objects o
			                 WHERE o.owner_handle = packs.owner_handle AND o.pack_id = packs.pack_id), 0)
			 WHERE owner_handle = ? AND pack_id IN (`+placeholders(len(group))+`)`,
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
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, ids,
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
// The one unbatched IN clause in this file is deliberate: the handler caps the id
// set at maxPublicObjectIDs (10,000), ~10,003 bound variables against SQLite's
// 32,766 limit, so it cannot overrun the way an unbounded set would.
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

// queryIDsBatched runs query once per batch-size group of ids, keeping the IN clause
// well under SQLite's bound-variable limit. It prepends lead to the bound args and
// splices the group's placeholder list plus closing paren onto query, so callers pass
// the SELECT up to and including "IN (". Each batch's rows are closed before the next
// runs, and the first scan error aborts.
func queryIDsBatched(q queryer, query string, lead []any, ids []string, scan func(*sql.Rows) error) error {
	const batch = 400
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
				_ = rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
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

func (s *Store) PutPackWithLimits(owner, packID string, data []byte, quotaBytes int64, maxObjects int) (stored int, err error) {
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

	defer s.gcLocks.lock(owner)()
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

	path := s.packPath(owner, packID)
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !created {
		return 0, statErr
	}
	committed := false
	defer func() {
		if committed || !created {
			return
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove uncommitted pack %s: %w", packID, removeErr))
		}
	}()

	if err = s.writePack(owner, packID, data); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Packs intentionally predate account foreign keys. Recheck the owner inside
	// this write transaction so an upload authenticated just before an operator
	// deletes the account cannot recreate pack/object rows after the deletion.
	var accountExists int
	err = tx.QueryRow(`SELECT 1 FROM accounts WHERE owner_handle = ?`, owner).Scan(&accountExists)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
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
		return 0, err
	}
	inserted, _ := res.RowsAffected()
	if inserted == 0 {
		// The pack already exists; re-arm its GC age guard so a concurrent read of it
		// is not reaped.
		if _, err := tx.Exec(
			`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`, now, owner, packID,
		); err != nil {
			return 0, err
		}
	} else {
		if quotaBytes > 0 {
			var used int64
			if err := tx.QueryRow(`SELECT pack_bytes FROM accounts WHERE owner_handle = ?`, owner).Scan(&used); err != nil {
				return 0, err
			}
			if used+int64(len(data)) > quotaBytes {
				return 0, ErrQuotaExceeded
			}
		}
		if err := addOwnerPackBytes(tx, owner, int64(len(data))); err != nil {
			return 0, err
		}
	}
	stored, err = insertObjects(tx, owner, packID, index)
	if err != nil {
		return 0, err
	}
	if err := addOwnerObjectCount(tx, owner, int64(stored)); err != nil {
		return 0, err
	}
	if maxObjects > 0 {
		// The counter already includes this transaction's inserts, so the cap check
		// reads it instead of counting the owner's largest table per pack PUT.
		var count int64
		if err := tx.QueryRow(`SELECT object_count FROM accounts WHERE owner_handle = ?`, owner).Scan(&count); err != nil {
			return 0, err
		}
		if count > int64(maxObjects) {
			return 0, &LimitExceededError{Kind: "objects", Current: count - int64(stored), Limit: int64(maxObjects)}
		}
	}
	// The new rows change this pack's obj_count. They cannot be live yet — a root's
	// FK requires a pre-existing object row, so a just-inserted object is unrooted
	// until a later manifest PUT — but recounting keeps one code path.
	if err := recountPacks(tx, owner, []string{packID}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	committed = true
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
		return nil, 0, fmt.Errorf("%w: index json: %w", ErrBadPack, err)
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
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id, pack_id, "offset", length FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, ids,
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

	// Membership: every requested id must be a chunk root of this resource. A miss on
	// any id fails the whole request without revealing which one.
	member := map[string]bool{}
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id FROM resource_chunks WHERE resource_id = ? AND chunk_id IN (`,
		[]any{resourceID}, distinct,
		func(rows *sql.Rows) error {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			member[id] = true
			return nil
		},
	); err != nil {
		return nil, err
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
	if err := queryIDsBatched(s.rdb,
		`SELECT chunk_id, pack_id, "offset", length FROM objects WHERE owner_handle = ? AND chunk_id IN (`,
		[]any{owner}, distinct,
		func(rows *sql.Rows) error {
			var (
				id, packID  string
				off, length int64
			)
			if err := rows.Scan(&id, &packID, &off, &length); err != nil {
				return err
			}
			locByID[id] = api.ObjectLocation{ID: id, PackID: packID, Off: off, Len: length}
			if !seenPack[packID] {
				seenPack[packID] = true
				packs = append(packs, packID)
			}
			return nil
		},
	); err != nil {
		return nil, err
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
			_ = rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

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
// Any other stored action errors and leaves the row alone, so the sweep stops rather
// than guesses.
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
	defer func() { _ = tx.Rollback() }()
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if !stillExpired {
		return nil
	}
	// Every action is named. Destroying content is never the fall-through: an on_expiry
	// this build does not know (a newer server wrote the row, or an enum grew) leaves the
	// resource untouched and fails the sweep, because the one guess that cannot be undone
	// is the wrong one to make.
	switch api.OnExpiry(action) {
	case api.ExpiryRetire:
		if _, err := tx.Exec(
			`UPDATE resources SET visibility = ?, expires_at = NULL, max_reads = NULL, reads = 0,
			   exhausted_at = NULL, version = version + 1
			 WHERE id = ?`,
			string(api.Private), id,
		); err != nil {
			return err
		}
		return tx.Commit()
	case api.ExpiryReclaim:
		return s.reclaimLink(tx, id)
	default:
		return fmt.Errorf("resource %s: unknown on_expiry action %q", id, action)
	}
}

// reclaimLink is endOfLife's reclaim arm: it runs inside that function's transaction and
// under its resource lock, and commits.
func (s *Store) reclaimLink(tx *sql.Tx, id string) error {
	// The blob dies here; the chunk objects (still possibly shared with other
	// resources) wait for a client prune.
	if _, err := tx.Exec(`DELETE FROM resource_chunks WHERE resource_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`UPDATE resources SET reclaimed = 1, wrapped_key = NULL, blob_size = 0, version = version + 1 WHERE id = ?`, id,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.removeStaleBlobs(id, nil) // drop every blob file; the content is reclaimed
	return nil
}

// GC runs the owner's scheduled maintenance under one owner-scoped lock: it fires
// due link lifecycle policies (SweepExpired), sweeps fully-dead packs (GCPacks),
// then compacts the dead objects trapped in still-live ones (RepackOwner). The lock
// serializes the whole sequence so two concurrent passes — two folders syncing at
// once, two devices, or a manual sync racing the watch daemon, each of which triggers
// a GC — cannot both pick the same repack candidate and have the loser's stale-plan
// branch delete the winner's now-live compacted pack. The single DB connection
// serializes the transactions, but not the pack-file writes and removes around them,
// so this lock is what makes the swap safe.
func (s *Store) GC(owner string, minAge time.Duration) (api.GCResponse, error) {
	defer s.gcLocks.lock(owner)()
	// Fire due link policies first. This unroots a reclaimed link's chunks and deletes
	// its blob, but not its object rows — those wait for a prune, since the server
	// cannot tell which of them another resource still shares — so what this frees for
	// the pack sweep below is only what an earlier prune had already emptied.
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

// BackdatePacksForTest shifts every pack's created_at into the past, so a test can
// step over the GC age guard without waiting it out.
func (s *Store) BackdatePacksForTest(owner string, by time.Duration) error {
	_, err := s.db.Exec(
		`UPDATE packs SET created_at = created_at - ? WHERE owner_handle = ?`,
		int64(by/time.Second), owner,
	)
	return err
}

// ResourceChunkRowsForTest counts a resource's stored chunk-ref rows, so a test can
// tell a refs-less write (rows untouched) from a refs-full one (rows replaced).
func (s *Store) ResourceChunkRowsForTest(id string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM resource_chunks WHERE resource_id = ?`, id).Scan(&n)
	return n, err
}

// chunkListPageSize is the fixed page size of the client-GC object inventory. A
// page is ids only (64 hex each), so this stays well under a MiB of JSON; the
// ?limit clamp of the row-listing endpoints would make a full-inventory read of a
// large account absurdly chatty, hence a per-endpoint constant instead.
const chunkListPageSize = 10000

// ListOwnerChunks returns one lexically-ordered page of every object id the owner
// stores, plus the cursor for the next page ("" on the last). This is the
// inventory a client prune diffs against the closure of its decrypted roots, so it
// must be complete — it deliberately has no filter.
func (s *Store) ListOwnerChunks(owner, cursor string) ([]string, string, error) {
	after := ""
	if cursor != "" {
		parts, err := decodeCursor(cursor, 1)
		if err != nil {
			return nil, "", err
		}
		after = parts[0]
	}
	rows, err := s.rdb.Query(
		`SELECT chunk_id FROM objects WHERE owner_handle = ? AND chunk_id > ?
		 ORDER BY chunk_id LIMIT ?`,
		owner, after, chunkListPageSize+1,
	)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(ids) > chunkListPageSize {
		ids = ids[:chunkListPageSize]
		next = encodeCursor(ids[len(ids)-1])
	}
	return ids, next, nil
}

// DeleteOwnerChunks drops the named objects: the client has computed reachability
// over its decrypted roots and these ids fell outside it. Only ids in packs older
// than minAge are dropped — a young pack's created_at was re-armed by CheckChunks
// on behalf of a push that is about to reference it, and deleting under it would
// strand that push's committed manifest. Skipped-young ids are counted, not
// failed, so a pruner retries them on its next run. resource_chunks rows naming a
// dropped id are removed in the same transaction — a reachable id is never handed
// to this function by a correct pruner, so such rows are stale scope, and leaving
// them would trip the objects FK. Unknown ids are ignored — another device's
// prune got there first.
//
// The GC lock serializes this against the pack sweep and repack, whose plans read
// object rows outside their commit transactions. After the row deletes, the
// fully-emptied aged packs are swept immediately so the response can report bytes
// actually freed.
func (s *Store) DeleteOwnerChunks(owner string, ids []string, minAge time.Duration) (deleted, skippedRecent int, freed int64, err error) {
	defer s.gcLocks.lock(owner)()
	cutoff := time.Now().Add(-minAge).Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var (
		drop     []string
		packSeen = map[string]bool{}
		packs    []string
	)
	const batch = 400 // the delete loop below reuses it; queryIDsBatched batches on its own
	err = queryIDsBatched(tx,
		`SELECT o.chunk_id, o.pack_id, p.created_at FROM objects o
		 JOIN packs p ON p.owner_handle = o.owner_handle AND p.pack_id = o.pack_id
		 WHERE o.owner_handle = ? AND o.chunk_id IN (`,
		[]any{owner}, ids,
		func(rows *sql.Rows) error {
			var (
				id, packID string
				createdAt  int64
			)
			if err := rows.Scan(&id, &packID, &createdAt); err != nil {
				return err
			}
			if createdAt >= cutoff {
				skippedRecent++
				return nil
			}
			drop = append(drop, id)
			if !packSeen[packID] {
				packSeen[packID] = true
				packs = append(packs, packID)
			}
			return nil
		},
	)
	if err != nil {
		return 0, 0, 0, err
	}
	if len(drop) == 0 {
		return 0, skippedRecent, 0, nil
	}
	var objectsDropped int64
	for _, table := range []string{"resource_chunks", "objects"} {
		for start := 0; start < len(drop); start += batch {
			end := min(start+batch, len(drop))
			group := drop[start:end]
			args := make([]any, 0, len(group)+1)
			args = append(args, owner)
			for _, id := range group {
				args = append(args, id)
			}
			res, err := tx.Exec(
				`DELETE FROM `+table+` WHERE owner_handle = ? AND chunk_id IN (`+placeholders(len(group))+`)`,
				args...,
			)
			if err != nil {
				return 0, 0, 0, err
			}
			if table == "objects" {
				n, _ := res.RowsAffected()
				objectsDropped += n
			}
		}
	}
	if err := addOwnerObjectCount(tx, owner, -objectsDropped); err != nil {
		return 0, 0, 0, err
	}
	if err := recountPacks(tx, owner, packs); err != nil {
		return 0, 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	deleted = len(drop)
	_, freed, err = s.GCPacks(owner, minAge)
	return deleted, skippedRecent, freed, err
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

// GCPacks deletes the owner's packs whose every object row is already gone — an
// `aqt prune` deleted them; the server never decides that on its own — and that
// were uploaded longer ago than minAge. The age guard keeps an in-flight push's
// freshly uploaded packs from being reaped before its manifest commits. Only
// fully-dead packs go here; dead objects inside a still-live pack are left to
// RepackOwner. Returns the pack count and bytes reclaimed.
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
	defer func() { _ = tx.Rollback() }()
	// A pack is dead once every one of its object rows has been deleted (a client
	// prune, or the resource churn that preceded it). obj_count is maintained inside
	// every transaction that moves object rows (see recountPacks), so selection
	// reads the packs table alone instead of joining every object row per sweep.
	rows, err := tx.Query(
		`SELECT pack_id, length FROM packs
		 WHERE owner_handle = ? AND created_at < ? AND obj_count = 0`,
		owner, cutoff,
	)
	if err != nil {
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
			_ = rows.Close()
			return 0, 0, err
		}
		dead = append(dead, d)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, 0, err
	}
	_ = rows.Close()

	var freed int64
	for _, d := range dead {
		// Objects FK-reference the pack, so they go first. A dead pack's objects are
		// by definition unreferenced by resource_chunks, so removing them cannot
		// violate that backstop.
		res, err := tx.Exec(`DELETE FROM objects WHERE owner_handle = ? AND pack_id = ?`, owner, d.id)
		if err != nil {
			return 0, 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			if err := addOwnerObjectCount(tx, owner, -n); err != nil {
				return 0, 0, err
			}
		}
		if _, err := tx.Exec(`DELETE FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, d.id); err != nil {
			return 0, 0, err
		}
		freed += d.length
	}
	if freed > 0 {
		if err := addOwnerPackBytes(tx, owner, -freed); err != nil {
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
// live data moves per call.
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
		newPath := s.packPath(owner, newID)
		cleanupRepack := func() error {
			exists, err := s.packExists(owner, newID)
			if err != nil {
				return err
			}
			if exists {
				return nil
			}
			if err := os.Remove(newPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove uncommitted repack %s: %w", newID, err)
			}
			return nil
		}
		if err := s.writePack(owner, newID, newPack); err != nil {
			if cleanupErr := cleanupRepack(); cleanupErr != nil {
				return repacked, reclaimed, errors.Join(err, cleanupErr)
			}
			return repacked, reclaimed, err
		}
		ok, freed, err := s.commitRepack(owner, cutoff, cand, newID, len(newPack), newIndex)
		if err != nil {
			if cleanupErr := cleanupRepack(); cleanupErr != nil {
				return repacked, reclaimed, errors.Join(err, cleanupErr)
			}
			return repacked, reclaimed, err
		}
		if !ok {
			// The plan went stale (the pack was touched, rooted differently, or
			// vanished). The new file is normally an orphan we just wrote, but a
			// content address can coincide with a pack a prior swap already committed,
			// so drop it only when no row references it — never a live pack's file.
			if cleanupErr := cleanupRepack(); cleanupErr != nil {
				return repacked, reclaimed, cleanupErr
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
// maintained per-pack counters alone: aged past cutoff, still holding objects, and
// at most repackMaxLiveFraction live — a deleted object loses its row entirely, so
// a sparse pack's dead bytes are the row-less holes and the live-bytes fraction is
// the whole economic filter. No object row is read here; the caller loads each
// candidate's live objects only when it actually processes that pack.
func (s *Store) repackCandidates(owner string, cutoff int64) ([]repackCand, error) {
	rows, err := s.rdb.Query(
		`SELECT pack_id, length, live_bytes FROM packs
		 WHERE owner_handle = ? AND created_at < ? AND obj_count > 0
		 ORDER BY pack_id`,
		owner, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

// packLiveObjects returns a pack's remaining objects in ascending offset order,
// plus their total bytes. Planning reads run on the read pool; commitRepack
// re-validates the set inside its transaction, so a concurrent delete between the
// two only makes the swap skip the pack.
func (s *Store) packLiveObjects(owner, packID string) ([]liveObj, int64, error) {
	rows, err := s.rdb.Query(
		`SELECT o.chunk_id, o."offset", o.length FROM objects o
		 WHERE o.owner_handle = ? AND o.pack_id = ?
		 ORDER BY o."offset"`,
		owner, packID,
	)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
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
// planning. freed is the bytes the swap reclaimed: the old pack's size, less the new
// pack's when the swap actually added it (a content address can land on a pack that
// already exists, whose bytes are already counted).
func (s *Store) commitRepack(owner string, cutoff int64, cand repackCand, newID string, newLen int, newIndex []api.PackIndexEntry) (ok bool, freed int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	// Take SQLite's cross-process writer lock before validating the plan. Without
	// this no-op write, an admin process can delete and commit after these reads,
	// leaving this deferred transaction to fail with SQLITE_BUSY after its new pack
	// file was already written.
	accountLock, err := tx.Exec(`UPDATE accounts SET owner_handle = owner_handle WHERE owner_handle = ?`, owner)
	if err != nil {
		return false, 0, err
	}
	accountRows, err := accountLock.RowsAffected()
	if err != nil {
		return false, 0, err
	}
	if accountRows == 0 {
		return false, 0, nil
	}
	var curCreated, curLen int64
	err = tx.QueryRow(`SELECT created_at, length FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID).Scan(&curCreated, &curLen)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	if curCreated >= cutoff {
		return false, 0, nil // re-armed age guard: an in-flight read may still use this pack
	}
	liveNow := map[string]bool{}
	lrows, err := tx.Query(
		`SELECT o.chunk_id FROM objects o
		 WHERE o.owner_handle = ? AND o.pack_id = ?`,
		owner, cand.packID,
	)
	if err != nil {
		return false, 0, err
	}
	for lrows.Next() {
		var id string
		if err := lrows.Scan(&id); err != nil {
			_ = lrows.Close()
			return false, 0, err
		}
		liveNow[id] = true
	}
	if err := lrows.Err(); err != nil {
		_ = lrows.Close()
		return false, 0, err
	}
	_ = lrows.Close()

	// The new pack was built from the planned object set; if a concurrent delete
	// changed it, the new pack no longer matches the objects to move, so abandon.
	if len(liveNow) != len(newIndex) {
		return false, 0, nil
	}
	for _, e := range newIndex {
		if !liveNow[e.ID] {
			return false, 0, nil
		}
	}

	now := time.Now().Unix()
	// DO NOTHING (not DO UPDATE) so RowsAffected distinguishes a first store from a
	// collision with a pack that already exists, exactly as PutPack does: only a new
	// row adds bytes to the owner's counter.
	ins, err := tx.Exec(
		`INSERT INTO packs(owner_handle, pack_id, length, created_at) VALUES(?,?,?,?)
		 ON CONFLICT(owner_handle, pack_id) DO NOTHING`,
		owner, newID, newLen, now,
	)
	if err != nil {
		return false, 0, err
	}
	inserted, _ := ins.RowsAffected()
	if inserted == 0 {
		// Re-arm the existing pack's GC age guard, which the prior DO UPDATE did.
		if _, err := tx.Exec(
			`UPDATE packs SET created_at = ? WHERE owner_handle = ? AND pack_id = ?`, now, owner, newID,
		); err != nil {
			return false, 0, err
		}
	}
	// Re-point each live object onto the new pack before deleting the old one, so the
	// objects FK never dangles. chunk_id is unchanged, so resource_chunks stays valid.
	for _, e := range newIndex {
		if _, err := tx.Exec(
			`UPDATE objects SET pack_id = ?, "offset" = ?, length = ? WHERE owner_handle = ? AND chunk_id = ?`,
			newID, e.Off, e.Len, owner, e.ID,
		); err != nil {
			return false, 0, err
		}
	}
	// The old pack now holds only dead objects (the live ones moved); remove them and
	// the pack row.
	res, err := tx.Exec(`DELETE FROM objects WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID)
	if err != nil {
		return false, 0, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if err := addOwnerObjectCount(tx, owner, -n); err != nil {
			return false, 0, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM packs WHERE owner_handle = ? AND pack_id = ?`, owner, cand.packID); err != nil {
		return false, 0, err
	}
	// The moved objects now count against the new pack (which may pre-exist with
	// other objects, via the ON CONFLICT above), so recount it in the same tx.
	if err := recountPacks(tx, owner, []string{newID}); err != nil {
		return false, 0, err
	}
	// The swap dropped curLen, and added newLen only if it minted the new pack row: a
	// pre-existing row's length is already on the owner's counter, so adding it again
	// would over-charge the quota permanently (addOwnerPackBytes has no ceiling).
	var added int64
	if inserted > 0 {
		added = int64(newLen)
	}
	if err := addOwnerPackBytes(tx, owner, added-curLen); err != nil {
		return false, 0, err
	}
	if err := tx.Commit(); err != nil {
		return false, 0, err
	}
	return true, curLen - added, nil
}
