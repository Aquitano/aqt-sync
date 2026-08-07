package server

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AdminAccount is the operator's view of one account: its identity, what it is
// storing, and the two per-account policies an operator controls. It carries no
// key material and no plaintext — the server holds neither.
type AdminAccount struct {
	OwnerHandle string
	Email       string
	CreatedAt   time.Time
	// DisabledAt is zero while the account is active.
	DisabledAt time.Time
	// QuotaBytes is the per-account override. Absent means the account inherits
	// the server-wide AQT_QUOTA_BYTES; present and 0 means explicitly unlimited.
	QuotaBytes sql.NullInt64
	Usage      AccountUsage
}

// Disabled reports whether an operator has suspended the account.
func (a AdminAccount) Disabled() bool { return !a.DisabledAt.IsZero() }

// EffectiveQuota resolves the byte cap that actually applies, given the
// server-wide default. 0 means unlimited, matching ServerConfig.QuotaBytes.
func (a AdminAccount) EffectiveQuota(serverDefault int64) int64 {
	if a.QuotaBytes.Valid {
		return a.QuotaBytes.Int64
	}
	return serverDefault
}

// ErrAmbiguousAccount means an account reference matched more than one account, so
// acting on it would be a guess. Only possible for a prefix; an email or a full
// handle is unique by construction.
var ErrAmbiguousAccount = errors.New("account reference is ambiguous")

// ErrAccountDisabled means the account has been suspended by an operator. The
// authenticated routes map it to 403 rather than 401: the credential is valid, so
// telling the user to log in again would send them in a circle.
var ErrAccountDisabled = errors.New("account is disabled; contact the server operator")

// SuspensionLag is how long a running server may keep serving an account that
// another process just suspended. Operator tooling reports it rather than claiming
// the change is instant.
func SuspensionLag() time.Duration { return suspensionTTL }

// ListAdminAccounts returns every account with its usage, oldest first. Intended
// for operator tooling and reporting, never for a request handler: it walks every
// account's usage, which is O(accounts) usage queries.
func (s *Store) ListAdminAccounts() ([]AdminAccount, error) {
	rows, err := s.rdb.Query(
		`SELECT owner_handle, email, created_at, disabled_at, quota_bytes
		 FROM accounts ORDER BY created_at, owner_handle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AdminAccount
	for rows.Next() {
		a, err := scanAdminAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		u, err := s.AccountUsage(out[i].OwnerHandle)
		if err != nil {
			return nil, fmt.Errorf("usage for %s: %w", out[i].OwnerHandle, err)
		}
		out[i].Usage = u
	}
	return out, nil
}

// AdminAccountByRef resolves an operator's account reference: an exact email, an
// exact owner handle, or an unambiguous handle prefix. A prefix matching more than
// one account is ErrAmbiguousAccount rather than an arbitrary pick — every admin
// verb below is destructive or policy-changing, so guessing is not acceptable.
func (s *Store) AdminAccountByRef(ref string) (AdminAccount, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return AdminAccount{}, ErrNotFound
	}
	row := s.rdb.QueryRow(
		`SELECT owner_handle, email, created_at, disabled_at, quota_bytes
		 FROM accounts WHERE email = ? OR owner_handle = ?`, ref, ref)
	a, err := scanAdminAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		if a, err = s.adminAccountByPrefix(ref); err != nil {
			return AdminAccount{}, err
		}
	} else if err != nil {
		return AdminAccount{}, err
	}
	if a.Usage, err = s.AccountUsage(a.OwnerHandle); err != nil {
		return AdminAccount{}, err
	}
	return a, nil
}

func (s *Store) adminAccountByPrefix(prefix string) (AdminAccount, error) {
	// LIKE would treat _ and % in the reference as wildcards; a handle is
	// base64url, so compare the prefix directly instead.
	rows, err := s.rdb.Query(
		`SELECT owner_handle, email, created_at, disabled_at, quota_bytes
		 FROM accounts WHERE substr(owner_handle, 1, ?) = ? ORDER BY owner_handle LIMIT 2`,
		len(prefix), prefix)
	if err != nil {
		return AdminAccount{}, err
	}
	defer rows.Close()

	var matches []AdminAccount
	for rows.Next() {
		a, err := scanAdminAccount(rows)
		if err != nil {
			return AdminAccount{}, err
		}
		matches = append(matches, a)
	}
	if err := rows.Err(); err != nil {
		return AdminAccount{}, err
	}
	switch len(matches) {
	case 0:
		return AdminAccount{}, ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return AdminAccount{}, ErrAmbiguousAccount
	}
}

func scanAdminAccount(row interface{ Scan(...any) error }) (AdminAccount, error) {
	var (
		a          AdminAccount
		created    sql.NullInt64
		disabledAt int64
	)
	if err := row.Scan(&a.OwnerHandle, &a.Email, &created, &disabledAt, &a.QuotaBytes); err != nil {
		return AdminAccount{}, err
	}
	if created.Valid && created.Int64 > 0 {
		a.CreatedAt = time.Unix(created.Int64, 0).UTC()
	}
	if disabledAt > 0 {
		a.DisabledAt = time.Unix(disabledAt, 0).UTC()
	}
	return a, nil
}

// SetAccountQuota sets or clears the per-account byte cap. A nil quota clears the
// override so the account inherits the server default again; 0 is an explicit
// "unlimited", which is why the column is nullable rather than defaulting to 0.
func (s *Store) SetAccountQuota(owner string, quota *int64) error {
	var value any
	if quota != nil {
		if *quota < 0 {
			return errors.New("quota must not be negative")
		}
		value = *quota
	}
	res, err := s.db.Exec(`UPDATE accounts SET quota_bytes = ? WHERE owner_handle = ?`, value, owner)
	return affectedOne(res, err)
}

// SetAccountDisabled suspends or restores an account. Suspension is a policy flag
// only: no ciphertext is touched and no key is destroyed, so it is fully
// reversible. A server running in *another* process picks the change up within
// suspensionTTL; this process's own cache is invalidated immediately.
func (s *Store) SetAccountDisabled(owner string, disabled bool) error {
	var at int64
	if disabled {
		at = time.Now().Unix()
	}
	res, err := s.db.Exec(`UPDATE accounts SET disabled_at = ? WHERE owner_handle = ?`, at, owner)
	if err := affectedOne(res, err); err != nil {
		return err
	}
	s.suspended.invalidate(owner)
	return nil
}

// AccountDisabled reports whether the account is suspended. It is on the
// authenticated hot path, so it reads one indexed column rather than the full
// admin row.
func (s *Store) AccountDisabled(owner string) (bool, error) {
	var at int64
	err := s.rdb.QueryRow(`SELECT disabled_at FROM accounts WHERE owner_handle = ?`, owner).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	return at > 0, err
}

// AccountQuota returns the per-account byte-cap override, if one is set.
func (s *Store) AccountQuota(owner string) (sql.NullInt64, error) {
	var quota sql.NullInt64
	err := s.rdb.QueryRow(`SELECT quota_bytes FROM accounts WHERE owner_handle = ?`, owner).Scan(&quota)
	if errors.Is(err, sql.ErrNoRows) {
		return quota, ErrNotFound
	}
	return quota, err
}

// DeletedAccount reports what erasing an account actually removed, so the operator
// gets a receipt rather than a bare "ok".
type DeletedAccount struct {
	OwnerHandle string
	Email       string
	Resources   int64
	Snapshots   int64
	Devices     int64
	Packs       int64
	Objects     int64
	Grants      int64
	Bytes       int64
	// FileErrors are blobs or packs whose rows were deleted but whose files could
	// not be removed. The database is authoritative, so the account is gone either
	// way; these are orphaned files an operator must clean up by hand.
	FileErrors []string
}

// DeleteAccount erases an account and everything attributable to it. The row
// deletions commit as one transaction, so the account never half-exists; the files
// are removed afterwards, because a rollback cannot restore an unlinked file and
// an orphaned file is the recoverable direction of that trade.
//
// Grants *to* this account from other owners are removed too: the grantee's
// published key is going away, so the wrap becomes unopenable and keeping it would
// leave the granter listing a share nobody can read.
func (s *Store) DeleteAccount(owner string) (DeletedAccount, error) {
	var acct DeletedAccount

	// Collect the blob files before the rows naming them are gone. Packs need no
	// such pass: they live under a single owner-scoped directory tree.
	blobs, err := s.accountBlobPaths(owner)
	if err != nil {
		return acct, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return acct, err
	}
	defer tx.Rollback()

	if err := tx.QueryRow(`SELECT owner_handle, email FROM accounts WHERE owner_handle = ?`, owner).
		Scan(&acct.OwnerHandle, &acct.Email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return acct, ErrNotFound
		}
		return acct, err
	}

	// Ordered children-before-parent: the accounts row is the FK target for
	// devices and resources, so it must go last.
	for _, step := range []struct {
		table string
		stmt  string
		count *int64
	}{
		{"grants", `DELETE FROM grants WHERE owner_handle = ? OR grantee_handle = ?`, &acct.Grants},
		{"snapshot_chunks", `DELETE FROM snapshot_chunks WHERE owner_handle = ?`, nil},
		{"resource_chunks", `DELETE FROM resource_chunks WHERE owner_handle = ?`, nil},
		{"snapshots", `DELETE FROM snapshots WHERE owner_handle = ?`, &acct.Snapshots},
		{"resources", `DELETE FROM resources WHERE owner_handle = ?`, &acct.Resources},
		{"objects", `DELETE FROM objects WHERE owner_handle = ?`, &acct.Objects},
		{"packs", `DELETE FROM packs WHERE owner_handle = ?`, &acct.Packs},
		{"devices", `DELETE FROM devices WHERE owner_handle = ?`, &acct.Devices},
		{"idempotency_keys", `DELETE FROM idempotency_keys WHERE owner_handle = ?`, nil},
		{"accounts", `DELETE FROM accounts WHERE owner_handle = ?`, nil},
	} {
		args := []any{owner}
		if strings.Count(step.stmt, "?") == 2 {
			args = append(args, owner)
		}
		res, err := tx.Exec(step.stmt, args...)
		if err != nil {
			// A data dir predating one of these tables is not a reason to refuse the
			// deletion; the rest of the erasure still has to happen.
			if isMissingTable(err) {
				continue
			}
			return acct, fmt.Errorf("delete %s: %w", step.table, err)
		}
		if step.count != nil {
			n, _ := res.RowsAffected()
			*step.count = n
		}
	}
	if err := tx.Commit(); err != nil {
		return acct, err
	}
	s.auth.invalidateOwner(owner)

	for _, path := range blobs {
		if info, err := os.Stat(path); err == nil {
			acct.Bytes += info.Size()
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			acct.FileErrors = append(acct.FileErrors, fmt.Sprintf("%s: %v", path, err))
		}
	}
	// Every pack the account ever stored lives under one owner-scoped tree, so this
	// also sweeps packs whose rows a prior GC removed but whose files it left.
	packDir := filepath.Join(s.packsDir, owner)
	acct.Bytes += treeSize(packDir)
	if err := os.RemoveAll(packDir); err != nil && !os.IsNotExist(err) {
		acct.FileErrors = append(acct.FileErrors, fmt.Sprintf("%s: %v", packDir, err))
	}
	return acct, nil
}

// accountBlobPaths lists every blob file belonging to the account's resources and
// snapshots. It globs each id's fan-out directory rather than addressing the live
// nonce alone: a reseal writes a new nonce-addressed file, so an id can still have
// superseded files on disk, and an erasure that left those behind would leave real
// ciphertext for a deleted account.
func (s *Store) accountBlobPaths(owner string) ([]string, error) {
	rows, err := s.rdb.Query(
		`SELECT id FROM resources WHERE owner_handle = ?
		 UNION
		 SELECT snapshot_id FROM snapshots WHERE owner_handle = ?`, owner, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		matches, err := filepath.Glob(filepath.Join(s.blobDir(id), id+".*.bin"))
		if err != nil {
			return nil, err
		}
		out = append(out, matches...)
	}
	return out, rows.Err()
}

func treeSize(dir string) int64 {
	var total int64
	// A walk error means the file is already gone or unreadable; the caller reports
	// removal failures separately, so the size is best-effort.
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func affectedOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func isMissingTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
