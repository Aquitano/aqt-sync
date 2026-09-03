// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"errors"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// The SQLite failures the store turns into its own errors, matched on the driver's
// extended result code rather than on the message text. The codes are SQLite's own
// ABI, so they survive a message rewording, and an error from anywhere else cannot
// satisfy one by accident. The driver enables extended result codes on every
// connection, so the specific constraint is always available.

func sqliteCode(err error, code int) bool {
	var serr *sqlite.Error
	return errors.As(err, &serr) && serr.Code() == code
}

// isForeignKeyViolation reports a foreign-key failure specifically, not the whole
// SQLITE_CONSTRAINT family it shares with UNIQUE, NOT NULL, and CHECK.
func isForeignKeyViolation(err error) bool {
	return sqliteCode(err, sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY)
}

// isUnique reports a UNIQUE violation specifically. NOT NULL and CHECK failures
// are server bugs and must not reach a caller as a duplicate, so they get their own
// codes here and never match. A PRIMARY KEY collision reports the distinct code
// SQLITE_CONSTRAINT_PRIMARYKEY and is deliberately not covered: the only caller is
// CreateAccount, whose handle is random, so a colliding primary key is a bug rather
// than the duplicate-account case this answers.
func isUnique(err error) bool {
	return sqliteCode(err, sqlite3.SQLITE_CONSTRAINT_UNIQUE)
}

// isMissingTable reports a statement naming a table the schema does not have.
// SQLite has no dedicated code for it — every statement-preparation failure is a
// bare SQLITE_ERROR — so the message is what separates a missing table from a
// syntax error, and the code only bounds the match to that class of SQLite error.
func isMissingTable(err error) bool {
	return sqliteCode(err, sqlite3.SQLITE_ERROR) && strings.Contains(err.Error(), "no such table")
}
