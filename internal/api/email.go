// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "strings"

// NormalizeEmail is the one canonical form an account email takes on the wire and
// in storage: trimmed and lower-cased. The client and server must agree on it —
// the client compares emails case-insensitively, so a server that binary-collated
// would hand `User@X.com` the decoy salt (and a "wrong passphrase" dead end) and
// could hold mixed-case rows for one mailbox that cross-write key material.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
