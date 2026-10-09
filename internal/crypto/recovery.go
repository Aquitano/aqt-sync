// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// RecoveryKey is a random secret that unwraps the account root key in place of the
// passphrase. Being random, it needs no Argon2id: HKDF turns it into the unlock key
// its wrap is sealed under, and that wrap is as hard to open offline as any other
// 256-bit key.
type RecoveryKey [KeySize]byte

// recoveryChecksumSize bytes of SHA-256 ride along in the encoded key, so a typo is
// reported as one instead of as an unlock failure the decoy bootstrap makes
// indistinguishable from "no such account".
const recoveryChecksumSize = 2

// Crockford's alphabet has no I, L, O, or U, so ParseRecoveryKey can read the
// letters people confuse with digits as the digits they meant.
var recoveryEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// ErrRecoveryKeyTypo means a recovery key failed its checksum or did not decode.
var ErrRecoveryKeyTypo = errors.New("that is not a valid recovery key; a character is wrong or missing")

// GenerateRecoveryKey returns a fresh random recovery key.
func GenerateRecoveryKey() (RecoveryKey, error) {
	var k RecoveryKey
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("generate recovery key: %w", err)
	}
	return k, nil
}

// Wipe best-effort zeroes the recovery key (see MasterKey.Wipe for the caveats).
func (k *RecoveryKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// UnlockKey derives the key the account's recovery wrap is sealed under, for
// WrapRoot, UnwrapRoot, and DeriveAuthVerifier.
func (k RecoveryKey) UnlockKey() UnlockKey {
	var uk UnlockKey
	copy(uk[:], derive(k[:], nil, "aqt-recovery-unlock-v1"))
	return uk
}

// Encode renders the key for a person to write down: Crockford base32 of the key
// and its checksum, in dash-separated groups of five.
func (k RecoveryKey) Encode() string {
	sum := sha256.Sum256(k[:])
	raw := recoveryEncoding.EncodeToString(append(k[:], sum[:recoveryChecksumSize]...))
	var groups []string
	for len(raw) > 5 {
		groups = append(groups, raw[:5])
		raw = raw[5:]
	}
	return strings.Join(append(groups, raw), "-")
}

// ParseRecoveryKey reads a key as Encode wrote it, forgiving case, spacing, dashes,
// and the letters Crockford folds into digits.
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	var k RecoveryKey
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t':
			return -1
		case 'O':
			return '0'
		case 'I', 'L':
			return '1'
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(s)))
	raw, err := recoveryEncoding.DecodeString(cleaned)
	if err != nil || len(raw) != KeySize+recoveryChecksumSize {
		return k, ErrRecoveryKeyTypo
	}
	sum := sha256.Sum256(raw[:KeySize])
	if subtle.ConstantTimeCompare(sum[:recoveryChecksumSize], raw[KeySize:]) != 1 {
		return k, ErrRecoveryKeyTypo
	}
	copy(k[:], raw[:KeySize])
	return k, nil
}
