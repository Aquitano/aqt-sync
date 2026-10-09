// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"errors"
	"strings"
	"testing"
)

// A recovery key is typed back in by hand, possibly years later: it must survive the
// ways people retype it and reject a typo as a typo.
func TestRecoveryKeyEncoding(t *testing.T) {
	var key RecoveryKey
	for i := range key {
		key[i] = byte(i * 7)
	}
	encoded := key.Encode()
	retyped := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(encoded, "-", " "), "0", "o"))
	for _, s := range []string{encoded, retyped, "  " + encoded + "\n"} {
		got, err := ParseRecoveryKey(s)
		if err != nil || got != key {
			t.Fatalf("ParseRecoveryKey(%q) = %x, %v; want the original key", s, got, err)
		}
	}
	typo := []byte(encoded)
	if typo[0] == 'A' {
		typo[0] = 'B'
	} else {
		typo[0] = 'A'
	}
	if _, err := ParseRecoveryKey(string(typo)); !errors.Is(err, ErrRecoveryKeyTypo) {
		t.Fatalf("a one-character typo parsed: %v", err)
	}
	if _, err := ParseRecoveryKey(encoded[:len(encoded)-1]); !errors.Is(err, ErrRecoveryKeyTypo) {
		t.Fatalf("a truncated key parsed: %v", err)
	}
}
