// SPDX-License-Identifier: AGPL-3.0-or-later

package safetext

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCleanDropsControlBytes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, in, want string
	}{
		{"plain text passes", "upgrade aqt", "upgrade aqt"},
		{"escape sequences are dropped", "safe\x1b[2Kforged", "safe[2Kforged"},
		{"newlines cannot forge a line", "line one\nerror: fake", "line oneerror: fake"},
		{"carriage return is dropped", "real\rfake", "realfake"},
		{"nul is dropped", "a\x00b", "ab"},
		{"c1 controls are dropped", "a\u009bb", "ab"},
		{"tabs become spaces", "a\tb", "a b"},
		{"non-ascii text survives", "Rechnung März.pdf", "Rechnung März.pdf"},
		{"bidi override is dropped", "invoice\u202egpj.exe", "invoicegpj.exe"},
		{"bidi isolates are dropped", "\u2066safe\u2069\u2068forged\u2069", "safeforged"},
		{"right-to-left mark is dropped", "a\u200fb", "ab"},
		{"zero-width space is dropped", "a\u200bb", "ab"},
		{"line separator cannot forge a line", "one\u2028error: fake", "oneerror: fake"},
		// The joiners are the two format controls Clean keeps: without them a family
		// emoji falls apart into its members and Persian text loses its word breaks.
		{"joiners survive", "\U0001f468\u200d\U0001f469\u200d\U0001f467", "\U0001f468\u200d\U0001f469\u200d\U0001f467"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Clean(tc.in, DisplayMax); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCleanIsBounded(t *testing.T) {
	t.Parallel()
	got := Clean(strings.Repeat("x", 500), 32)
	if len([]rune(got)) > 33 { // 32 plus the ellipsis
		t.Fatalf("got %d runes, want at most 33", len([]rune(got)))
	}
}

// The bound counts bytes, so a multi-byte rune can straddle it; cutting mid-rune
// would turn valid UTF-8 into replacement characters on screen.
func TestCleanNeverSplitsARune(t *testing.T) {
	t.Parallel()
	for cut := 1; cut <= 16; cut++ {
		got := Clean(strings.Repeat("é", 16), cut)
		if !utf8.ValidString(got) {
			t.Fatalf("bound %d produced invalid UTF-8: %q", cut, got)
		}
	}
}

// FuzzClean holds Clean's output contract on arbitrary input, since everything it
// sees came from someone else: valid UTF-8, within the byte bound plus the ellipsis,
// and no rune that moves the cursor, starts an escape, or reorders what follows.
func FuzzClean(f *testing.F) {
	f.Add("safe\x1b[2Kforged", 200)
	f.Add("abc\u202edcba\u2066x\u2069", 5)
	f.Add("\u200dzwj\u200czwnj\u2028\u2029", 200)
	f.Add("\xff\xfe\x85\u0085", 1)
	f.Fuzz(func(t *testing.T, s string, maxLen int) {
		if maxLen < 0 {
			return // every caller passes DisplayMax
		}
		got := Clean(s, maxLen)
		if !utf8.ValidString(got) {
			t.Fatalf("Clean(%q, %d) = %q, not valid UTF-8", s, maxLen, got)
		}
		if len(got) > maxLen+len("…") {
			t.Fatalf("Clean(%q, %d) is %d bytes", s, maxLen, len(got))
		}
		for _, r := range strings.TrimSuffix(got, "…") {
			unsafe := r < 0x20 || (r >= 0x7f && r <= 0x9f) ||
				(unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) && r != '\u200c' && r != '\u200d')
			if unsafe {
				t.Fatalf("Clean(%q, %d) kept %U", s, maxLen, r)
			}
		}
	})
}
