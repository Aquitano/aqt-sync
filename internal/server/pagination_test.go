package server

import "testing"

// A grantee handle is deliberately unvalidated (a decoy handle must be
// indistinguishable from a real one), so a cursor part can contain the separator
// itself. Escaping must survive that rather than splitting into an extra field.
func TestCursorPartsSurviveSeparatorBytes(t *testing.T) {
	for _, parts := range [][]string{
		{"1700000000", "handle\x1fwith-sep"},
		{"1700000000", "handle\x1ewith-esc"},
		{"1700000000", "\x1e\x1f\x1e\x1fboth"},
		{"", ""},
	} {
		got, err := decodeCursor(encodeCursor(parts...), len(parts))
		if err != nil {
			t.Fatalf("decodeCursor(encodeCursor(%q)) = %v", parts, err)
		}
		if len(got) != len(parts) {
			t.Fatalf("round trip of %q gave %d parts, want %d", parts, len(got), len(parts))
		}
		for i := range parts {
			if got[i] != parts[i] {
				t.Fatalf("part %d round-tripped to %q, want %q", i, got[i], parts[i])
			}
		}
	}
}
