// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"errors"
	"testing"
)

func TestParseVersionAcceptsOnlyExactSemanticVersions(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"v0.3.0", "v0.3.0"},
		{"0.3.0", "v0.3.0"},
		{"v1.2.3-rc.1", "v1.2.3-rc.1"},
		{"v1.2.3-0.beta", "v1.2.3-0.beta"},
		{"v1.2.3+build.5", "v1.2.3+build.5"},
		{"v1.2.3-rc.1+build.5", "v1.2.3-rc.1+build.5"},
		{"v10.20.30", "v10.20.30"},
	}
	for _, tc := range valid {
		v, err := ParseVersion(tc.in)
		if err != nil {
			t.Errorf("ParseVersion(%q): %v", tc.in, err)
			continue
		}
		if got := v.String(); got != tc.want {
			t.Errorf("ParseVersion(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
	}

	// A version that is merely version-shaped is a packaging bug. Accepting it would
	// mean comparing the running build against a release nobody published.
	invalid := []string{
		"", "v", "v1", "v1.2", "v1.2.3.4", "1.2.x", "v01.2.3", "v1.02.3",
		"v1.2.3-", "v1.2.3-01", "v1.2.3-rc..1", "v1.2.3+", "v1.2.3 ",
		" v1.2.3", "v1.2.3-rc!1", "release-1.2.3", "v-1.2.3",
		"v99999999999999999999.0.0",
	}
	for _, in := range invalid {
		if v, err := ParseVersion(in); err == nil {
			t.Errorf("ParseVersion(%q) = %v, want an error", in, v)
		} else if !errors.Is(err, ErrBadVersion) {
			t.Errorf("ParseVersion(%q) error is %v, want ErrBadVersion", in, err)
		}
	}
}

func TestCompareFollowsSemanticVersionPrecedence(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.0.0", "v1.0.0", 0},
		{"v1.0.1", "v1.0.0", 1},
		{"v1.1.0", "v1.0.9", 1},
		{"v2.0.0", "v1.99.99", 1},
		{"v1.0.0-rc.1", "v1.0.0", -1}, // a prerelease sorts below its release
		{"v1.0.0-rc.1", "v1.0.0-rc.2", -1},
		{"v1.0.0-rc.2", "v1.0.0-rc.10", -1}, // numeric identifiers compare as numbers
		{"v1.0.0-alpha", "v1.0.0-beta", -1},
		{"v1.0.0-alpha.1", "v1.0.0-alpha", 1}, // more identifiers outrank fewer
		{"v1.0.0-1", "v1.0.0-alpha", -1},      // numeric ranks below alphanumeric
		{"v1.0.0+meta", "v1.0.0", 0},          // build metadata is not part of precedence
	}
	for _, tc := range cases {
		a, err := ParseVersion(tc.a)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tc.a, err)
		}
		b, err := ParseVersion(tc.b)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tc.b, err)
		}
		if got := Compare(a, b); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := Compare(b, a); got != -tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestIsPrereleaseSeparatesChannels(t *testing.T) {
	for in, want := range map[string]bool{
		"v0.3.0":       false,
		"v0.3.0+meta":  false,
		"v0.4.0-rc.1":  true,
		"v0.4.0-beta1": true,
	} {
		v, err := ParseVersion(in)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", in, err)
		}
		if got := v.IsPrerelease(); got != want {
			t.Errorf("%q IsPrerelease = %v, want %v", in, got, want)
		}
	}
}
