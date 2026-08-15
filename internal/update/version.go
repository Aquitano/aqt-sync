// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrBadVersion means a version string is not an exact semantic version.
var ErrBadVersion = errors.New("malformed version")

// Version is a strict semantic version. A partial version ("v1.2") is rejected
// rather than interpreted: release metadata that omits a component is a packaging
// bug, and guessing what it meant is how a client ends up comparing against the
// wrong release.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 string // prerelease identifiers, without the leading '-'
	Build               string // build metadata, ignored when comparing
}

// ParseVersion parses "v1.2.3", "1.2.3-rc.1", "v1.2.3+meta" and rejects anything
// else. The leading "v" is optional on input; String always emits it, matching the
// release tags.
func ParseVersion(s string) (Version, error) {
	raw := s
	bad := func() (Version, error) { return Version{}, fmt.Errorf("%w %q", ErrBadVersion, raw) }

	s = strings.TrimPrefix(s, "v")
	var v Version
	if i := strings.IndexByte(s, '+'); i >= 0 {
		v.Build, s = s[i+1:], s[:i]
		if !validIdentifiers(v.Build, false) {
			return bad()
		}
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.Pre, s = s[i+1:], s[:i]
		if !validIdentifiers(v.Pre, true) {
			return bad()
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return bad()
	}
	nums := make([]uint64, 3)
	for i, p := range parts {
		n, ok := parseNumeric(p)
		if !ok {
			return bad()
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	if v.Build != "" {
		s += "+" + v.Build
	}
	return s
}

// IsPrerelease reports whether this version carries a prerelease suffix, which is
// what keeps a beta off the stable channel.
func (v Version) IsPrerelease() bool { return v.Pre != "" }

// Compare orders two versions per the semantic versioning precedence rules: build
// metadata is ignored, and a prerelease sorts before its own release.
func Compare(a, b Version) int {
	if c := cmpUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	switch {
	case a.Pre == "" && b.Pre == "":
		return 0
	case a.Pre == "":
		return 1
	case b.Pre == "":
		return -1
	}
	return comparePrerelease(a.Pre, b.Pre)
}

func comparePrerelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aNum := parseNumeric(as[i])
		bn, bNum := parseNumeric(bs[i])
		switch {
		case aNum && bNum:
			if c := cmpUint(an, bn); c != 0 {
				return c
			}
		case aNum:
			return -1 // numeric identifiers rank below alphanumeric ones
		case bNum:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return cmpUint(uint64(len(as)), uint64(len(bs)))
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// parseNumeric accepts a numeric identifier: digits only, no leading zero, and
// short enough that it cannot overflow.
func parseNumeric(s string) (uint64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// validIdentifiers checks a dot-separated prerelease or build-metadata string.
// numericRules applies the no-leading-zero rule, which binds prerelease
// identifiers but not build metadata.
func validIdentifiers(s string, numericRules bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		digits := true
		for i := 0; i < len(id); i++ {
			c := id[i]
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				digits = false
			default:
				return false
			}
		}
		if digits && numericRules {
			if _, ok := parseNumeric(id); !ok {
				return false
			}
		}
	}
	return true
}
