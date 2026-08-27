// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"regexp"
	"strings"
	"testing"
)

// compileRuleRegexpOnly mirrors compileRule but always takes the regexp path. It
// is the reference the classified kinds must agree with: the fast paths exist for
// speed, and any divergence from the regexp semantics is a bug in them.
func compileRuleRegexpOnly(line string) (ignoreRule, bool) {
	line = strings.TrimRight(line, " ")
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var r ignoreRule
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	anchored := strings.HasPrefix(line, "/") || strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	expr := translateGlob(line)
	if anchored {
		expr = "^" + expr + "$"
	} else {
		expr = "(^|/)" + expr + "$"
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return ignoreRule{}, false
	}
	r.re = re
	return r, true
}

func diffRuleAgainstRegexp(t *testing.T, rule, path string) {
	t.Helper()
	fast, okFast := compileRule(rule)
	ref, okRef := compileRuleRegexpOnly(rule)
	if okFast != okRef {
		t.Fatalf("rule %q: classified compile ok=%v, regexp ok=%v", rule, okFast, okRef)
	}
	if !okFast {
		return
	}
	if fast.negate != ref.negate || fast.dirOnly != ref.dirOnly {
		t.Fatalf("rule %q: flags diverge (negate %v/%v, dirOnly %v/%v)",
			rule, fast.negate, ref.negate, fast.dirOnly, ref.dirOnly)
	}
	if got, want := fast.matches(path), ref.re.MatchString(path); got != want {
		t.Fatalf("rule %q path %q: classified kind %d = %v, regexp = %v",
			rule, path, fast.kind, got, want)
	}
}

var ignoreDiffRules = []string{
	// literals, bare and anchored, with the markers in every combination
	"name", "/dist", "a/b", "dist/", "/build/", "!keep.log", "!.git/", "sub/.git",
	// edge globs the fast path claims
	"*.log", "*X", ".aqt-tmp-*", "tmp*", "X*", "*",
	// genuine globs that must stay on the regexp
	"a*b", "*a*", "**", "**/foo", "a/**/b", "a?c", "??", "/dist*", "a/b*", "*.l?g",
	// metacharacters translateGlob escapes: literal strings under both matchers
	"x[a-z]", "a+b", "a.b", "(x)", "a|b", "^a$", "{x}", "\\bad", "a\\*b",
	// degenerate and odd lines
	"!", "/", "//", "#comment", "", "  ", "name ", "..", "café", "\xff\xfe", "a\xffb*",
}

var ignoreDiffPaths = []string{
	"", "name", "x/name", "namex", "x/namex/y", "Name", "a/b", "a/b/c", "b",
	"dist", "dist/x.js", "x/dist", "build", "build/x", "keep.log", "x/keep.log",
	"x.log", "deep/x.log", "xlog", "tmpfile", "x/tmp", "x/tmpy", "aXb", "aX",
	"x[a-z]", "a+b", "a.b", "azb", "aab", "(x)", "a|b", "^a$", "\\bad", "a*b",
	".git", "sub/.git", "sub/x/.git", "café", "caf\xc3", "\xff", "a\nb", "a\xffb",
	".aqt-tmp-123", "x/.aqt-tmp-", "foo", "deep/foo", "a/x/b", "a/b/x",
}

// Every classified rule kind must answer exactly as its regexp form would, across
// rules and paths chosen to hit the traps: anchored rules are equality (never
// prefix), escaped metacharacters are literals, invalid UTF-8 drops the rule under
// both compilers, and subjects may be arbitrary bytes.
func TestIgnoreClassifiedKindsMatchRegexp(t *testing.T) {
	for _, rule := range ignoreDiffRules {
		for _, path := range ignoreDiffPaths {
			diffRuleAgainstRegexp(t, rule, path)
		}
	}
}

func FuzzIgnoreRuleClassification(f *testing.F) {
	for _, rule := range ignoreDiffRules {
		f.Add(rule, "x/name.log")
	}
	f.Add("*.log", "a/b/c.log")
	f.Fuzz(func(t *testing.T, rule, path string) {
		diffRuleAgainstRegexp(t, rule, path)
	})
}
