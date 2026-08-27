// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Ignore matches paths against .aqtignore files, a pragmatic subset of gitignore:
// blank lines and # comments, ! negation, trailing-/ directory rules, leading-/
// or embedded-/ anchoring, and * / ? / ** globs. Like gitignore, rules live in
// per-directory files: a nested .aqtignore adds rules scoped to its subtree, and
// deeper rules (evaluated later) override shallower ones. The control directory
// and .git are always ignored (a tracked tree syncs working files, never a live
// git directory's locks/objects), though a later rule may re-include with `!`.
// Not supported: character classes ([a-z]) and escapes.
type Ignore struct {
	scopes []ignoreScope
}

// ignoreScope is the set of rules from one .aqtignore file, with the directory
// (POSIX, relative to the tracked root; "" for root) they apply within.
type ignoreScope struct {
	dir   string
	rules []ignoreRule
}

// ruleKind selects how a rule matches. Almost every real rule is a literal or a
// single edge glob, and the regexp form of those is slow in exactly the common
// case — the bare-name pattern (^|/)name$ opens with an alternation that defeats
// the literal-prefix optimizer, so the backtracker retries at every byte of a
// path that does not match. Those shapes are classified at compile time into
// direct string comparisons; the compiled regexp remains only for genuine globs
// (?, **, a * away from the edge, or more than one *).
type ruleKind uint8

const (
	ruleRegexp          ruleKind = iota
	ruleBareLiteral              // name: matches a whole path segment at any depth
	ruleBareSuffix               // *X: the last segment ends with X
	ruleBarePrefix               // X*: the last segment starts with X
	ruleAnchoredLiteral          // a/b: matches exactly that path — equality, not prefix
)

type ignoreRule struct {
	kind    ruleKind
	lit     string         // the literal for the non-regexp kinds
	re      *regexp.Regexp // only for ruleRegexp
	negate  bool
	dirOnly bool
}

// matches mirrors what the rule's regexp form would answer. The literal kinds
// compare bytes, matching regexp semantics for a metacharacter-free pattern; the
// anchored kind is equality on purpose — /dist compiles to ^dist$ and never
// matches dist/x.js (a walk excludes children via SkipDir instead), and callers
// that match individual paths (fswatch, gitguard) rely on that.
func (r *ignoreRule) matches(sub string) bool {
	switch r.kind {
	case ruleBareLiteral:
		return strings.HasSuffix(sub, r.lit) && (len(sub) == len(r.lit) || sub[len(sub)-len(r.lit)-1] == '/')
	case ruleBareSuffix:
		return strings.HasSuffix(lastSegment(sub), r.lit)
	case ruleBarePrefix:
		return strings.HasPrefix(lastSegment(sub), r.lit)
	case ruleAnchoredLiteral:
		return sub == r.lit
	default:
		return r.re.MatchString(sub)
	}
}

func lastSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// newIgnore seeds a matcher that always excludes the control directory, .git, and
// this tool's own transient artifacts: materialize temp files (.aqt-tmp-*, left
// behind by a crash mid-write) and filesystem probes (.aqt-CaseProbe-*,
// .aqt-linkprobe). Without these a leftover or a scan racing a probe reads as a
// local add and is pushed fleet-wide. A later `!` rule may re-include, like any
// other default.
func newIgnore() *Ignore {
	return &Ignore{scopes: []ignoreScope{{dir: "", rules: compileRules([]string{
		ControlDir + "/", ".git/", ".aqt-tmp-*", ".aqt-CaseProbe-*", ".aqt-linkprobe",
	})}}}
}

// loadDir adds the rules from absDir/.aqtignore, scoped to relDir. A directory
// without an .aqtignore (or with only blanks/comments) adds nothing.
func (ig *Ignore) loadDir(absDir, relDir string) {
	b, err := os.ReadFile(filepath.Join(absDir, ignoreFile))
	if err != nil {
		return
	}
	if rules := compileRules(strings.Split(string(b), "\n")); len(rules) > 0 {
		ig.scopes = append(ig.scopes, ignoreScope{dir: relDir, rules: rules})
	}
}

// LoadIgnore builds a matcher from the root .aqtignore only. Tree walks load
// nested files as they descend; this is for callers that match against the root
// rules directly.
func LoadIgnore(dir string) (*Ignore, error) {
	ig := newIgnore()
	ig.loadDir(dir, "")
	return ig, nil
}

// Match reports whether relPath (POSIX, relative to the tracked root) is ignored.
// Scopes are consulted shallowest-first so a deeper .aqtignore can override a
// shallower one; within a scope, the last matching rule wins.
func (ig *Ignore) Match(relPath string, isDir bool) bool {
	ignored := false
	for _, sc := range ig.scopes {
		sub, ok := relativeTo(sc.dir, relPath)
		if !ok {
			continue // this scope does not cover relPath
		}
		for i := range sc.rules {
			r := &sc.rules[i]
			if r.dirOnly && !isDir {
				continue
			}
			if r.matches(sub) {
				ignored = !r.negate
			}
		}
	}
	return ignored
}

// HasNegation reports whether any loaded rule is a `!` re-include. Callers use it
// to skip work only a negation can make reachable: the built-in .git/ rule
// excludes every .git path, so without a negation anywhere no .git can be
// tracked and a walk looking for one provably finds nothing.
func (ig *Ignore) HasNegation() bool {
	for _, sc := range ig.scopes {
		for i := range sc.rules {
			if sc.rules[i].negate {
				return true
			}
		}
	}
	return false
}

// relativeTo returns relPath expressed relative to scopeDir, and whether relPath
// lies within scopeDir at all.
func relativeTo(scopeDir, relPath string) (string, bool) {
	if scopeDir == "" {
		return relPath, true
	}
	if relPath == scopeDir {
		return "", true
	}
	prefix := scopeDir + "/"
	if rest, ok := strings.CutPrefix(relPath, prefix); ok {
		return rest, true
	}
	return "", false
}

func compileRules(lines []string) []ignoreRule {
	var rules []ignoreRule
	for _, line := range lines {
		if r, ok := compileRule(line); ok {
			rules = append(rules, r)
		}
	}
	return rules
}

func compileRule(line string) (ignoreRule, bool) {
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

	// Classify on * and ? only: translateGlob escapes every other metacharacter, so
	// a pattern like x[a-z] or a+b is a literal string here exactly as it is under
	// the regexp. The UTF-8 guard preserves the compile path's behavior of silently
	// dropping a rule regexp.Compile would reject.
	if utf8.ValidString(line) && !strings.Contains(line, "?") {
		switch stars := strings.Count(line, "*"); {
		case stars == 0 && anchored:
			r.kind, r.lit = ruleAnchoredLiteral, line
			return r, true
		case stars == 0:
			r.kind, r.lit = ruleBareLiteral, line
			return r, true
		case stars == 1 && !anchored && strings.HasPrefix(line, "*"):
			r.kind, r.lit = ruleBareSuffix, line[1:]
			return r, true
		case stars == 1 && !anchored && strings.HasSuffix(line, "*"):
			r.kind, r.lit = ruleBarePrefix, line[:len(line)-1]
			return r, true
		}
	}

	expr := translateGlob(line)
	if anchored {
		expr = "^" + expr + "$"
	} else {
		// A bare name matches at any depth within the scope: the start or after a /.
		expr = "(^|/)" + expr + "$"
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return ignoreRule{}, false // skip an un-compilable pattern rather than abort
	}
	r.re = re
	return r, true
}

// translateGlob converts one gitignore-style glob into a regexp fragment, where
// * stops at a path separator, ? matches one non-separator, and ** spans them.
func translateGlob(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				i++
				if i+1 < len(glob) && glob[i+1] == '/' {
					i++
					b.WriteString("(.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
