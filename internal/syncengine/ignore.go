// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

type ignoreRule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// newIgnore seeds a matcher that always excludes the control directory and .git.
func newIgnore() *Ignore {
	return &Ignore{scopes: []ignoreScope{{dir: "", rules: compileRules([]string{ControlDir + "/", ".git/"})}}}
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
		for _, r := range sc.rules {
			if r.dirOnly && !isDir {
				continue
			}
			if r.re.MatchString(sub) {
				ignored = !r.negate
			}
		}
	}
	return ignored
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
