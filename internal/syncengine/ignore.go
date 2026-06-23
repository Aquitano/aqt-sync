package syncengine

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Ignore matches paths against .aqtignore, a pragmatic subset of gitignore:
// blank lines and # comments, ! negation, trailing-/ directory rules, leading-/
// or embedded-/ anchoring, and * / ? / ** globs. Later rules win, mirroring
// gitignore. The control directory is always ignored. Not supported: character
// classes ([a-z]) and escape sequences.
type Ignore struct {
	rules []ignoreRule
}

type ignoreRule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// LoadIgnore reads dir/.aqtignore; a missing file yields a matcher that still
// excludes the control directory.
func LoadIgnore(dir string) (*Ignore, error) {
	ig := &Ignore{}
	ig.add(ControlDir + "/")

	f, err := os.Open(filepath.Join(dir, ignoreFile))
	if err != nil {
		if os.IsNotExist(err) {
			return ig, nil
		}
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ig.add(sc.Text())
	}
	return ig, sc.Err()
}

func (ig *Ignore) add(line string) {
	line = strings.TrimRight(line, " ")
	if line == "" || strings.HasPrefix(line, "#") {
		return
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
		// A bare name matches at any depth: the root or any path segment.
		expr = "(^|/)" + expr + "$"
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return // skip an un-compilable pattern rather than abort the whole sync
	}
	r.re = re
	ig.rules = append(ig.rules, r)
}

// Match reports whether relPath (POSIX, relative to the tracked root) is ignored.
func (ig *Ignore) Match(relPath string, isDir bool) bool {
	ignored := false
	for _, r := range ig.rules {
		if r.dirOnly && !isDir {
			continue
		}
		if r.re.MatchString(relPath) {
			ignored = !r.negate
		}
	}
	return ignored
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
