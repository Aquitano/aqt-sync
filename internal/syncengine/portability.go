// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

// Case-insensitive filesystems (the macOS and Windows defaults) resolve two
// manifest paths that differ only by case (on macOS, or by Unicode normalization)
// to one file, so materializing both
// silently drops one — and the survivor is then re-uploaded under both names on
// the next sync, destroying the remote copies too. Symlink creation on Windows
// needs a privilege that is off by default outside Developer Mode. The helpers
// here detect both conditions so callers can refuse or degrade by name instead
// of losing data.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// FoldName is the key under which a case-insensitive filesystem resolves a path. It
// folds Unicode normalization along with case because APFS, the macOS default, is
// insensitive to both: café spelled with a precomposed é and with e plus a combining
// accent name one file there, exactly as Notes.md and notes.md do.
func FoldName(p string) string { return strings.ToLower(norm.NFC.String(p)) }

// CaseCollisions groups the manifest paths (files, symlinks, and directories)
// that a case-insensitive filesystem would resolve to the same name (see FoldName).
// Groups and their members come back sorted, for stable messages.
func CaseCollisions(entries []Entry, dirs []DirEntry) [][]string {
	byFold := map[string][]string{}
	for _, e := range entries {
		k := FoldName(e.Path)
		byFold[k] = append(byFold[k], e.Path)
	}
	for _, d := range dirs {
		k := FoldName(d.Path)
		byFold[k] = append(byFold[k], d.Path)
	}
	var groups [][]string
	for _, g := range byFold {
		if len(g) > 1 {
			sort.Strings(g)
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

// CaseInsensitiveDir reports whether the filesystem at dir folds case, probed by
// creating a temp file and looking it up under a different case. A probe that
// cannot run (unwritable dir) reports false — the case-sensitive assumption is
// today's behavior, and every gate keyed on this fails toward doing nothing new.
//
// AQT_TEST_CASE_INSENSITIVE=1 forces a true answer: a real case-folding
// filesystem cannot be conjured in CI, and the refusal paths need exercising.
func CaseInsensitiveDir(dir string) bool {
	if os.Getenv("AQT_TEST_CASE_INSENSITIVE") == "1" {
		return true
	}
	f, err := os.CreateTemp(dir, ".aqt-CaseProbe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(name) }()
	_, err = os.Lstat(filepath.Join(dir, strings.ToLower(filepath.Base(name))))
	return err == nil
}

// SymlinkSupport reports whether the process can create symlinks under dir. On
// POSIX it can; on Windows it needs SeCreateSymbolicLinkPrivilege, which is off
// by default outside Developer Mode.
//
// AQT_TEST_NO_SYMLINKS=1 forces a false answer, for the same CI reason as above.
func SymlinkSupport(dir string) bool {
	if os.Getenv("AQT_TEST_NO_SYMLINKS") == "1" {
		return false
	}
	name := filepath.Join(dir, ".aqt-linkprobe")
	// A leftover from a crashed probe would read as EEXIST, not inability.
	_ = os.Remove(name)
	if err := os.Symlink("aqt-probe-target", name); err != nil {
		return false
	}
	_ = os.Remove(name)
	return true
}
