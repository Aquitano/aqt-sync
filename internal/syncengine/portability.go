// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

// Case-insensitive filesystems (the macOS and Windows defaults) resolve two
// manifest paths that differ only by case (or, on macOS, only by Unicode
// normalization) to one file, so materializing both silently drops one — and the
// survivor is then re-uploaded under both names on the next sync, destroying the
// remote copies too. Symlink creation on Windows needs a privilege that is off by
// default outside Developer Mode. The helpers here detect both conditions so
// callers can refuse or degrade by name instead of losing data.

import (
	"errors"
	"io/fs"
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

// collisionKey is FoldName with each segment's trailing dots and spaces dropped,
// because Win32 drops them too: notes and notes. are one file on Windows. It stays
// out of FoldName, which also keys case-only renames on APFS, where the two are
// distinct files.
func collisionKey(p string) string {
	segs := strings.Split(FoldName(p), "/")
	for i, s := range segs {
		if t := strings.TrimRight(s, ". "); t != "" {
			segs[i] = t
		}
	}
	return strings.Join(segs, "/")
}

// CaseCollisions groups the manifest paths (files, symlinks, and directories)
// that a case-insensitive filesystem would resolve to the same name (see FoldName),
// including names Windows resolves alike after dropping trailing dots and spaces.
// Groups and their members come back sorted, for stable messages.
func CaseCollisions(entries []Entry, dirs []DirEntry) [][]string {
	byFold := map[string][]string{}
	for _, e := range entries {
		k := collisionKey(e.Path)
		byFold[k] = append(byFold[k], e.Path)
	}
	for _, d := range dirs {
		k := collisionKey(d.Path)
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

// BackslashPaths returns the manifest paths containing a backslash, sorted. Windows
// reads one as a path separator, so a\b would land there as file b in directory a
// and the next scan would delete a\b everywhere.
func BackslashPaths(entries []Entry, dirs []DirEntry) []string {
	var out []string
	for _, e := range entries {
		if strings.ContainsRune(e.Path, '\\') {
			out = append(out, e.Path)
		}
	}
	for _, d := range dirs {
		if strings.ContainsRune(d.Path, '\\') {
			out = append(out, d.Path)
		}
	}
	sort.Strings(out)
	return out
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

// errReparsePoint is the skip cause for a linkLike entry that is not a symlink.
var errReparsePoint = errors.New("junction or other reparse point, not followed")

// linkLike reports whether mode is an entry a write must never descend through: a
// symlink, or a Windows junction or mount point, which Go reports as ModeIrregular
// without ModeDir. A cloud-placeholder directory is ModeDir|ModeIrregular and holds
// real children, so it does not count.
func linkLike(mode fs.FileMode) bool {
	return mode&fs.ModeSymlink != 0 || (mode&fs.ModeIrregular != 0 && !mode.IsDir())
}
