package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// Property-based tests for the keep-both conflict planner. The invariant that
// matters is the sim's "never loses bytes" rule: every conflicting remote entry
// must survive as a copy at a fresh path, byte-identical (same hash/chunks),
// across any set of paths, hosts, pre-existing files, and retry re-plans.

var sanitizedHostRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestSanitizeHostProps(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := rapid.String().Draw(t, "raw")
		out := sanitizeHost(raw)
		if !sanitizedHostRe.MatchString(out) {
			t.Fatalf("sanitizeHost(%q) = %q, not a clean [a-z0-9-] name", raw, out)
		}
		if again := sanitizeHost(out); again != out {
			t.Fatalf("sanitizeHost not idempotent: %q -> %q -> %q", raw, out, again)
		}
	})
}

// relPathGen draws a short relative POSIX path (1-3 lowercase segments).
func relPathGen() *rapid.Generator[string] {
	seg := rapid.StringMatching(`[a-z0-9]{1,6}`)
	return rapid.Custom(func(t *rapid.T) string {
		return strings.Join(rapid.SliceOfN(seg, 1, 3).Draw(t, "segments"), "/")
	})
}

func writeUnder(t *rapid.T, root, rel string) {
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConflictCopyPathIsFreshProp(t *testing.T) {
	base := t.TempDir()
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp(base, "case")
		if err != nil {
			t.Fatal(err)
		}
		path := relPathGen().Draw(t, "path")
		host := sanitizeHost(rapid.String().Draw(t, "host"))
		writeUnder(t, root, path)
		// Pre-create the first n candidate names so the suffix bump has to walk
		// past real collisions.
		stem := path + ".conflict-" + host + "-" + now.UTC().Format("20060102-150405")
		taken := []string{stem, stem + "-1", stem + "-2"}
		for _, rel := range taken[:rapid.IntRange(0, 3).Draw(t, "collisions")] {
			writeUnder(t, root, rel)
		}

		got := conflictCopyPath(root, path, host, now)
		if !strings.HasPrefix(got, stem) {
			t.Fatalf("copy path %q does not extend %q", got, stem)
		}
		if pathExists(root, got) {
			t.Fatalf("copy path %q already exists; materializing would clobber it", got)
		}
	})
}

func TestPlanConflictCopiesProps(t *testing.T) {
	base := t.TempDir()
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	kinds := []syncengine.ActionKind{
		syncengine.Upload, syncengine.Download, syncengine.DeleteRemote,
		syncengine.DeleteLocal, syncengine.Conflict,
	}
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp(base, "case")
		if err != nil {
			t.Fatal(err)
		}
		host := sanitizeHost(rapid.String().Draw(t, "host"))
		// A path that is a directory prefix of another ("a" and "a/b") cannot
		// coexist as files on disk, so such sets are not valid tracked trees.
		paths := rapid.SliceOfNDistinct(relPathGen(), 1, 8, rapid.ID).
			Filter(func(ps []string) bool {
				for _, a := range ps {
					for _, b := range ps {
						if a != b && strings.HasPrefix(b, a+"/") {
							return false
						}
					}
				}
				return true
			}).Draw(t, "paths")

		var actions []syncengine.Action
		remoteByPath := map[string]syncengine.Entry{}
		wantCopies := map[string]syncengine.Entry{}
		for _, p := range paths {
			kind := rapid.SampledFrom(kinds).Draw(t, "kind")
			actions = append(actions, syncengine.Action{Path: p, Kind: kind})
			if rapid.Bool().Draw(t, "hasRemote") {
				e := syncengine.Entry{Path: p, Hash: rapid.StringMatching(`[0-9a-f]{8}`).Draw(t, "hash"), Size: 1}
				remoteByPath[p] = e
				if kind == syncengine.Conflict {
					wantCopies[p] = e
				}
			}
			if rapid.Bool().Draw(t, "onDisk") {
				writeUnder(t, root, p)
			}
		}

		memo := conflictCopyMemo{}
		copies := planConflictCopies(root, actions, remoteByPath, host, now, memo)

		if len(copies) != len(wantCopies) {
			t.Fatalf("planned %d copies, want %d (one per conflict with a remote entry)", len(copies), len(wantCopies))
		}
		seen := map[string]bool{}
		for _, cp := range copies {
			want, ok := wantCopies[cp.orig]
			if !ok {
				t.Fatalf("copy planned for %q, which is not a conflict with remote bytes", cp.orig)
			}
			// The remote entry must survive byte-identical: only the path is rewritten.
			if cp.entry.Hash != want.Hash || cp.entry.Size != want.Size {
				t.Fatalf("copy for %q lost content: entry %+v, remote %+v", cp.orig, cp.entry, want)
			}
			if cp.entry.Path == cp.orig || pathExists(root, cp.entry.Path) {
				t.Fatalf("copy path %q for %q is not fresh", cp.entry.Path, cp.orig)
			}
			if seen[cp.entry.Path] {
				t.Fatalf("two copies share path %q", cp.entry.Path)
			}
			seen[cp.entry.Path] = true
		}

		// Retry semantics: materialize the copies and memoize them the way sync.go
		// does, then re-plan the same standing conflicts. Nothing new may be planned
		// (no duplicate accumulation across retries).
		for _, cp := range copies {
			writeUnder(t, root, cp.entry.Path)
			memo[cp.orig] = conflictCopyRecord{copyPath: cp.entry.Path, remoteHash: cp.entry.Hash}
		}
		if again := planConflictCopies(root, actions, remoteByPath, host, now, memo); len(again) != 0 {
			t.Fatalf("re-plan after materializing planned %d copies, want 0", len(again))
		}

		// A copy lost from disk is rewritten at its memoized name, never a bumped one.
		for _, cp := range copies {
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(cp.entry.Path))); err != nil {
				t.Fatal(err)
			}
			redo := planConflictCopies(root, actions, remoteByPath, host, now, memo)
			if len(redo) != 1 || redo[0].entry.Path != cp.entry.Path {
				t.Fatalf("lost copy re-plan = %+v, want exactly %q again", redo, cp.entry.Path)
			}
			writeUnder(t, root, cp.entry.Path)
		}

		// A remote re-edit (hash changed since the memoized attempt) must get a
		// fresh copy carrying the new bytes.
		for _, cp := range copies {
			e := remoteByPath[cp.orig]
			e.Hash = "f" + e.Hash[1:]
			if e.Hash == cp.entry.Hash {
				continue
			}
			remoteByPath[cp.orig] = e
			redo := planConflictCopies(root, actions, remoteByPath, host, now, memo)
			var got *conflictCopyItem
			for i := range redo {
				if redo[i].orig == cp.orig {
					got = &redo[i]
				}
			}
			if got == nil {
				t.Fatalf("re-edited remote for %q planned no copy; the new bytes would be lost", cp.orig)
			}
			if got.entry.Hash != e.Hash || pathExists(root, got.entry.Path) {
				t.Fatalf("re-edited copy %+v does not carry the new bytes at a fresh path", got)
			}
			remoteByPath[cp.orig] = wantCopies[cp.orig]
		}
	})
}
