// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestPartitionDeletesByDownload(t *testing.T) {
	downloads := []syncengine.Entry{{Path: "link/inner.txt"}, {Path: "a/b/c.txt"}, {Path: "top.txt"}, {Path: "foo"}}
	deletes := []string{"link", "a/b", "top.txt", "unrelated", "foo/x", "foo/y"}

	early, late := partitionDeletesByDownload(deletes, downloads, false)

	// "link" and "a/b" are ancestors of a download path (a file/symlink became a dir),
	// and "foo/x"/"foo/y" are descendants of the download "foo" (a directory became a
	// file), so all run first. "top.txt" equals a download path but does not nest with
	// it (a file replaced by a file, handled by rename), and "unrelated" matches nothing.
	wantEarly := map[string]bool{"link": true, "a/b": true, "foo/x": true, "foo/y": true}
	for _, p := range early {
		if !wantEarly[p] {
			t.Errorf("unexpected early delete %q", p)
		}
		delete(wantEarly, p)
	}
	if len(wantEarly) != 0 {
		t.Errorf("missing early deletes: %v", wantEarly)
	}
	wantLate := map[string]bool{"top.txt": true, "unrelated": true}
	for _, p := range late {
		if !wantLate[p] {
			t.Errorf("unexpected late delete %q", p)
		}
		delete(wantLate, p)
	}
	if len(wantLate) != 0 {
		t.Errorf("missing late deletes: %v", wantLate)
	}
}

// The linear partition must agree with the obvious pairwise scan it replaced, in
// both fold modes. The path set is built to stress the sorted-prefix probe: names
// where a sibling sorts between a directory key and its children ("a0" sorts after
// "a/" bytewise), equal delete/download paths, deep nesting, and case overlaps.
func TestPartitionDeletesByDownloadMatchesPairwise(t *testing.T) {
	pairwise := func(deletes []string, downloads []syncengine.Entry, fold bool) (early, late []string) {
		key := func(p string) string {
			if fold {
				return strings.ToLower(p)
			}
			return p
		}
		for _, d := range deletes {
			races := false
			for _, e := range downloads {
				if strings.HasPrefix(key(e.Path), key(d)+"/") || strings.HasPrefix(key(d), key(e.Path)+"/") {
					races = true
					break
				}
			}
			if races {
				early = append(early, d)
			} else {
				late = append(late, d)
			}
		}
		return early, late
	}

	paths := []string{
		"a", "a/b", "a/b/c.txt", "a0", "a0/b", "A/B", "a/B/C.TXT",
		"dir", "dir/f", "dir!", "dir!/f", "Dir/F/g", "z", "z/z/z/z",
		"top.txt", "TOP.TXT", "foo", "foo/x", "foo/y/deep",
	}
	for mask := 0; mask < 1<<len(paths); mask += 97 { // sampled subsets
		var deletes []string
		var downloads []syncengine.Entry
		for i, p := range paths {
			if mask&(1<<i) != 0 {
				deletes = append(deletes, p)
			} else {
				downloads = append(downloads, syncengine.Entry{Path: p})
			}
		}
		for _, fold := range []bool{false, true} {
			wantEarly, wantLate := pairwise(deletes, downloads, fold)
			gotEarly, gotLate := partitionDeletesByDownload(deletes, downloads, fold)
			if !slices.Equal(gotEarly, wantEarly) || !slices.Equal(gotLate, wantLate) {
				t.Fatalf("mask %d fold %v: got early=%v late=%v, want early=%v late=%v",
					mask, fold, gotEarly, gotLate, wantEarly, wantLate)
			}
		}
	}
}
