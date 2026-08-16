// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
