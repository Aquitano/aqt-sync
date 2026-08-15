// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestDiffIncoming pins the base-vs-remote classification the status view reports:
// a remote-only entry is an add, a differing hash or mode is a modify, a base-only
// entry is a delete, and an identical entry is silent.
func TestDiffIncoming(t *testing.T) {
	base := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "same.txt", Hash: "h1", Mode: 0o644},
		{Path: "modmode.txt", Hash: "h2", Mode: 0o644},
		{Path: "modcontent.txt", Hash: "h3", Mode: 0o644},
		{Path: "gone.txt", Hash: "h4", Mode: 0o644},
	}}
	remote := syncengine.Manifest{Entries: []syncengine.Entry{
		{Path: "same.txt", Hash: "h1", Mode: 0o644},
		{Path: "modmode.txt", Hash: "h2", Mode: 0o755},     // mode changed
		{Path: "modcontent.txt", Hash: "h3b", Mode: 0o644}, // content changed
		{Path: "fresh.txt", Hash: "h5", Mode: 0o644},
	}}

	got := diffIncoming(base, remote)
	if want := []string{"fresh.txt"}; !equalStrings(got.added, want) {
		t.Errorf("added = %v, want %v", got.added, want)
	}
	if want := []string{"modcontent.txt", "modmode.txt"}; !equalStrings(got.modified, want) {
		t.Errorf("modified = %v, want %v", got.modified, want)
	}
	if want := []string{"gone.txt"}; !equalStrings(got.deleted, want) {
		t.Errorf("deleted = %v, want %v", got.deleted, want)
	}
	if got.total() != 4 {
		t.Errorf("total = %d, want 4", got.total())
	}
}

func TestDiffIncomingClean(t *testing.T) {
	m := syncengine.Manifest{Entries: []syncengine.Entry{{Path: "a", Hash: "h", Mode: 0o644}}}
	if got := diffIncoming(m, m); got.total() != 0 {
		t.Errorf("identical manifests reported %d incoming changes, want 0", got.total())
	}
}

// TestStatusIncomingE2E drives the real status path against the real server: a second
// machine's `status` must see the files a first machine pushed after the clone, report
// "up to date" once it syncs, and (with --offline) skip the server entirely.
func TestStatusIncomingE2E(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "v1")
	writeTree(t, origin, "old.txt", "remove me")
	h.sync(origin)
	id := h.folderID(origin)

	replica := t.TempDir()
	h.clone(id, replica)

	// The replica has nothing pending yet: clean locally and level with the server.
	if out := captureStdout(t, func() { mustStatus(t, replica) }); !strings.Contains(out, "up to date with the server") {
		t.Fatalf("fresh clone status did not report up to date:\n%s", out)
	}

	// The origin pushes an add, a modify, and a delete; the replica has not pulled them.
	writeTree(t, origin, "keep.txt", "v2")
	writeTree(t, origin, "new.txt", "brand new")
	removeTree(t, origin, "old.txt")
	h.sync(origin)

	out := captureStdout(t, func() { mustStatus(t, replica) })
	for _, want := range []string{
		"incoming: 3 to pull (1 new, 1 modified, 1 deleted)",
		"new       new.txt",
		"modified  keep.txt",
		"deleted   old.txt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("incoming status missing %q, got:\n%s", want, out)
		}
	}

	// --offline reports only the (clean) local half, never touching the server.
	if off := captureStdout(t, func() { mustStatusOpts(t, replica, statusOptions{offline: true}) }); strings.Contains(off, "incoming") {
		t.Errorf("--offline status reported incoming changes:\n%s", off)
	}

	// Without a cached session, status cannot decrypt for a file count but still spots
	// that the server is ahead from the version alone. Clear the session, assert the
	// coarse message, then restore it so the later sync unlocks without a prompt.
	mk, ok := identity.LoadSession(identity.DefaultProfile)
	if !ok {
		t.Fatal("expected a cached session from the harness")
	}
	if err := identity.ClearSession(identity.DefaultProfile); err != nil {
		t.Fatalf("clear session: %v", err)
	}
	if out := captureStdout(t, func() { mustStatus(t, replica) }); !strings.Contains(out, "the server is ahead by 1 version(s)") {
		t.Errorf("locked status did not fall back to the version delta:\n%s", out)
	}
	if err := identity.SaveSession(identity.DefaultProfile, mk, time.Hour); err != nil {
		t.Fatalf("restore session: %v", err)
	}

	// After syncing, the replica is level again and status says so.
	h.sync(replica)
	if out := captureStdout(t, func() { mustStatus(t, replica) }); !strings.Contains(out, "up to date with the server") {
		t.Fatalf("post-sync status did not report up to date:\n%s", out)
	}
}

func mustStatus(t *testing.T, dir string) { mustStatusOpts(t, dir, statusOptions{}) }

func mustStatusOpts(t *testing.T, dir string, opts statusOptions) {
	t.Helper()
	if err := runStatus(dir, opts); err != nil {
		t.Fatalf("status %s: %v", dir, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestStatusReportsEveryTrackedKind covers the classification a file-only comparison
// used to drop: a tracked directory (added and mode-edited) and a path that switched
// kind must reach both the human view and the JSON contract.
func TestStatusReportsEveryTrackedKind(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	h.init(dir)
	writeTree(t, dir, "notes/todo.txt", "buy milk")
	writeTree(t, dir, "swap", "was a file")
	h.sync(dir)

	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	removeTree(t, dir, "swap")
	writeTree(t, dir, "swap/inner.txt", "now a dir")
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(dir, "notes"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	out := captureStdout(t, func() {
		if err := runStatus(dir, statusOptions{offline: true}); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	// Directories print with the trailing slash the plan printer uses, so `empty` and
	// a file named `empty` are not confusable.
	for _, want := range []string{"new       empty/", "type      swap/ (file -> dir)"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
	if runtime.GOOS != "windows" && !strings.Contains(out, "mode      notes/") {
		t.Errorf("status output missing the directory mode edit:\n%s", out)
	}

	withJSON(t, func() {
		out := captureStdout(t, func() {
			if err := runStatus(dir, statusOptions{offline: true}); err != nil {
				t.Fatalf("status --json: %v", err)
			}
		})
		var st struct {
			Clean    bool     `json:"clean"`
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Changes  []struct {
				Path string `json:"path"`
				Kind string `json:"kind"`
				Type string `json:"type"`
				Was  string `json:"was"`
			} `json:"changes"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			t.Fatalf("status --json is not valid JSON: %v\n%s", err, out)
		}
		if st.Clean {
			t.Error("status --json reported clean")
		}
		// The legacy buckets keep their meaning: a type switch is a modification.
		if !contains(st.Added, "empty") || !contains(st.Modified, "swap") {
			t.Errorf("legacy buckets = added %v, modified %v", st.Added, st.Modified)
		}
		kinds := map[string]string{}
		types := map[string]string{}
		for _, c := range st.Changes {
			kinds[c.Path] = c.Kind
			types[c.Path] = c.Type
			if c.Path == "swap" && c.Was != "file" {
				t.Errorf("swap was = %q, want file", c.Was)
			}
		}
		if kinds["empty"] != "added" || types["empty"] != "dir" {
			t.Errorf("empty classified as %q/%q, want added/dir", kinds["empty"], types["empty"])
		}
		if kinds["swap"] != "type" || types["swap"] != "dir" {
			t.Errorf("swap classified as %q/%q, want type/dir", kinds["swap"], types["swap"])
		}
		if runtime.GOOS != "windows" && kinds["notes"] != "mode" {
			t.Errorf("notes classified as %q, want mode", kinds["notes"])
		}
	})
}
