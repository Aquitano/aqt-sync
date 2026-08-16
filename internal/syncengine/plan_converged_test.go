// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"os"
	"path/filepath"
	"testing"
)

// A path deleted on both sides since base has exactly one possible outcome, which
// both sides already reached: it must plan no action, not a Conflict that wedges
// every sync with exit 4 (issue #183). A one-sided delete still plans its delete,
// and delete-vs-edit stays a Conflict.
func TestPlanBothSidesDeletedConverges(t *testing.T) {
	base := Manifest{
		Entries: []Entry{{Path: "gone.txt", Hash: "h1"}, {Path: "edited.txt", Hash: "h2"}, {Path: "kept.txt", Hash: "h3"}},
		Dirs:    []DirEntry{{Path: "gonedir"}, {Path: "keptdir"}},
	}
	local := Manifest{
		Entries: []Entry{{Path: "kept.txt", Hash: "h3"}},
		Dirs:    []DirEntry{{Path: "keptdir"}},
	}
	remote := Manifest{
		Entries: []Entry{{Path: "edited.txt", Hash: "h2-changed"}, {Path: "kept.txt", Hash: "h3"}},
		Dirs:    []DirEntry{{Path: "keptdir"}},
	}

	actions := Plan(local, base, remote)
	for _, a := range actions {
		if a.Path == "gone.txt" {
			t.Fatalf("both-sides-deleted file planned %s", a.Kind)
		}
	}
	// Local deleted edited.txt, remote edited it: still a real conflict.
	found := false
	for _, a := range actions {
		if a.Path == "edited.txt" && a.Kind == Conflict {
			found = true
		}
	}
	if !found {
		t.Fatal("delete-vs-edit no longer conflicts")
	}

	for _, a := range PlanDirs(local, base, remote) {
		if a.Path == "gonedir" {
			t.Fatalf("both-sides-deleted dir planned %s", a.Kind)
		}
	}
}

// The scanner must skip this tool's own transient artifacts — materialize temp
// files and filesystem probes — or a crash leftover reads as a local add and is
// pushed fleet-wide (issue #183).
func TestScanIgnoresOwnTransientFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".aqt-tmp-123456", ".aqt-CaseProbe-42", ".aqt-linkprobe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	byPath := m.ByPath()
	if _, ok := byPath["real.txt"]; !ok {
		t.Fatal("real file missing from scan")
	}
	for _, name := range []string{".aqt-tmp-123456", ".aqt-CaseProbe-42", ".aqt-linkprobe"} {
		if _, ok := byPath[name]; ok {
			t.Fatalf("transient artifact %s scanned as tracked content", name)
		}
	}
}
