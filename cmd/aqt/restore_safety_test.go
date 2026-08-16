// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConflictsCopyConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"conflicts": "copy"}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An in-place restore of a tree whose own .aqtconfig selects conflicts=copy used to
// wedge after the swap: the internal propagation sync runs with force, which the
// config's copy mode contradicts — a flag conflict the user never caused. The
// propagation sync pins conflicts=block instead (issue #183).
func TestInPlaceRestoreWithConflictsCopyConfig(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeConflictsCopyConfig(t, src)
	writeTree(t, src, "a.txt", "original")
	h.sync(src)
	runCmd(t, checkpointCmd(), "pin", src)

	writeTree(t, src, "a.txt", "changed")
	h.sync(src)

	runCmd(t, restoreCmd(), "pin", src, "--in-place", "-y")
	if c := readTree(t, src, "a.txt"); c != "original" {
		t.Fatalf("a.txt = %q after restore", c)
	}
	// A completed restore leaves no marker behind.
	if _, err := os.Stat(controlPath(src, restoreMarkerFile)); !os.IsNotExist(err) {
		t.Fatalf("restore marker left behind: %v", err)
	}
}

// Adopting a clone whose synced .aqtconfig selects conflicts=copy used to wedge the
// internal reconcile the same way (copy contradicts --reconcile); it pins block too.
func TestAdoptWithConflictsCopyConfig(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeConflictsCopyConfig(t, origin)
	writeTree(t, origin, "a.txt", "same content")
	h.sync(origin)
	id := h.folderID(origin)

	adoptee := t.TempDir()
	copyTreeExclAqt(t, origin, adoptee)
	if err := runClone(id, adoptee, true, ""); err != nil {
		t.Fatalf("adopt with conflicts=copy config: %v", err)
	}
	if got := h.folderID(adoptee); got != id {
		t.Fatalf("adoptee tracks %s, want %s", got, id)
	}
}

// A kill mid-swap leaves a half-emptied root; the marker written before the swap
// must make the next sync refuse with recovery guidance instead of scanning the
// carnage as local deletions and pushing them fleet-wide.
func TestSyncRefusesAfterInterruptedRestoreSwap(t *testing.T) {
	h := newE2E(t)
	src := t.TempDir()
	h.init(src)
	writeTree(t, src, "a.txt", "x")
	h.sync(src)

	if err := writeMarker(src, restoreMarkerFile, interruptedRestore{SnapshotID: "snapXYZ"}); err != nil {
		t.Fatal(err)
	}
	err := runSync(src, syncOptions{})
	if err == nil || !strings.Contains(err.Error(), "restore") || !strings.Contains(err.Error(), "snapXYZ") {
		t.Fatalf("sync with restore marker: %v", err)
	}

	if err := clearMarker(src, restoreMarkerFile); err != nil {
		t.Fatal(err)
	}
	h.sync(src)
}
