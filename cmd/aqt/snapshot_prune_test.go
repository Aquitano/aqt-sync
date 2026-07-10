package main

import (
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestSelectSnapshotsToPrune(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	day := 24 * time.Hour
	// Newest-first, mixing two resources, as ListSnapshots returns.
	snaps := []api.SnapshotInfo{
		{ID: "r1-new", ResourceID: "r1", CreatedAt: now.Unix()},
		{ID: "r1-mid", ResourceID: "r1", CreatedAt: now.Add(-2 * day).Unix()},
		{ID: "r1-old", ResourceID: "r1", CreatedAt: now.Add(-10 * day).Unix()},
		{ID: "r2-new", ResourceID: "r2", CreatedAt: now.Add(-1 * time.Hour).Unix()},
		{ID: "r2-old", ResourceID: "r2", CreatedAt: now.Add(-30 * day).Unix()},
	}

	// keep-last is per resource: keep the newest of each, prune the rest.
	assertIDs(t, "keep-last 1",
		selectSnapshotsToPrune(snaps, 1, 0, now), "r1-mid", "r1-old", "r2-old")

	// older-than spans all resources and ignores rank.
	assertIDs(t, "older-than 5d",
		selectSnapshotsToPrune(snaps, 0, 5*day, now), "r1-old", "r2-old")

	// Intersection: beyond keep-last 1 AND older than 5d. r1-mid is beyond the keep
	// window but only 2d old, so it survives.
	assertIDs(t, "keep-last 1 + older-than 5d",
		selectSnapshotsToPrune(snaps, 1, 5*day, now), "r1-old", "r2-old")

	// No policy selects nothing.
	if got := selectSnapshotsToPrune(snaps, 0, 0, now); len(got) != 0 {
		t.Fatalf("no policy: got %v, want none", got)
	}
}

// Anchored snapshots are outside the retention universe: they are never selected and
// do not consume a --keep-last slot, so anchoring the newest one lets an older
// unanchored snapshot fill the kept quota instead.
func TestSelectSnapshotsToPruneSkipsAnchored(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	day := 24 * time.Hour
	snaps := []api.SnapshotInfo{
		{ID: "new", ResourceID: "r1", CreatedAt: now.Unix(), Anchored: true},
		{ID: "mid", ResourceID: "r1", CreatedAt: now.Add(-2 * day).Unix()},
		{ID: "old", ResourceID: "r1", CreatedAt: now.Add(-10 * day).Unix()},
	}

	// keep-last 1: the anchored newest does not count, so "mid" fills the kept slot and
	// only "old" is pruned. The anchor is never selected.
	assertIDs(t, "keep-last 1 with anchor", selectSnapshotsToPrune(snaps, 1, 0, now), "old")

	// older-than spans all snapshots but still skips the anchored one, even were it old.
	anchoredOld := []api.SnapshotInfo{
		{ID: "a", ResourceID: "r1", CreatedAt: now.Add(-30 * day).Unix(), Anchored: true},
		{ID: "b", ResourceID: "r1", CreatedAt: now.Add(-30 * day).Unix()},
	}
	assertIDs(t, "older-than skips anchor", selectSnapshotsToPrune(anchoredOld, 0, 5*day, now), "b")
}

func assertIDs(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
	for _, w := range want {
		if !set[w] {
			t.Fatalf("%s: missing %s in %v", label, w, got)
		}
	}
}
