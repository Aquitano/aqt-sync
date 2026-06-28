package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
)

func TestFilterSnapshots(t *testing.T) {
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	at := func(id string, ageHours int) api.SnapshotInfo {
		return api.SnapshotInfo{ID: id, CreatedAt: now.Add(-time.Duration(ageHours) * time.Hour).Unix()}
	}
	// Newest first, as the server returns them.
	snaps := []api.SnapshotInfo{
		at("a", 1),    // 1h old
		at("b", 48),   // 2d old
		at("c", 240),  // 10d old
		at("d", 1000), // ~41d old
	}
	ids := func(in []api.SnapshotInfo) []string {
		out := []string{}
		for _, s := range in {
			out = append(out, s.ID)
		}
		return out
	}

	cases := []struct {
		name          string
		limit         int
		since, before time.Duration
		want          []string
	}{
		{"no filters", 0, 0, 0, []string{"a", "b", "c", "d"}},
		{"limit caps", 2, 0, 0, []string{"a", "b"}},
		{"limit beyond len", 99, 0, 0, []string{"a", "b", "c", "d"}},
		{"since keeps recent", 0, 72 * time.Hour, 0, []string{"a", "b"}},
		{"before keeps old", 0, 0, 72 * time.Hour, []string{"c", "d"}},
		{"since+before window", 0, 720 * time.Hour, 24 * time.Hour, []string{"b", "c"}},
		{"since then limit", 1, 72 * time.Hour, 0, []string{"a"}},
	}
	for _, tc := range cases {
		got := ids(filterSnapshots(snaps, tc.limit, tc.since, tc.before, now))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The index `snapshot find` searches is built from the same decrypted rows as
// `list`: the resource name and the optional label both come back in the clear.
func TestSnapshotFindIndex(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "hi")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	rid := h.folderID(src)
	sealed, err := sealSnapshotLabel(cl, prof, rid, "tagged")
	if err != nil {
		t.Fatalf("seal label: %v", err)
	}
	if _, err := cl.CreateSnapshot(rid, sealed); err != nil {
		t.Fatalf("create: %v", err)
	}

	snaps, err := cl.ListSnapshots(rid)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	rows := snapshotRows(snaps, mk)
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Name != "work" || rows[0].Label != "tagged" {
		t.Fatalf("row = %+v, want name=work label=tagged", rows[0])
	}
}
