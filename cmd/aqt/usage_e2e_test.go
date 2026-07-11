package main

import (
	"path/filepath"
	"testing"
)

func TestUsageE2E(t *testing.T) {
	h := newE2E(t)
	dir := filepath.Join(t.TempDir(), "tree")
	writeTree(t, dir, "notes.txt", "usage e2e file one")
	writeTree(t, dir, "sub/b.txt", "usage e2e file two")
	h.init(dir)
	h.sync(dir)

	cl, _, err := authedClient()
	if err != nil {
		t.Fatalf("authed client: %v", err)
	}
	u, err := cl.Usage()
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if u.StorageBytes <= 0 || u.Packs < 1 || u.Objects < 1 {
		t.Fatalf("usage after sync = %+v, want stored bytes and at least one pack/object", u)
	}
	if u.Resources != 1 || u.Devices != 1 {
		t.Fatalf("usage = %+v, want 1 resource and 1 device", u)
	}

	if err := runUsage(true); err != nil {
		t.Fatalf("runUsage json: %v", err)
	}
	if err := runUsage(false); err != nil {
		t.Fatalf("runUsage table: %v", err)
	}
}
