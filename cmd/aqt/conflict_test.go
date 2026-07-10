package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestEffectiveConflictMode(t *testing.T) {
	cfgCopy := syncengine.Config{Conflicts: "copy"}
	cfgEmpty := syncengine.Config{}

	// An unset flag falls back to the .aqtconfig default.
	if m, err := effectiveConflictMode(syncOptions{}, cfgCopy); err != nil || m != conflictCopy {
		t.Errorf("config default: got (%v, %v), want copy", m, err)
	}
	// An explicit --conflicts=block overrides a config that selects copy.
	if m, err := effectiveConflictMode(syncOptions{conflicts: "block"}, cfgCopy); err != nil || m != conflictBlock {
		t.Errorf("explicit block over config copy: got (%v, %v), want block", m, err)
	}
	// Nothing set anywhere defaults to block.
	if m, err := effectiveConflictMode(syncOptions{}, cfgEmpty); err != nil || m != conflictBlock {
		t.Errorf("default: got (%v, %v), want block", m, err)
	}
	// An explicit copy applies when the config is silent.
	if m, err := effectiveConflictMode(syncOptions{conflicts: "copy"}, cfgEmpty); err != nil || m != conflictCopy {
		t.Errorf("explicit copy: got (%v, %v), want copy", m, err)
	}
	// An invalid flag value is rejected.
	if _, err := effectiveConflictMode(syncOptions{conflicts: "bogus"}, cfgEmpty); err == nil {
		t.Error("expected an error for an invalid --conflicts value")
	}
}

func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"Laptop":             "laptop",
		"my.host.local":      "my-host-local",
		"a__b--c":            "a-b-c",
		"--Edge--":           "edge",
		"MacBook Pro (Work)": "macbook-pro-work",
		"héllo":              "h-llo",
		"":                   "device",
		"...":                "device",
		"123-ABC":            "123-abc",
	}
	for in, want := range cases {
		if got := sanitizeHost(in); got != want {
			t.Errorf("sanitizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConflictCopyPathFormat(t *testing.T) {
	root := t.TempDir()
	ts := time.Date(2026, 7, 10, 14, 30, 5, 0, time.UTC)
	got := conflictCopyPath(root, "notes/todo.txt", "laptop", ts)
	want := "notes/todo.txt.conflict-laptop-20260710-143005"
	if got != want {
		t.Fatalf("conflictCopyPath = %q, want %q", got, want)
	}
	// The suffix is appended to the whole name, extension included, not spliced in.
	got = conflictCopyPath(root, "archive.tar.gz", "host", ts)
	if want := "archive.tar.gz.conflict-host-20260710-143005"; got != want {
		t.Fatalf("conflictCopyPath = %q, want %q", got, want)
	}
}

func TestConflictCopyPathTimestampIsUTC(t *testing.T) {
	root := t.TempDir()
	// A non-UTC time must still be formatted in UTC for a stable, location-free name.
	loc := time.FixedZone("UTC-5", -5*3600)
	ts := time.Date(2026, 7, 10, 9, 30, 5, 0, loc) // 14:30:05 UTC
	got := conflictCopyPath(root, "f.txt", "h", ts)
	if want := "f.txt.conflict-h-20260710-143005"; got != want {
		t.Fatalf("conflictCopyPath = %q, want %q", got, want)
	}
}

func TestConflictCopyPathCollisionCounter(t *testing.T) {
	root := t.TempDir()
	ts := time.Date(2026, 7, 10, 14, 30, 5, 0, time.UTC)
	base := "data.bin.conflict-laptop-20260710-143005"

	// With nothing on disk, the base name is used verbatim.
	if got := conflictCopyPath(root, "data.bin", "laptop", ts); got != base {
		t.Fatalf("first copy path = %q, want %q", got, base)
	}

	// Pre-create the base and the first two counters; the helper must skip past them.
	for _, name := range []string{base, base + "-1", base + "-2"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := conflictCopyPath(root, "data.bin", "laptop", ts), base+"-3"; got != want {
		t.Fatalf("collision copy path = %q, want %q", got, want)
	}
}
