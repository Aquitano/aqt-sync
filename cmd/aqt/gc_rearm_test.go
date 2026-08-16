package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The pre-PUT re-check must stay off the wire for ordinary pushes and fire only
// once a push has outlived gcRearmThreshold; swept ids fail with the re-run
// guidance instead of reaching the manifest PUT (#177).
func TestRearmUploadedChunks(t *testing.T) {
	t.Parallel()
	calls := 0
	present := func(ids []string) ([]string, error) { calls++; return nil, nil }

	if err := rearmUploadedChunks(present, []string{"a"}, time.Now()); err != nil || calls != 0 {
		t.Fatalf("fresh push: err=%v calls=%d, want no round trip", err, calls)
	}
	if err := rearmUploadedChunks(present, []string{"a"}, time.Time{}); err != nil || calls != 0 {
		t.Fatalf("zero start: err=%v calls=%d, want no round trip", err, calls)
	}

	old := time.Now().Add(-gcRearmThreshold - time.Minute)
	if err := rearmUploadedChunks(present, []string{"a"}, old); err != nil || calls != 1 {
		t.Fatalf("long push, all present: err=%v calls=%d, want one re-check and no error", err, calls)
	}

	swept := func(ids []string) ([]string, error) { return ids[:1], nil }
	if err := rearmUploadedChunks(swept, []string{"a", "b"}, old); err == nil || !strings.Contains(err.Error(), "re-run") {
		t.Fatalf("swept ids = %v, want the re-run recovery guidance", err)
	}

	boom := func(ids []string) ([]string, error) { return nil, errors.New("boom") }
	if err := rearmUploadedChunks(boom, []string{"a"}, old); err == nil {
		t.Fatal("check error must propagate, not be swallowed")
	}
}
