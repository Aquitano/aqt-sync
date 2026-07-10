package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/client"
)

// pullFreshErr pulls ref as a fresh link holder and returns the pull error (nil on
// success), so a test can assert a link has gone away.
func pullFreshErr(t *testing.T, ref, password string) error {
	t.Helper()
	var perr error
	withFreshEnv(t, func() {
		out := filepath.Join(t.TempDir(), "out.bin")
		perr = runPull(ref, out, password, false, false)
	})
	return perr
}

// A --public --burn push serves exactly one pull; the second gets the gone error and
// exit code 7.
func TestPushBurnPullOnce(t *testing.T) {
	newE2E(t)
	id, data, ref := pushRandomStreamedFile(t, 1024, pushOptions{
		public: true, noClip: true, quiet: true, policy: linkPolicy{maxReads: 1},
	})
	_ = id

	got := pullFresh(t, ref, "")
	if len(got) != len(data) {
		t.Fatalf("first pull got %d bytes, want %d", len(got), len(data))
	}
	err := pullFreshErr(t, ref, "")
	if !errors.Is(err, client.ErrGone) {
		t.Fatalf("second pull err = %v, want ErrGone", err)
	}
	if code := exitCode(err); code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
}

// A --public --max-reads 2 inline push serves two pulls; the third is gone.
func TestPushMaxReadsInline(t *testing.T) {
	newE2E(t)
	_, data, ref := pushRandomStreamedFile(t, 512, pushOptions{
		public: true, noClip: true, quiet: true, policy: linkPolicy{maxReads: 2},
	})

	for i := 0; i < 2; i++ {
		if got := pullFresh(t, ref, ""); len(got) != len(data) {
			t.Fatalf("pull %d got %d bytes, want %d", i, len(got), len(data))
		}
	}
	if err := pullFreshErr(t, ref, ""); !errors.Is(err, client.ErrGone) {
		t.Fatalf("third pull err = %v, want ErrGone", err)
	}
}

// A streamed --public --burn push completes its single permitted pull in full (object
// fetches after the root read succeed), and a second pull is gone at the root.
func TestStreamedBurnPull(t *testing.T) {
	h := newE2E(t)
	_, data, ref := pushRandomStreamedFile(t, 9<<20, pushOptions{
		public: true, noClip: true, quiet: true, policy: linkPolicy{maxReads: 1},
	})
	_ = h

	got := pullFresh(t, ref, "")
	if len(got) != len(data) {
		t.Fatalf("streamed pull got %d bytes, want %d", len(got), len(data))
	}
	if err := pullFreshErr(t, ref, ""); !errors.Is(err, client.ErrGone) {
		t.Fatalf("second streamed pull err = %v, want ErrGone", err)
	}
}

// `aqt share --expire` applies a policy after the fact; poking the stored expiry into
// the past makes the link gone.
func TestShareExpireAfterFact(t *testing.T) {
	h := newE2E(t)

	src := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(src, []byte("shared with a deadline"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimSpace(captureStdout(t, func() {
		if err := runPush(src, pushOptions{noClip: true, quiet: true}); err != nil {
			t.Fatalf("push: %v", err)
		}
	}))
	id, _, _ := parseRef(ref)

	shareRef := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, "", true, linkPolicy{expireSeconds: 3600}); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	// Sanity: it is pullable before the deadline.
	if got := pullFresh(t, shareRef, ""); string(got) != "shared with a deadline" {
		t.Fatalf("pre-expiry pull = %q", got)
	}
	// Poke the stored expiry into the past, then the link is gone.
	if err := h.store.SetResourceExpiryForTest(id, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := pullFreshErr(t, shareRef, ""); !errors.Is(err, client.ErrGone) {
		t.Fatalf("post-expiry pull err = %v, want ErrGone", err)
	}
}

// The flag layer rejects --burn with --max-reads and a policy without --public.
func TestPushPolicyFlagValidation(t *testing.T) {
	cmd := pushCmd()
	cmd.SetArgs([]string{"somefile", "--burn", "--max-reads", "2"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--burn with --max-reads should be a usage error")
	}

	cmd = pushCmd()
	cmd.SetArgs([]string{"somefile", "--max-reads", "1"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--public") {
		t.Fatalf("policy without --public err = %v, want a --public usage error", err)
	}
}
