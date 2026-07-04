package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// TestInfoCatRm exercises the single-resource commands against the real router:
// info shows decrypted metadata, cat decrypts to stdout byte-for-byte, and rm
// deletes the resource so a later fetch 404s.
func TestInfoCatRm(t *testing.T) {
	newE2E(t)

	fdir := t.TempDir()
	fpath := filepath.Join(fdir, "secret.env")
	content := []byte("API_KEY=xyz")
	if err := os.WriteFile(fpath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("expected a cached session")
	}
	rows, err := collectResources(cl, mk)
	if err != nil {
		t.Fatalf("collectResources: %v", err)
	}
	var id string
	for _, r := range rows {
		if r.Name == "secret.env" {
			id = r.ID
		}
	}
	if id == "" {
		t.Fatalf("pushed resource not in listing; rows=%+v", rows)
	}

	out := captureStdout(t, func() {
		if err := runInfo(id, "", false); err != nil {
			t.Fatalf("info: %v", err)
		}
	})
	if !strings.Contains(out, "secret.env") || !strings.Contains(out, "private") {
		t.Errorf("info output missing name/visibility: %q", out)
	}

	out = captureStdout(t, func() {
		if err := runPull(id, "", "", true, false); err != nil {
			t.Fatalf("cat: %v", err)
		}
	})
	if out != string(content) {
		t.Errorf("cat output = %q, want %q", out, content)
	}

	if err := runRemove([]string{id}, false); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := cl.GetResource(id); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("after rm, GetResource err = %v, want ErrNotFound", err)
	}
	// A second rm of the same id reports it gone rather than succeeding silently.
	if err := runRemove([]string{id}, false); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("rm of deleted id err = %v, want a not-found error", err)
	}
}

// TestRmSnapshotSemantics covers 1.5: a plain rm leaves the resource's snapshots
// pinning its ciphertext (still fetchable), while --with-snapshots cascades the delete
// so nothing keeps the data alive.
func TestRmSnapshotSemantics(t *testing.T) {
	newE2E(t)
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}

	push := func(name, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := runPush(p, pushOptions{noClip: true, quiet: true}); err != nil {
			t.Fatalf("push %s: %v", name, err)
		}
		rows, err := collectResources(cl, mk)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Name == name {
				return r.ID
			}
		}
		t.Fatalf("pushed %s not in listing", name)
		return ""
	}

	// Default rm: the snapshot survives, so the ciphertext is still retained.
	kept := push("keep.env", "SECRET=1")
	if _, err := cl.CreateSnapshot(kept, nil); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := runRemove([]string{kept}, false); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if snaps, err := cl.ListSnapshots(kept); err != nil || len(snaps) != 1 {
		t.Fatalf("after plain rm: snaps=%d err=%v, want 1 (snapshot retained)", len(snaps), err)
	}

	// --with-snapshots: the cascade deletes the snapshot too.
	cascade := push("cascade.env", "SECRET=2")
	if _, err := cl.CreateSnapshot(cascade, nil); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := runRemove([]string{cascade}, true); err != nil {
		t.Fatalf("rm --with-snapshots: %v", err)
	}
	if snaps, err := cl.ListSnapshots(cascade); err != nil || len(snaps) != 0 {
		t.Fatalf("after cascade rm: snaps=%d err=%v, want 0", len(snaps), err)
	}
}

// captureStdout redirects os.Stdout for the duration of fn and returns what it
// wrote, so a test can assert on the human-facing output of cat/info.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}
