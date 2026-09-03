// SPDX-License-Identifier: AGPL-3.0-or-later

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
	if err := pushQuiet(fpath, pushOptions{noClip: true}); err != nil {
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

	if err := runRemove([]string{id}, false, true); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if _, err := cl.GetResource(id); !errors.Is(err, client.ErrNotFound) {
		t.Errorf("after rm, GetResource err = %v, want ErrNotFound", err)
	}
	// A second rm of the same id reports it gone rather than succeeding silently.
	if err := runRemove([]string{id}, false, true); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("rm of deleted id err = %v, want a not-found error", err)
	}
}

// TestRmSnapshotSemantics checks that a plain rm leaves the resource's snapshots
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
		if err := pushQuiet(p, pushOptions{noClip: true}); err != nil {
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
	if _, err := cl.CreateSnapshot(kept, nil, false); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := runRemove([]string{kept}, false, true); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if snaps, err := cl.ListSnapshots(kept); err != nil || len(snaps) != 1 {
		t.Fatalf("after plain rm: snaps=%d err=%v, want 1 (snapshot retained)", len(snaps), err)
	}

	// --with-snapshots: the cascade deletes the snapshot too.
	cascade := push("cascade.env", "SECRET=2")
	if _, err := cl.CreateSnapshot(cascade, nil, false); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := runRemove([]string{cascade}, true, true); err != nil {
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
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// TestEverydayResourceRefsAndRename covers issue #90's common loop end to end:
// rename by name, inspect/share/delete by the renamed name, and retain content.
func TestEverydayResourceRefsAndRename(t *testing.T) {
	newE2E(t)
	path := filepath.Join(t.TempDir(), "original.txt")
	const body = "metadata-only rename keeps these bytes"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pushQuiet(path, pushOptions{noClip: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if err := runShare("original.txt", "", true, linkPolicy{maxReads: 3, onExpiry: "retire"}); err != nil {
		t.Fatalf("share by name: %v", err)
	}
	if err := runRename("original.txt", "renamed.txt"); err != nil {
		t.Fatalf("rename by name: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runInfo("renamed.txt", "", false); err != nil {
			t.Fatalf("info by name: %v", err)
		}
	})
	if !strings.Contains(out, "renamed.txt") {
		t.Fatalf("info did not resolve renamed name: %q", out)
	}
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	id, err := resolveOwnedResourceIDWithProfile(cl, prof, "renamed.txt")
	if err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := runPull(id, "", "", true, false); err != nil {
			t.Fatalf("cat renamed resource: %v", err)
		}
	})
	if out != body {
		t.Fatalf("renamed content = %q, want %q", out, body)
	}
	out = captureStdout(t, func() {
		if err := runInfo("renamed.txt", "", false); err != nil {
			t.Fatalf("info lifecycle: %v", err)
		}
	})
	if !strings.Contains(out, "0/3") || !strings.Contains(out, "3 remaining") {
		t.Fatalf("info omitted read lifecycle: %q", out)
	}
	if err := runRemove([]string{"renamed.txt"}, false, true); err != nil {
		t.Fatalf("rm by name: %v", err)
	}
}

// TestResolveTrackedResourcePath confirms the tracked root itself resolves to
// its resource id, while a path inside it is refused instead of silently
// widening to the whole folder resource.
func TestResolveTrackedResourcePath(t *testing.T) {
	h := newE2E(t)
	root := t.TempDir()
	h.init(root)
	nested := filepath.Join(root, "not-yet-created", "file.txt")

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("expected cached master key")
	}
	t.Chdir(root)
	if _, ok, err := trackedResourceID("remote-name"); ok || err != nil {
		t.Fatalf("bare name treated as tracked path: ok=%v err=%v", ok, err)
	}
	got, err := resolveOwnedResourceID(cl, mk, root)
	if err != nil {
		t.Fatalf("resolve tracked root: %v", err)
	}
	if want := h.folderID(root); got != want {
		t.Fatalf("resolved id = %q, want %q", got, want)
	}
	if _, err := resolveOwnedResourceID(cl, mk, nested); err == nil || !strings.Contains(err.Error(), "inside the tracked folder") {
		t.Fatalf("nested path err = %v, want inside-tracked-folder refusal", err)
	}
}

// TestFriendlyNameMustBeUnique prevents an arbitrary same-name resource from
// being selected for a destructive or sharing command.
func TestFriendlyNameMustBeUnique(t *testing.T) {
	newE2E(t)
	for _, body := range []string{"one", "two"} {
		path := filepath.Join(t.TempDir(), "source.txt")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := pushQuiet(path, pushOptions{name: "duplicate", noClip: true}); err != nil {
			t.Fatalf("push duplicate: %v", err)
		}
	}
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("expected cached master key")
	}
	if _, err := resolveOwnedResourceID(cl, mk, "duplicate"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate name err = %v, want ambiguity", err)
	}
}

// The NAME column `aqt ls` prints is an argument too: pull, cat, clone, and the
// folder form of ls resolve it, so a script never has to look an id up first.
func TestPullCatCloneLsResolveNames(t *testing.T) {
	h := newE2E(t)

	const body = "API_KEY=xyz"
	path := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pushQuiet(path, pushOptions{noClip: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	out := captureStdout(t, func() {
		if err := runPull("secret.env", "", "", true, false); err != nil {
			t.Fatalf("cat by name: %v", err)
		}
	})
	if out != body {
		t.Errorf("cat by name = %q, want %q", out, body)
	}

	// A tracked folder is named after its directory, so `vault` addresses it.
	dir := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(dir)
	writeTree(t, dir, "notes.md", "hello")
	h.sync(dir)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("expected cached master key")
	}
	rows, err := collectFolderRows(cl, mk, "vault")
	if err != nil {
		t.Fatalf("ls by name: %v", err)
	}
	if len(rows) != 2 { // notes.md plus the starter .aqtignore
		t.Errorf("ls by name rows = %+v, want notes.md and .aqtignore", rows)
	}

	dest := filepath.Join(t.TempDir(), "copy")
	if err := runClone("vault", dest, false, ""); err != nil {
		t.Fatalf("clone by name: %v", err)
	}
	if got := readTree(t, dest, "notes.md"); got != "hello" {
		t.Errorf("cloned notes.md = %q, want hello", got)
	}

	// A name that matches nothing names the argument forms it accepts, instead of
	// implying the resource exists and belongs to someone else.
	err = runPull("no-such-resource", "", "", true, false)
	if err == nil || !strings.Contains(err.Error(), "unique name") {
		t.Errorf("pull of an unknown name err = %v, want the accepted-forms message", err)
	}
}
