// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// runCmd executes a freshly-built command with the given args, failing the test on
// error. It exercises the real cobra RunE (flag parsing, authedClient, output).
func runCmd(t *testing.T, cmd interface {
	SetArgs([]string)
	Execute() error
}, args ...string) {
	t.Helper()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("command %v: %v", args, err)
	}
}

// checkpoint saves an anchored, named snapshot; restore resolves it by that name and
// rolls the tree back, both side-by-side and in place over a modified tree.
func TestCheckpointRestoreByName(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "original A")
	writeTree(t, src, "sub/b.txt", "original B")
	h.sync(src)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	rid := h.folderID(src)

	runCmd(t, checkpointCmd(), "release-1", src)

	// The checkpoint exists, is anchored, and its name decrypts locally.
	snaps, err := cl.ListSnapshots(rid)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("list = %d err=%v, want 1", len(snaps), err)
	}
	if !snaps[0].Anchored {
		t.Fatal("checkpoint snapshot is not anchored")
	}
	mk, err := unlockMaster(prof)
	if err != nil {
		t.Fatal(err)
	}
	if _, label := snapshotNameLabel(snaps[0], mk); label != "release-1" {
		t.Fatalf("label = %q, want 'release-1'", label)
	}
	mk.Wipe()

	// Move the live state on.
	writeTree(t, src, "a.txt", "CHANGED A")
	removeTree(t, src, "sub/b.txt")
	writeTree(t, src, "c.txt", "new C")
	h.sync(src)

	// Restore by name, side-by-side into a fresh dir: must match the pre-mutation tree.
	dest := filepath.Join(t.TempDir(), "restored")
	runCmd(t, restoreCmd(), "release-1", src, "--out", dest)
	if c := readTree(t, dest, "a.txt"); c != "original A" {
		t.Fatalf("side-by-side a.txt = %q", c)
	}
	if c := readTree(t, dest, "sub/b.txt"); c != "original B" {
		t.Fatalf("side-by-side sub/b.txt = %q", c)
	}
	assertAbsent(t, dest, "c.txt")

	// Restore by name in place over the modified tree: the live folder rolls back
	// only with the explicit --in-place (side-by-side is the default).
	runCmd(t, restoreCmd(), "release-1", src, "--in-place", "-y")
	if c := readTree(t, src, "a.txt"); c != "original A" {
		t.Fatalf("in-place a.txt = %q", c)
	}
	if c := readTree(t, src, "sub/b.txt"); c != "original B" {
		t.Fatalf("in-place sub/b.txt = %q", c)
	}
	assertAbsent(t, src, "c.txt")
}

// restore resolves a bare snapshot id, reports a clear error for an unknown name, and
// disambiguates a reused name by preferring the anchored snapshot.
func TestRestoreByIDAndAmbiguity(t *testing.T) {
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

	// Two snapshots share the label "dup"; neither anchored yet.
	sealed, err := sealSnapshotLabel(cl, prof, rid, "dup")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cl.CreateSnapshot(rid, sealed, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cl.CreateSnapshot(rid, sealed, false)
	if err != nil {
		t.Fatal(err)
	}

	// Ambiguous name errors with the candidate ids.
	if _, err := resolveRestoreTarget(cl, prof, "dup", src, ""); err == nil ||
		!strings.Contains(err.Error(), "matches 2 snapshots") {
		t.Fatalf("ambiguous restore err = %v, want a candidates listing", err)
	}

	// Unknown name (and not an id) errors clearly.
	if _, err := resolveRestoreTarget(cl, prof, "nope", src, ""); err == nil ||
		!strings.Contains(err.Error(), "no checkpoint named") {
		t.Fatalf("unknown restore err = %v", err)
	}

	// A bare snapshot id still resolves.
	got, err := resolveRestoreTarget(cl, prof, first.ID, src, "")
	if err != nil || got.Snapshot.ID != first.ID {
		t.Fatalf("by-id restore = %v err=%v, want %s", got.Snapshot.ID, err, first.ID)
	}

	// Anchoring one of the duplicates disambiguates by name.
	if _, err := cl.SetSnapshotAnchor(second.ID, true); err != nil {
		t.Fatal(err)
	}
	got, err = resolveRestoreTarget(cl, prof, "dup", src, "")
	if err != nil || got.Snapshot.ID != second.ID {
		t.Fatalf("anchored-preferred restore = %v err=%v, want %s", got.Snapshot.ID, err, second.ID)
	}
}

// The server refuses to prune an anchored snapshot over the wire (409 -> a typed
// error naming the escape hatch); removing the anchor makes the same delete succeed.
func TestAnchoredDeleteRefusedOverWire(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "hi")
	h.sync(src)

	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	rid := h.folderID(src)
	snap, err := cl.CreateSnapshot(rid, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	err = cl.DeleteSnapshot(snap.ID)
	if !errors.Is(err, client.ErrSnapshotAnchored) {
		t.Fatalf("delete anchored = %v, want ErrSnapshotAnchored", err)
	}
	if !strings.Contains(err.Error(), "snapshot unanchor") {
		t.Fatalf("refusal message %q does not name the escape hatch", err)
	}

	info, err := cl.SetSnapshotAnchor(snap.ID, false)
	if err != nil || info.Anchored {
		t.Fatalf("unanchor = %v anchored=%v", err, info.Anchored)
	}
	if err := cl.DeleteSnapshot(snap.ID); err != nil {
		t.Fatalf("delete after unanchor = %v, want nil", err)
	}
}

// setSnapshotAnchor fails closed when the server echoes a state that does not match the
// requested one — a server that ignores the anchor field entirely.
func TestSetSnapshotAnchorFailsClosed(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo a snapshot with no anchored field, so it reads back as unanchored.
		json.NewEncoder(w).Encode(map[string]any{"id": "s1"})
	}))
	t.Cleanup(stub.Close)
	cl, err := client.New(stub.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := setSnapshotAnchor(cl, "s1", true); err == nil || !strings.Contains(err.Error(), "did not apply the anchor change") {
		t.Fatalf("setSnapshotAnchor against an unanchoring server = %v, want a fail-closed error", err)
	}
}

// anchorStrippingProxy fronts the real server but strips the "anchor" field from every
// create-snapshot request, so the backend stores an unanchored snapshot — what a server
// that dropped the field on the floor would leave behind.
func anchorStrippingProxy(t *testing.T, backend string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	base := rp.Director
	rp.Director = func(req *http.Request) {
		base(req)
		if req.Method != http.MethodPost || req.URL.Path != "/v1/snapshots" || req.Body == nil {
			return
		}
		body, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return
		}
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			delete(m, "anchor")
			body, _ = json.Marshal(m)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	ts := httptest.NewServer(rp)
	t.Cleanup(ts.Close)
	return ts
}

// Against a server that ignores the anchor field, checkpoint must fail closed: it
// deletes the unprotected snapshot it just created and errors, so no prunable
// "checkpoint" is left behind.
func TestCheckpointFailsClosedWhenTheServerDropsTheAnchor(t *testing.T) {
	h := newE2E(t)
	src := filepath.Join(t.TempDir(), "work")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	h.init(src)
	writeTree(t, src, "a.txt", "hi")
	h.sync(src)

	// A client at the real server, to inspect the aftermath.
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	rid := h.folderID(src)

	// Point the profile at the anchor-stripping proxy (an explicit --server that
	// contradicts the folder's recorded server is rejected by the identity binding,
	// so the proxy has to look like the profile's own server moving).
	proxy := anchorStrippingProxy(t, h.url)
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	prof.Server = proxy.URL
	if err := identity.Save(prof); err != nil {
		t.Fatal(err)
	}

	cmd := checkpointCmd()
	cmd.SetArgs([]string{"release-1", src})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "did not anchor the checkpoint") {
		t.Fatalf("checkpoint against an anchor-dropping server = %v, want a fail-closed error", err)
	}

	// The half-checkpoint was cleaned up: no snapshot lingers.
	if snaps, err := cl.ListSnapshots(rid); err != nil || len(snaps) != 0 {
		t.Fatalf("after fail-closed: %d snapshots err=%v, want 0", len(snaps), err)
	}
}
