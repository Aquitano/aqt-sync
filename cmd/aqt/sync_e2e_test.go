package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/server"
)

// TestSyncE2E drives the real CLI orchestration (runInit/runSync/runClone)
// against the real Gin router over HTTP — the seam where the data-loss bugs live
// and that unit tests never cross. It models two working copies of one folder on
// one account (two "machines"): init+push, clone, edit roundtrip, delete
// propagation, independent-edit merge, and a both-sides conflict resolved with
// --force.
func TestSyncE2E(t *testing.T) {
	h := newE2E(t)

	// One machine inits and pushes a tree with a small file, a nested file, and a
	// chunked file (larger than the inline cutoff, so it exercises chunk upload).
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	writeTree(t, origin, "big.dat", bigContent())
	h.sync(origin)
	id := h.folderID(origin)

	// A second machine clones it and must see byte-identical content.
	replica := t.TempDir()
	h.clone(id, replica)
	assertTreeEqual(t, origin, replica)
	if got := readTree(t, replica, "big.dat"); got != bigContent() {
		t.Fatal("chunked file did not round-trip through clone")
	}

	// Edit on origin propagates to replica through a push then a pull.
	writeTree(t, origin, "notes/todo.txt", "buy milk and eggs")
	h.sync(origin)
	h.sync(replica)
	if got := readTree(t, replica, "notes/todo.txt"); got != "buy milk and eggs" {
		t.Fatalf("edit did not propagate: %q", got)
	}

	// Delete on origin propagates as a delete, not a resurrection.
	removeTree(t, origin, "big.dat")
	h.sync(origin)
	h.sync(replica)
	assertAbsent(t, replica, "big.dat")

	// Independent edits to different files on both copies merge without conflict.
	writeTree(t, origin, "a.txt", "from origin")
	h.sync(origin)
	writeTree(t, replica, "b.txt", "from replica")
	h.sync(replica) // pulls a.txt, pushes b.txt
	h.sync(origin)  // pulls b.txt
	if got := readTree(t, origin, "b.txt"); got != "from replica" {
		t.Fatalf("origin missing merged b.txt: %q", got)
	}
	if got := readTree(t, replica, "a.txt"); got != "from origin" {
		t.Fatalf("replica missing merged a.txt: %q", got)
	}

	// A both-sides edit to the same file is a conflict: it aborts without --force,
	// and resolves local-wins with it.
	writeTree(t, origin, "notes/todo.txt", "origin edit")
	h.sync(origin)
	writeTree(t, replica, "notes/todo.txt", "replica edit")
	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected conflict abort, got %v", err)
	}
	h.syncOpts(replica, syncOptions{force: true}) // local (replica) wins
	h.sync(origin)
	if got := readTree(t, origin, "notes/todo.txt"); got != "replica edit" {
		t.Fatalf("force conflict resolution did not win: %q", got)
	}
	assertTreeEqual(t, origin, replica)
}

// TestSyncConflictCopyBothModified covers --conflicts=copy on a two-sided edit: the
// sync resolves without error (exit 0), local wins at the primary path, and the remote
// version lands in exactly one conflict-copy. A following round pushes the copy and the
// other replica pulls it, with no conflict re-triggered.
func TestSyncConflictCopyBothModified(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "base")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "notes/todo.txt", "origin edit")
	h.sync(origin)
	writeTree(t, replica, "notes/todo.txt", "replica edit")

	if err := runSync(replica, syncOptions{conflicts: "copy"}); err != nil {
		t.Fatalf("copy-mode sync: %v", err)
	}
	if got := readTree(t, replica, "notes/todo.txt"); got != "replica edit" {
		t.Fatalf("local did not win at the primary path: %q", got)
	}
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("expected exactly one conflict-copy, got %v", copies)
	}
	if got := readTree(t, replica, copies[0]); got != "origin edit" {
		t.Fatalf("conflict-copy content = %q, want the remote %q", got, "origin edit")
	}

	// The copy was written after the snapshot, so a following sync pushes it; origin
	// then pulls both the local-wins primary and the copy.
	h.sync(replica)
	h.sync(origin)
	assertTreeEqual(t, origin, replica)
	if got := readTree(t, origin, "notes/todo.txt"); got != "replica edit" {
		t.Fatalf("origin primary did not converge to local-wins: %q", got)
	}
	if got := readTree(t, origin, copies[0]); got != "origin edit" {
		t.Fatalf("origin missing pulled conflict-copy: %q", got)
	}
	// Both sides are now clean: the copy is ordinary content, not a standing conflict.
	h.sync(replica)
	h.sync(origin)
}

// TestSyncConflictCopyRetryDoesNotDuplicate exercises the push-conflict retry with a
// standing copy-mode conflict. The remote side is unchanged between attempts, so the
// copy the first attempt materialized must be reused, not re-materialized under a bumped
// suffix. A one-shot injected 409 on the folder commit stands in for another device that
// committed first, forcing reconcileWithRetry to re-plan the same conflict.
func TestSyncConflictCopyRetryDoesNotDuplicate(t *testing.T) {
	var armed, injected atomic.Bool
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if armed.Load() && r.Method == http.MethodPut && r.URL.Path == "/v1/resources" &&
			injected.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusConflict)
			return
		}
		pass(w, r)
	})

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "base")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "notes/todo.txt", "origin edit")
	h.sync(origin)
	writeTree(t, replica, "notes/todo.txt", "replica edit")

	// Arm the 409 only for the conflicting copy-mode sync, not the setup pushes above.
	armed.Store(true)
	if err := runSync(replica, syncOptions{conflicts: "copy"}); err != nil {
		t.Fatalf("copy-mode sync through retry: %v", err)
	}
	if !injected.Load() {
		t.Fatal("retry path never exercised: no 409 was injected on the folder commit")
	}

	if got := readTree(t, replica, "notes/todo.txt"); got != "replica edit" {
		t.Fatalf("local did not win at the primary path: %q", got)
	}
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("retry duplicated the conflict-copy: got %v, want exactly one", copies)
	}
	if got := readTree(t, replica, copies[0]); got != "origin edit" {
		t.Fatalf("conflict-copy content = %q, want the remote %q", got, "origin edit")
	}

	// The reused copy pushes and converges like a normal one, with no second conflict.
	h.sync(replica)
	h.sync(origin)
	assertTreeEqual(t, origin, replica)
}

// TestSyncConflictCopyLocalDeleteRemoteModify covers the delete-vs-modify conflict: the
// remote edit is preserved as a copy, the primary stays absent locally, and the remote
// primary is dropped (local delete wins), so it disappears from the other replica too.
func TestSyncConflictCopyLocalDeleteRemoteModify(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "doc.txt", "base")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "doc.txt", "origin edit")
	h.sync(origin)
	removeTree(t, replica, "doc.txt")

	if err := runSync(replica, syncOptions{conflicts: "copy"}); err != nil {
		t.Fatalf("copy-mode sync: %v", err)
	}
	assertAbsent(t, replica, "doc.txt")
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("expected one conflict-copy, got %v", copies)
	}
	if got := readTree(t, replica, copies[0]); got != "origin edit" {
		t.Fatalf("conflict-copy content = %q, want %q", got, "origin edit")
	}

	h.sync(replica) // push the copy
	h.sync(origin)
	assertAbsent(t, origin, "doc.txt")
	if got := readTree(t, origin, copies[0]); got != "origin edit" {
		t.Fatalf("origin missing pulled conflict-copy: %q", got)
	}
}

// TestSyncConflictCopyRemoteDeleteLocalModify covers the modify-vs-delete conflict: the
// remote has no bytes to preserve, so no copy is written; the local edit is kept and
// pushed, resurrecting the file on the other replica.
func TestSyncConflictCopyRemoteDeleteLocalModify(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "doc.txt", "base")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	removeTree(t, origin, "doc.txt")
	h.sync(origin)
	writeTree(t, replica, "doc.txt", "replica edit")

	if err := runSync(replica, syncOptions{conflicts: "copy"}); err != nil {
		t.Fatalf("copy-mode sync: %v", err)
	}
	if copies := globConflicts(t, replica); len(copies) != 0 {
		t.Fatalf("expected no conflict-copy when the remote deleted the file, got %v", copies)
	}
	if got := readTree(t, replica, "doc.txt"); got != "replica edit" {
		t.Fatalf("local edit was not kept: %q", got)
	}

	h.sync(origin)
	if got := readTree(t, origin, "doc.txt"); got != "replica edit" {
		t.Fatalf("origin did not receive the local-wins push: %q", got)
	}
}

// TestSyncConflictCopyValidation covers the flag-combination guards: copy is
// incompatible with --force, with the baseless --reconcile/--accept-rollback plans, and
// with a pack-and-seal folder.
func TestSyncConflictCopyValidation(t *testing.T) {
	h := newE2E(t)

	dir := t.TempDir()
	h.init(dir)
	if err := runSync(dir, syncOptions{conflicts: "copy", force: true}); err == nil ||
		!strings.Contains(err.Error(), "force") {
		t.Fatalf("copy+force: got %v, want a contradiction error", err)
	}
	if err := runSync(dir, syncOptions{conflicts: "copy", reconcile: true}); err == nil ||
		!strings.Contains(err.Error(), "three-way") {
		t.Fatalf("copy+reconcile: got %v, want a three-way error", err)
	}

	packDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(packDir, ".aqtconfig"), []byte(`{"pack":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	h.init(packDir)
	if err := runSync(packDir, syncOptions{conflicts: "copy"}); err == nil ||
		!strings.Contains(err.Error(), "pack-and-seal") {
		t.Fatalf("copy on a pack folder: got %v, want a pack error", err)
	}
	if err := runSync(packDir, syncOptions{conflicts: "merge"}); err == nil ||
		!strings.Contains(err.Error(), "pack-and-seal") {
		t.Fatalf("merge on a pack folder: got %v, want a pack error", err)
	}
}

func TestSyncConflictMergeCleanAndOverlapFallback(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes.md", "one\ntwo\nthree\nfour\n")
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "notes.md", "ONE\ntwo\nthree\nfour\n")
	h.sync(origin)
	writeTree(t, replica, "notes.md", "one\ntwo\nthree\nFOUR\n")
	h.syncOpts(replica, syncOptions{conflicts: "merge"})
	if got, want := readTree(t, replica, "notes.md"), "ONE\ntwo\nthree\nFOUR\n"; got != want {
		t.Fatalf("clean merge = %q, want %q", got, want)
	}
	if copies := globConflicts(t, replica); len(copies) != 0 {
		t.Fatalf("clean merge wrote conflict copies: %v", copies)
	}
	h.sync(origin)
	assertTreeEqual(t, origin, replica)

	writeTree(t, origin, "notes.md", "ORIGIN\ntwo\nthree\nFOUR\n")
	h.sync(origin)
	writeTree(t, replica, "notes.md", "REPLICA\ntwo\nthree\nFOUR\n")
	h.syncOpts(replica, syncOptions{conflicts: "merge"})
	if got := readTree(t, replica, "notes.md"); got != "REPLICA\ntwo\nthree\nFOUR\n" {
		t.Fatalf("overlap did not keep local primary: %q", got)
	}
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("overlap conflict copies = %v, want exactly one", copies)
	}
	if got := readTree(t, replica, copies[0]); got != "ORIGIN\ntwo\nthree\nFOUR\n" {
		t.Fatalf("overlap copy lost remote bytes: %q", got)
	}
	if bytes.Contains([]byte(readTree(t, replica, "notes.md")), []byte("<<<<<<<")) {
		t.Fatal("merge fallback wrote conflict markers")
	}
	h.sync(replica) // publish the local-only conflict copy
	h.sync(origin)
	assertTreeEqual(t, origin, replica)
}

// Merged bytes stay live until the post-CAS write, so the peak is the sum over every
// conflict in the sync, not the per-file cap. Past the budget a conflict has to take
// the copy path — and has to say so, or a copy nobody asked for reads as an overlap
// the merge could not resolve.
func TestSyncConflictMergeBudgetFallsBackToCopy(t *testing.T) {
	original := maxMergedBytesHeld
	t.Cleanup(func() { maxMergedBytesHeld = original })

	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	body := func(first, last string) string {
		return first + "\ntwo\nthree\n" + last + "\n"
	}
	for _, name := range []string{"a.md", "b.md"} {
		writeTree(t, origin, name, body("one", "four"))
	}
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Both files gain a non-overlapping edit on each side: both would merge cleanly.
	for _, name := range []string{"a.md", "b.md"} {
		writeTree(t, origin, name, body("ONE", "four"))
	}
	h.sync(origin)
	for _, name := range []string{"a.md", "b.md"} {
		writeTree(t, replica, name, body("one", "FOUR"))
	}

	// Room for the first merge only. Candidates are visited in action order, so a.md
	// merges and b.md is pushed to the copy path.
	maxMergedBytesHeld = len(body("ONE", "FOUR"))

	var stderr string
	stderr = captureStderr(t, func() {
		h.syncOpts(replica, syncOptions{conflicts: "merge"})
	})
	if got, want := readTree(t, replica, "a.md"), body("ONE", "FOUR"); got != want {
		t.Fatalf("first conflict did not merge within budget: %q, want %q", got, want)
	}
	if got, want := readTree(t, replica, "b.md"), body("one", "FOUR"); got != want {
		t.Fatalf("over-budget conflict did not keep local primary: %q, want %q", got, want)
	}
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("over-budget conflict copies = %v, want exactly one", copies)
	}
	if got, want := readTree(t, replica, copies[0]), body("ONE", "four"); got != want {
		t.Fatalf("over-budget copy lost remote bytes: %q, want %q", got, want)
	}
	if !strings.Contains(stderr, "1 further conflict(s) kept both versions") {
		t.Fatalf("budget fallback was silent:\n%s", stderr)
	}

	// The deferred conflict merges on the next run, once the budget is not the limit.
	maxMergedBytesHeld = original
	h.sync(replica)
	h.sync(origin)
	assertTreeEqual(t, origin, replica)
}

func TestSyncConflictMergeKeepsEditMadeWhilePUTIsInFlight(t *testing.T) {
	var armed, blocked atomic.Bool
	putStarted := make(chan struct{})
	releasePUT := make(chan struct{})
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if armed.Load() && r.Method == http.MethodPut && r.URL.Path == "/v1/resources" &&
			blocked.CompareAndSwap(false, true) {
			close(putStarted)
			<-releasePUT
		}
		pass(w, r)
	})

	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "notes.md", "one\ntwo\nthree\nfour\n")
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "notes.md", "ONE\ntwo\nthree\nfour\n")
	h.sync(origin)
	writeTree(t, replica, "notes.md", "one\ntwo\nthree\nFOUR\n")

	armed.Store(true)
	result := make(chan error, 1)
	go func() { result <- runSync(replica, syncOptions{conflicts: "merge"}) }()
	<-putStarted
	newer := "one\nTWO\nthree\nFOUR\n"
	writeTree(t, replica, "notes.md", newer)
	close(releasePUT)
	if err := <-result; !errors.Is(err, errConflictsRemain) {
		t.Fatalf("merge with local drift: want errConflictsRemain, got %v", err)
	}
	if got := readTree(t, replica, "notes.md"); got != newer {
		t.Fatalf("merge clobbered newer local edit: %q", got)
	}

	armed.Store(false)
	if err := runSync(replica, syncOptions{conflicts: "merge"}); err != nil {
		t.Fatalf("reconcile preserved edit: %v", err)
	}
	if got, want := readTree(t, replica, "notes.md"), "ONE\nTWO\nthree\nFOUR\n"; got != want {
		t.Fatalf("reconciled merge = %q, want %q", got, want)
	}
}

func TestSyncConflictMergeMissingBaseChunkFallsBackToCopy(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	lines := make([]string, 700)
	for i := range lines {
		lines[i] = fmt.Sprintf("base line %04d", i)
	}
	base := strings.Join(lines, "\n") + "\n"
	writeTree(t, origin, "chunked.txt", base)
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	originLines := append([]string(nil), lines...)
	for i := range originLines {
		originLines[i] = fmt.Sprintf("remote replacement %04d", i)
	}
	remote := strings.Join(originLines, "\n") + "\n"
	writeTree(t, origin, "chunked.txt", remote)
	h.sync(origin)

	profile, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	removed, _, err := h.store.GCPacks(profile.OwnerHandle, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed == 0 {
		t.Fatal("forced GC removed no packs; test did not make the base content unavailable")
	}

	replicaLines := append([]string(nil), lines...)
	replicaLines[len(replicaLines)-1] = "local replacement at the end"
	local := strings.Join(replicaLines, "\n") + "\n"
	writeTree(t, replica, "chunked.txt", local)
	h.syncOpts(replica, syncOptions{conflicts: "merge"})
	if got := readTree(t, replica, "chunked.txt"); got != local {
		t.Fatalf("missing-base fallback did not keep local primary")
	}
	copies := globConflicts(t, replica)
	if len(copies) != 1 {
		t.Fatalf("missing-base conflict copies = %v, want exactly one", copies)
	}
	if got := readTree(t, replica, copies[0]); got != remote {
		t.Fatalf("missing-base copy lost remote bytes")
	}
}

// globConflicts returns the tracked conflict-copy files under root (paths containing
// the ".conflict-" marker), skipping the .aqt control directory.
func globConflicts(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".aqt" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if strings.Contains(filepath.ToSlash(rel), ".conflict-") {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMixedVersionUpgradeRequired proves the point of issue #69: a client that hits a
// future write-format boundary gets an actionable upgrade error, not an opaque
// decryption failure. A folder syncs normally, then its resource's min_client is
// bumped past this build's capability (simulating a device that wrote a newer
// format); a clone must fail with client.ErrUpgradeRequired before any decrypt runs.
func TestMixedVersionUpgradeRequired(t *testing.T) {
	h := newE2E(t)
	origin := filepath.Join(t.TempDir(), "origin")

	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	h.sync(origin)
	id := h.folderID(origin)

	// Simulate a resource sealed in a format newer than this build reads. No client
	// can declare this over the wire (the server 400s a declaration above the writer's
	// own capability), so the test reaches through the store the harness owns.
	if err := h.store.SetResourceMinClientForTest(id, api.ClientCapability+1); err != nil {
		t.Fatalf("bump min_client: %v", err)
	}

	err := runClone(id, filepath.Join(t.TempDir(), "replica"), false, "")
	if !errors.Is(err, client.ErrUpgradeRequired) {
		t.Fatalf("clone error = %v, want client.ErrUpgradeRequired", err)
	}
	// The gate must fire at the API layer, before the client tries (and fails) to open
	// the blob — the whole point is to replace the AEAD failure with a clear message.
	if strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("error mentions decryption (%q); it must fail before any decrypt attempt", err.Error())
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("error = %q, want an actionable upgrade hint", err.Error())
	}
}

// A located-but-missing object surfaces client.ErrNotFound, which the reconcile
// loop maps to a conflict-retry: a manifest whose objects were GC'd by a concurrent
// supersede is re-read against the current version instead of hard-failing.
func TestPackSourceMissingObjectIsNotFound(t *testing.T) {
	src := &packSource{
		locs:    map[string]api.ObjectLocation{},
		objSpan: map[string]packSpan{},
		cache:   newPackCache(1),
	}
	if _, err := src.get("deadbeef"); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("get of an unlocated object = %v, want client.ErrNotFound", err)
	}
}

// TestSyncDedupHoldsOnResync covers the Phase 1 acceptance: a re-sync with no local
// changes uploads no new packs (the have/want gate dedups), and a clone reconstructs
// the chunked content byte-for-byte from the packs.
func TestSyncDedupHoldsOnResync(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "big.dat", bigContent())
	writeTree(t, origin, "notes.txt", "small inline file")
	h.sync(origin)

	afterFirst := h.countPacks()
	if afterFirst == 0 {
		t.Fatal("first sync of a chunked file should have uploaded at least one pack")
	}

	// A second sync with nothing changed must upload no new packs.
	h.sync(origin)
	if got := h.countPacks(); got != afterFirst {
		t.Fatalf("no-op re-sync changed pack count: %d -> %d (dedup did not hold)", afterFirst, got)
	}

	// A fresh clone reconstructs the chunked file exactly, fetching from packs.
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if got := readTree(t, replica, "big.dat"); got != bigContent() {
		t.Fatal("clone did not reconstruct the chunked file from packs")
	}
	assertTreeEqual(t, origin, replica)
}

// TestSyncRefusesMissingBase covers C7: a sync with no base must refuse rather
// than reconcile against an empty base (which resurrects deletions), and
// --reconcile must surface one-sided differences as conflicts.
func TestSyncRefusesMissingBase(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "keep.txt", "data")
	h.sync(origin)

	// Drop the base, as a botched restore or older build would.
	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
		t.Fatal(err)
	}
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errSyncNoBase) {
		t.Fatalf("expected errSyncNoBase, got %v", err)
	}
	// With identical local and remote, --reconcile finds nothing to do and rebuilds
	// the base, so the next plain sync works again.
	h.syncOpts(origin, syncOptions{reconcile: true})
	h.sync(origin)
}

// TestLsAndFindDecryptNames covers the new listing/search path: `ls` must decrypt
// resource names and sizes, and `find` must expand a tracked folder into its
// member files so a single index covers everything.
func TestLsAndFindDecryptNames(t *testing.T) {
	h := newE2E(t)

	// A single-file push.
	fdir := t.TempDir()
	fpath := filepath.Join(fdir, "secret.env")
	if err := os.WriteFile(fpath, []byte("API_KEY=xyz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}

	// A tracked folder with a nested file.
	folder := t.TempDir()
	h.init(folder)
	writeTree(t, folder, "notes/todo.txt", "buy milk")
	h.sync(folder)

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
	var sawFile, sawFolder bool
	for _, r := range rows {
		if r.Kind == api.KindFile && r.Name == "secret.env" {
			sawFile = true
		}
		if r.Kind == api.KindFolder && r.Name == filepath.Base(folder) {
			sawFolder = true
		}
	}
	if !sawFile {
		t.Errorf("ls did not surface the decrypted file name; rows=%+v", rows)
	}
	if !sawFolder {
		t.Errorf("ls did not surface the folder; rows=%+v", rows)
	}

	entries, err := buildFindIndex(cl, mk)
	if err != nil {
		t.Fatalf("buildFindIndex: %v", err)
	}
	var memberRef string
	for _, e := range entries {
		if e.Kind == kindFolderFile && e.Path == "notes/todo.txt" {
			memberRef = e.Ref
		}
	}
	if memberRef == "" {
		t.Fatalf("find did not surface the folder member; entries=%+v", entries)
	}
	// The member ref carries the subpath, so it composes with pull to fetch just
	// that file: `aqt pull "$(aqt find)"`.
	if want := "/notes/todo.txt"; !strings.HasSuffix(memberRef, want) {
		t.Errorf("member ref = %q, want aqt://<id>%s", memberRef, want)
	}
	dest := filepath.Join(t.TempDir(), "todo.txt")
	if err := runPull(memberRef, dest, "", false, false); err != nil {
		t.Fatalf("pull of find ref: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || string(got) != "buy milk" {
		t.Errorf("pulled member = %q, %v; want %q", got, err, "buy milk")
	}
}

// TestSyncSymlinkBecomesDir covers the type-change transition the per-entry symlink
// guard used to wedge: a tracked symlink is replaced on one machine by a directory of
// files. Pulling it must remove the stale local symlink and create the directory, not
// abort on "descends through a symlink" and leave the folder stuck.
func TestSyncSymlinkBecomesDir(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "target.txt", "data")
	if err := os.Symlink("target.txt", filepath.Join(origin, "link")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if fi, err := os.Lstat(filepath.Join(replica, "link")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("clone did not reproduce the symlink: mode=%v err=%v", fi.Mode(), err)
	}

	// Replace the symlink with a directory containing a file, and propagate it.
	if err := os.Remove(filepath.Join(origin, "link")); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "link/inner.txt", "inside")
	h.sync(origin)
	h.sync(replica)

	if got := readTree(t, replica, "link/inner.txt"); got != "inside" {
		t.Fatalf("symlink->dir did not propagate: %q", got)
	}
	if fi, err := os.Lstat(filepath.Join(replica, "link")); err != nil || !fi.IsDir() {
		t.Fatalf("replica link is not a directory: mode=%v err=%v", fi.Mode(), err)
	}
}

// --- harness ---

type e2eHarness struct {
	t       *testing.T
	url     string
	dataDir string
	store   *server.Store
}

func newE2E(t *testing.T) *e2eHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	home := t.TempDir()
	isolateConfigEnv(t, home)

	dataDir := t.TempDir()
	store, err := server.OpenStore(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	ts := httptest.NewServer(server.New(store).Router())
	t.Cleanup(ts.Close)

	h := &e2eHarness{t: t, url: ts.URL, dataDir: dataDir, store: store}
	h.signup("e2e@example.com", "correct horse battery staple")
	return h
}

// newE2EWithProxy is newE2E with a reverse proxy in front of the server, so a test can
// intercept requests (e.g. inject a one-shot 409 to force a version-conflict retry).
// intercept is called for every request and either handles it or forwards via pass.
func newE2EWithProxy(t *testing.T, intercept func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc)) *e2eHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	home := t.TempDir()
	isolateConfigEnv(t, home)

	dataDir := t.TempDir()
	store, err := server.OpenStore(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	backend := httptest.NewServer(server.New(store).Router())
	t.Cleanup(backend.Close)
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		intercept(w, r, proxy.ServeHTTP)
	}))
	t.Cleanup(front.Close)

	h := &e2eHarness{t: t, url: front.URL, dataDir: dataDir, store: store}
	h.signup("e2e@example.com", "correct horse battery staple")
	return h
}

// countPacks returns how many pack files the server has stored, so a test can
// assert that a no-op re-sync uploads nothing (dedup holds).
func (h *e2eHarness) countPacks() int {
	h.t.Helper()
	n := 0
	err := filepath.WalkDir(filepath.Join(h.dataDir, "packs"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".bin") {
			n++
		}
		return nil
	})
	if err != nil {
		h.t.Fatalf("count packs: %v", err)
	}
	return n
}

// signup registers an account against the test server and writes the profile +
// cached session to the temp config dir, so the run* commands authenticate and
// unlock without prompting.
func (h *e2eHarness) signup(email, pass string) {
	h.t.Helper()
	kdf, err := crypto.NewKdfParams()
	if err != nil {
		h.t.Fatal(err)
	}
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		h.t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(pass, kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		h.t.Fatal(err)
	}
	cl, err := client.New(h.url, "")
	if err != nil {
		h.t.Fatalf("client.New: %v", err)
	}
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "e2e",
	})
	if err != nil {
		h.t.Fatalf("signup: %v", err)
	}
	if err := identity.Save(&identity.Profile{
		Name: identity.DefaultProfile, Server: h.url, Email: email,
		OwnerHandle: resp.OwnerHandle, DeviceID: resp.DeviceID, Token: resp.Token,
		Kdf: kdf, WrappedRoot: wrappedRoot, AuthEpoch: resp.Epoch,
	}); err != nil {
		h.t.Fatalf("save profile: %v", err)
	}
	if err := identity.SaveSession(identity.DefaultProfile, mk, time.Hour); err != nil {
		h.t.Fatalf("save session: %v", err)
	}
}

// unlockSession re-caches the master key, standing in for the `aqt login` that
// follows an `aqt lock`.
func (h *e2eHarness) unlockSession() {
	h.t.Helper()
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		h.t.Fatal(err)
	}
	mk, err := prof.Unlock("correct horse battery staple")
	if err != nil {
		h.t.Fatalf("unlock: %v", err)
	}
	if err := identity.SaveSession(identity.DefaultProfile, mk, time.Hour); err != nil {
		h.t.Fatalf("save session: %v", err)
	}
}

func (h *e2eHarness) init(dir string) {
	h.t.Helper()
	if err := runInit(dir); err != nil {
		h.t.Fatalf("init %s: %v", dir, err)
	}
}

func (h *e2eHarness) clone(id, dir string) {
	h.t.Helper()
	if err := runClone(id, dir, false, ""); err != nil {
		h.t.Fatalf("clone %s: %v", id, err)
	}
}

func (h *e2eHarness) sync(dir string) { h.syncOpts(dir, syncOptions{}) }

func (h *e2eHarness) syncOpts(dir string, opts syncOptions) {
	h.t.Helper()
	if err := runSync(dir, opts); err != nil {
		h.t.Fatalf("sync %s: %v", dir, err)
	}
}

func (h *e2eHarness) folderID(dir string) string {
	h.t.Helper()
	st, err := loadState(dir)
	if err != nil {
		h.t.Fatalf("load state %s: %v", dir, err)
	}
	return st.ID
}

// --- tree helpers ---

func writeTree(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func removeTree(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
		t.Fatal(err)
	}
}

func readTree(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func assertAbsent(t *testing.T, root, rel string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s absent, lstat err=%v", rel, err)
	}
}

// collectTree maps every tracked file (path -> content) under root, skipping the
// .aqt control directory.
func collectTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if rel == ".aqt" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertTreeEqual(t *testing.T, a, b string) {
	t.Helper()
	ta, tb := collectTree(t, a), collectTree(t, b)
	for path, want := range ta {
		got, ok := tb[path]
		if !ok {
			t.Fatalf("%s present in %s but missing in %s", path, a, b)
		}
		if got != want {
			t.Fatalf("%s differs between copies", path)
		}
	}
	for path := range tb {
		if _, ok := ta[path]; !ok {
			t.Fatalf("%s present in %s but missing in %s", path, b, a)
		}
	}
}

// bigContent returns content well above the inline cutoff with enough variation
// for content-defined chunking to find boundaries (multiple chunks).
func bigContent() string {
	var b strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&b, "line %05d: the quick brown fox jumps over the lazy dog\n", i)
	}
	return b.String()
}

// TestSyncLargeMultiPackRoundTrip pushes several packs' worth of unique, incompressible
// data so the concurrent upload pipeline dispatches multiple packs at once and Flush
// must wait for all of them before the resource is rooted. A clone then has to
// reconstruct every byte, which fails if any dispatched pack was lost or a wait skipped.
func TestSyncLargeMultiPackRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the multi-pack upload test under -short")
	}
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)

	// 48 MiB of distinct random bytes => ~3 DefaultPackTarget-sized packs, none of
	// which dedups against another.
	files := map[string][]byte{
		"a.bin": randomBytes(t, 16<<20),
		"b.bin": randomBytes(t, 16<<20),
		"c.bin": randomBytes(t, 16<<20),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(origin, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.sync(origin)

	if n := h.countPacks(); n < 2 {
		t.Fatalf("expected multiple packs from 48 MiB of unique data, got %d", n)
	}

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(replica, name))
		if err != nil {
			t.Fatalf("read cloned %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("cloned %s differs from origin (%d vs %d bytes)", name, len(got), len(want))
		}
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return b
}
