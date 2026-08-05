package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestCompareWorkingTreeToRemote drives `aqt diff --against=remote` through the real
// CLI and server across the states the comparison has to tell apart. The cases that
// matter most are the two `status` cannot express: converged-both, where each side
// made the same edit independently and the trees agree even though both are ahead of
// the base, and conflicting, where both moved and the trees disagree.
func TestCompareWorkingTreeToRemote(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	writeTree(t, origin, "notes/todo.txt", "buy milk\n")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Clean: the clone matches the remote it came from.
	out := mustCompare(t, replica, nil)
	if !strings.Contains(out, "no differences") {
		t.Fatalf("fresh clone is not reported clean:\n%s", out)
	}
	if !strings.Contains(out, "->  working tree") || !strings.Contains(out, "remote (v") {
		t.Fatalf("header does not name both sides:\n%s", out)
	}

	// Local-only: the working tree moved, the remote did not.
	writeTree(t, replica, "a.txt", "alpha local\n")
	out = mustCompare(t, replica, nil)
	if !strings.Contains(out, "M  a.txt") {
		t.Fatalf("local-only edit not reported:\n%s", out)
	}

	// Remote-only: the server moved, the working tree did not. The path is still
	// "M" — the two states differ — but it differs in the other direction.
	writeTree(t, replica, "a.txt", "alpha\n") // undo the local edit
	writeTree(t, origin, "notes/todo.txt", "buy milk and eggs\n")
	writeTree(t, origin, "remote-only.txt", "server side\n")
	h.sync(origin)
	out = mustCompare(t, replica, nil)
	if !strings.Contains(out, "M  notes/todo.txt") {
		t.Fatalf("remote-only edit not reported:\n%s", out)
	}
	// Present on the remote, absent from the working tree: a removal going
	// remote -> working tree, which is why the header names the direction.
	if !strings.Contains(out, "D  remote-only.txt") {
		t.Fatalf("remote-only addition not reported as absent locally:\n%s", out)
	}

	// Converged: both sides reach the same content independently. `status` would
	// report a local change and an incoming change; the comparison reports neither,
	// because the two states genuinely agree.
	writeTree(t, replica, "notes/todo.txt", "buy milk and eggs\n")
	writeTree(t, replica, "remote-only.txt", "server side\n")
	out = mustCompare(t, replica, nil)
	if !strings.Contains(out, "no differences") {
		t.Fatalf("converged trees not reported identical:\n%s", out)
	}
	// The same state, through the base, is two pending changes on each side.
	if st := captureStdout(t, func() { mustStatus(t, replica) }); !strings.Contains(st, "incoming") {
		t.Fatalf("expected status to still see base-relative work:\n%s", st)
	}

	// Conflicting: both sides move the same path to different content.
	writeTree(t, origin, "a.txt", "alpha from origin\n")
	h.sync(origin)
	writeTree(t, replica, "a.txt", "alpha from replica\n")
	out = mustCompare(t, replica, nil)
	if !strings.Contains(out, "M  a.txt") {
		t.Fatalf("conflicting edit not reported:\n%s", out)
	}

	// Path filters narrow the comparison without changing its classification.
	out = mustCompare(t, replica, []string{"notes"})
	if strings.Contains(out, "a.txt") {
		t.Fatalf("path filter leaked an unrelated path:\n%s", out)
	}
}

// TestCompareRemoteReportsDirsModesAndTypes pins that the comparison inherits the
// shared manifest classification rather than re-deriving a files-only view: a tracked
// directory, a permission-only edit, and a file-to-symlink switch each surface as
// themselves.
func TestCompareRemoteReportsDirsModesAndTypes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits and symlinks are not faithfully tracked on Windows")
	}
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "script.sh", "echo hi\n")
	writeTree(t, origin, "keep/file.txt", "x\n")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	if err := os.Chmod(filepath.Join(replica, "script.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(replica, "fresh-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(replica, "keep", "file.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(replica, "keep", "file.txt")); err != nil {
		t.Fatal(err)
	}

	out := mustCompare(t, replica, nil)
	for _, want := range []string{"P  script.sh", "A  fresh-dir/", "T  keep/file.txt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("comparison missing %q:\n%s", want, out)
		}
	}
}

// TestCompareRemoteJSONReportsCompleteness covers the machine-readable contract: a
// complete comparison says so, and a locked session reports a stable reason with both
// sides still named rather than an empty change list a caller would read as "clean".
func TestCompareRemoteJSONReportsCompleteness(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	h.sync(origin)
	writeTree(t, origin, "a.txt", "alpha edited\n")

	got := mustCompareJSON(t, origin)
	if !got.Complete || got.Reason != "" {
		t.Fatalf("unlocked comparison reported incomplete: %+v", got)
	}
	if len(got.Modified) != 1 || got.Modified[0] != "a.txt" {
		t.Fatalf("modified bucket = %v", got.Modified)
	}
	if got.Left.Label != "remote" || got.Left.Version == 0 || got.Right.Label != "working tree" {
		t.Fatalf("sides not named: %+v / %+v", got.Left, got.Right)
	}

	mk, ok := identity.LoadSession(identity.DefaultProfile)
	if !ok {
		t.Fatal("expected a cached session from the harness")
	}
	if err := identity.ClearSession(identity.DefaultProfile); err != nil {
		t.Fatalf("clear session: %v", err)
	}
	defer func() {
		if err := identity.SaveSession(identity.DefaultProfile, mk, time.Hour); err != nil {
			t.Fatalf("restore session: %v", err)
		}
	}()

	locked := mustCompareJSON(t, origin)
	if locked.Complete {
		t.Fatalf("locked session reported a complete comparison: %+v", locked)
	}
	if locked.Reason != reasonSessionLocked {
		t.Fatalf("locked reason = %q, want %q", locked.Reason, reasonSessionLocked)
	}
	// The version is knowable without the folder key, so it is still reported.
	if locked.Left.Version == 0 {
		t.Fatalf("locked comparison dropped the remote version: %+v", locked.Left)
	}
	if len(locked.Changes) != 0 || locked.Added == nil || locked.Modified == nil {
		t.Fatalf("locked comparison should carry empty, non-null lists: %+v", locked)
	}

	// The human rendering must not print an empty list that reads as "no differences".
	var err error
	text := captureStdout(t, func() {
		err = runDiff(origin, nil, diffOptions{against: diffAgainstRemote, nameStatus: true})
	})
	if err != nil {
		t.Fatalf("locked comparison errored instead of reporting itself: %v", err)
	}
	if strings.Contains(text, "no differences") || !strings.Contains(text, "session is locked") {
		t.Fatalf("locked human output is misleading:\n%s", text)
	}
}

// TestCompareRemoteIsReadOnly is the guarantee the command rests on: comparing must
// never move the folder's synced state, or it would silently change what the next
// sync decides to do.
func TestCompareRemoteIsReadOnly(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	writeTree(t, origin, "a.txt", "alpha edited\n")
	writeTree(t, origin, "added.txt", "new\n")
	h.sync(origin)
	writeTree(t, replica, "local.txt", "mine\n")

	before := controlSnapshot(t, replica)
	mustCompare(t, replica, nil)
	mustCompareJSON(t, replica)
	if after := controlSnapshot(t, replica); after != before {
		t.Fatalf("comparison mutated .aqt control state:\nbefore: %s\nafter:  %s", before, after)
	}
	// The remote-only file must not have landed, and the local-only file must survive.
	if _, err := os.Stat(filepath.Join(replica, "added.txt")); !os.IsNotExist(err) {
		t.Fatalf("comparison downloaded a remote file into the working tree (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(replica, "local.txt")); err != nil {
		t.Fatalf("comparison disturbed a local-only file: %v", err)
	}
}

// TestCompareRemotePackAndSeal covers the folder shape with no per-file remote
// metadata: the comparison streams the sealed segments back through memory and still
// reports a truthful per-entry answer.
func TestCompareRemotePackAndSeal(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	writeTree(t, origin, "notes/todo.txt", "buy milk\n")
	h.sync(origin)

	if out := mustCompare(t, origin, nil); !strings.Contains(out, "no differences") {
		t.Fatalf("synced pack folder is not reported clean:\n%s", out)
	}

	writeTree(t, origin, "a.txt", "alpha edited\n")
	writeTree(t, origin, "fresh.txt", "new\n")
	removeTree(t, origin, "notes/todo.txt")

	before := controlSnapshot(t, origin)
	out := mustCompare(t, origin, nil)
	for _, want := range []string{"M  a.txt", "A  fresh.txt", "D  notes/todo.txt"} {
		if !strings.Contains(out, want) {
			t.Fatalf("pack comparison missing %q:\n%s", want, out)
		}
	}
	if after := controlSnapshot(t, origin); after != before {
		t.Fatal("pack comparison mutated .aqt control state")
	}
}

// TestCompareRemoteUnreachableServer pins the failure mode that would be worst: a
// server that cannot be reached must be an error, never an empty comparison a caller
// would read as "the trees agree".
func TestCompareRemoteUnreachableServer(t *testing.T) {
	var down atomic.Bool
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if down.Load() && strings.HasPrefix(r.URL.Path, "/v1/resources/") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		pass(w, r)
	})
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	h.sync(origin)
	down.Store(true)

	var err error
	out := captureStdout(t, func() {
		err = runDiff(origin, nil, diffOptions{against: diffAgainstRemote, nameStatus: true})
	})
	if err == nil {
		t.Fatalf("unreachable server did not fail the comparison:\n%s", out)
	}
	if strings.Contains(out, "no differences") {
		t.Fatalf("unreachable server produced a clean-looking comparison:\n%s", out)
	}
}

// TestNameStatusCoversEveryDiffMode pins that --name-status is a renderer, not a
// feature of one mode: each side pairing `aqt diff` supports reports classified paths
// under the sides it actually compared.
func TestNameStatusCoversEveryDiffMode(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	h.sync(origin)
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cl.CreateSnapshot(h.folderID(origin), nil, false)
	if err != nil {
		t.Fatal(err)
	}

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	writeTree(t, replica, "local.txt", "mine\n")
	writeTree(t, origin, "a.txt", "alpha edited\n")
	h.sync(origin)

	run := func(opts diffOptions) string {
		t.Helper()
		opts.nameStatus = true
		var err error
		out := captureStdout(t, func() { err = runDiff(replica, nil, opts) })
		if err != nil {
			t.Fatalf("diff %+v: %v", opts, err)
		}
		return out
	}

	if out := run(diffOptions{}); !strings.Contains(out, "last-synced base") ||
		!strings.Contains(out, "->  working tree") || !strings.Contains(out, "A  local.txt") {
		t.Fatalf("base-versus-working-tree name-status:\n%s", out)
	}
	if out := run(diffOptions{remote: true}); !strings.Contains(out, "last-synced base") ||
		!strings.Contains(out, "->  remote (v") || !strings.Contains(out, "M  a.txt") {
		t.Fatalf("base-versus-remote name-status:\n%s", out)
	}
	if out := run(diffOptions{against: snapshot.ID}); !strings.Contains(out, "snapshot "+snapshot.ID) ||
		!strings.Contains(out, "->  working tree") || !strings.Contains(out, "A  local.txt") {
		t.Fatalf("snapshot-versus-working-tree name-status:\n%s", out)
	}
}

// TestCompareRemoteSeesStatPreservingEdit guards the shortcut a comparison must not
// take: an edit that keeps a file's size, mode, and mtime is invisible to the stat
// fast-path `status` relies on, but the two trees still differ.
func TestCompareRemoteSeesStatPreservingEdit(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha\n")
	h.sync(origin)

	path := filepath.Join(origin, "a.txt")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ALPHA\n"), 0o644); err != nil { // same length
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}

	if out := mustCompare(t, origin, nil); !strings.Contains(out, "M  a.txt") {
		t.Fatalf("stat-preserving edit went unnoticed:\n%s", out)
	}
}

func TestComparisonFilterKeepsRenamesAndRebuildsBuckets(t *testing.T) {
	c := newComparison(
		diffSide{Label: "remote", Version: 3},
		diffSide{Label: "working tree"},
		syncengine.Delta{
			Changes: []syncengine.Change{
				{Path: "notes/new.md", Kind: syncengine.ChangeAdded, Type: syncengine.ChildFile},
				{Path: "src/main.go", Kind: syncengine.ChangeContent, Type: syncengine.ChildFile},
			},
			Renamed: []syncengine.Rename{{From: "notes/old.md", To: "docs/moved.md"}},
		},
	)

	got := c.filter([]string{"notes"})
	if len(got.Added) != 1 || got.Added[0] != "notes/new.md" {
		t.Fatalf("added bucket not rebuilt from the filtered changes: %v", got.Added)
	}
	if len(got.Modified) != 0 {
		t.Fatalf("filter kept an unmatched path: %v", got.Modified)
	}
	// The rename's source is inside the filter, so the move stays visible as a move.
	if len(got.Renamed) != 1 {
		t.Fatalf("filter dropped a rename with a matching side: %v", got.Renamed)
	}
	if !got.Complete || got.Left.Version != 3 {
		t.Fatalf("filter lost the comparison's identity: %+v", got)
	}
	if none := c.filter([]string{"nothing-here"}); none.total() != 0 || none.Added == nil {
		t.Fatalf("empty filter result should carry empty, non-null lists: %+v", none)
	}
}

// --- helpers ---

func mustCompare(t *testing.T, dir string, paths []string) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		err = runDiff(dir, paths, diffOptions{against: diffAgainstRemote, nameStatus: true})
	})
	if err != nil {
		t.Fatalf("compare %s: %v", dir, err)
	}
	return out
}

func mustCompareJSON(t *testing.T, dir string) comparison {
	t.Helper()
	prev := flagJSON
	flagJSON = true
	defer func() { flagJSON = prev }()

	var err error
	out := captureStdout(t, func() {
		err = runDiff(dir, nil, diffOptions{against: diffAgainstRemote})
	})
	if err != nil {
		t.Fatalf("compare --json %s: %v", dir, err)
	}
	var got comparison
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode comparison JSON (%s): %v", out, err)
	}
	return got
}

// controlSnapshot serializes the folder's synced state — the base manifest and the
// pinned remote version — so a test can assert a read-only command left both alone.
func controlSnapshot(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{baseFile, stateFile} {
		data, err := os.ReadFile(controlPath(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.WriteString(name + "=" + string(data) + "\n")
	}
	return b.String()
}
