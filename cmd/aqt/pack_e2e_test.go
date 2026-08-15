package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// TestPackSyncE2E drives a pack-and-seal folder (.aqtconfig pack=true) through the
// real CLI and server: init+push, clone, edit and delete propagation, and a
// both-sides conflict. Unlike the chunked path, reconciliation is whole-folder
// last-writer-wins, so even edits to different files collide.
func TestPackSyncE2E(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha")
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	big := make([]byte, (4<<20)+512) // spans more than one segment
	for i := range big {
		big[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(origin, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)

	// A no-op resync of a pack folder uploads nothing (no change to re-ship).
	packsAfterPush := h.countPacks()
	h.sync(origin)
	if got := h.countPacks(); got != packsAfterPush {
		t.Fatalf("no-op pack resync changed pack count: %d -> %d", packsAfterPush, got)
	}

	// Clone reconstructs the tree (including the multi-segment file) byte-for-byte.
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	assertTreeEqual(t, origin, replica)
	if got, _ := os.ReadFile(filepath.Join(replica, "big.bin")); string(got) != string(big) {
		t.Fatal("multi-segment file did not round-trip through clone")
	}

	// An edit on origin propagates to replica through a push then a pull.
	writeTree(t, origin, "notes/todo.txt", "buy milk and eggs")
	h.sync(origin)
	h.sync(replica)
	if got := readTree(t, replica, "notes/todo.txt"); got != "buy milk and eggs" {
		t.Fatalf("edit did not propagate: %q", got)
	}

	// A delete propagates as a delete (the pull prunes it), not a resurrection.
	removeTree(t, origin, "big.bin")
	h.sync(origin)
	h.sync(replica)
	assertAbsent(t, replica, "big.bin")

	// Independent edits to different files still conflict: pack-and-seal reconciles
	// the whole folder at once, so there is no per-file merge.
	writeTree(t, origin, "x.txt", "from origin")
	h.sync(origin)
	writeTree(t, replica, "y.txt", "from replica")
	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected folder-level conflict, got %v", err)
	}

	// --force resolves local-wins: replica's whole tree supersedes origin's, so
	// origin's x.txt is dropped when origin pulls.
	h.syncOpts(replica, syncOptions{force: true})
	h.sync(origin)
	assertAbsent(t, origin, "x.txt")
	if got := readTree(t, origin, "y.txt"); got != "from replica" {
		t.Fatalf("force resolution did not win: %q", got)
	}
	assertTreeEqual(t, origin, replica)
}

// TestPackSyncRefusesMissingBase mirrors the chunked guard for pack folders: a sync
// with no base refuses, and --reconcile rebuilds it when local and remote match.
func TestPackSyncRefusesMissingBase(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "keep.txt", "data")
	h.sync(origin)

	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
		t.Fatal(err)
	}
	if err := runSync(origin, syncOptions{}); !errors.Is(err, errSyncNoBase) {
		t.Fatalf("expected errSyncNoBase, got %v", err)
	}
	h.syncOpts(origin, syncOptions{reconcile: true}) // identical trees: rebuild base
	h.sync(origin)                                   // base restored, plain sync works
}

// TestPackDirectionalFlagsConflict verifies a directional flag does not silently
// discard the other side. When both sides changed since the last sync, --pull-only
// must conflict instead of overwriting and pruning the local working copy, and
// --push-only must conflict instead of clobbering the remote; --force then makes the
// chosen direction an explicit, opted-in resolution.
func TestPackDirectionalFlagsConflict(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "shared.txt", "v0")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Diverge both sides from the cloned base.
	writeTree(t, origin, "shared.txt", "origin edit")
	h.sync(origin)
	writeTree(t, replica, "keep-local.txt", "only on replica")

	// --pull-only would extract origin's tree over the replica and prune the
	// local-only file; it must conflict, and the local work must survive untouched.
	if err := runSync(replica, syncOptions{pullOnly: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("--pull-only with both sides changed: want errConflictsRemain, got %v", err)
	}
	if got := readTree(t, replica, "keep-local.txt"); got != "only on replica" {
		t.Fatalf("--pull-only destroyed local work: %q", got)
	}
	// --push-only would clobber origin's edit; it must conflict too.
	if err := runSync(replica, syncOptions{pushOnly: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("--push-only with both sides changed: want errConflictsRemain, got %v", err)
	}

	// --force --pull-only resolves local-wins, matching the hint and the chunked
	// path: the replica keeps its own tree and does not take origin's edit, so the
	// unsynced local file survives.
	h.syncOpts(replica, syncOptions{pullOnly: true, force: true})
	if got := readTree(t, replica, "shared.txt"); got != "v0" {
		t.Fatalf("--force --pull-only clobbered local: %q, want %q", got, "v0")
	}
	if got := readTree(t, replica, "keep-local.txt"); got != "only on replica" {
		t.Fatalf("--force --pull-only destroyed local work: %q", got)
	}
}

// TestPackReconcileNoBaseDiffers covers the baseless --reconcile branch the existing
// missing-base test skips: when local and remote actually differ with no base to
// judge add-vs-delete, it must conflict, and --force resolves local-wins and rebuilds
// a base the next plain sync accepts.
func TestPackReconcileNoBaseDiffers(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "remote value")
	h.sync(origin)

	// Drop the base and change the file so local != remote with nothing to reconcile
	// against.
	if err := os.Remove(controlPath(origin, baseFile)); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "a.txt", "local value")
	if err := runSync(origin, syncOptions{reconcile: true}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("baseless reconcile of differing trees: want errConflictsRemain, got %v", err)
	}

	// --force pushes local-wins and rebuilds the base; a fresh clone proves the remote
	// now holds the local value.
	h.syncOpts(origin, syncOptions{reconcile: true, force: true})
	h.sync(origin)
	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if got := readTree(t, replica, "a.txt"); got != "local value" {
		t.Fatalf("force reconcile did not push local value: %q", got)
	}
}

// TestChunkedSyncRefusesPackedFolder guards the silent tree-wipe: a pack-and-seal
// folder whose local .aqtconfig no longer carries pack=true is routed through the
// chunked sync path. That path must refuse it (the resource metadata says packed),
// not read an empty manifest and delete every local file.
func TestChunkedSyncRefusesPackedFolder(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	writePackConfig(t, dir)
	h.init(dir)
	writeTree(t, dir, "keep.txt", "data")
	writeTree(t, dir, "nested/also.txt", "more")
	h.sync(dir)

	// Drop pack=true so runSync routes this packed folder through the chunked path.
	if err := os.Remove(filepath.Join(dir, ".aqtconfig")); err != nil {
		t.Fatal(err)
	}
	if err := runSync(dir, syncOptions{}); err == nil {
		t.Fatal("chunked sync of a packed folder did not error")
	}
	if got := readTree(t, dir, "keep.txt"); got != "data" {
		t.Fatalf("keep.txt was damaged by the refused sync: %q", got)
	}
	if got := readTree(t, dir, "nested/also.txt"); got != "more" {
		t.Fatalf("nested/also.txt was damaged by the refused sync: %q", got)
	}
}

func TestDecidePack(t *testing.T) {
	cases := []struct {
		name          string
		local, remote bool
		opts          syncOptions
		want          packDecision
	}{
		{"clean", false, false, syncOptions{}, packNoop},
		{"local only", true, false, syncOptions{}, packPush},
		{"remote only", false, true, syncOptions{}, packPull},
		{"both", true, true, syncOptions{}, packConflict},
		{"both forced", true, true, syncOptions{force: true}, packPush},
		// A directional flag must not silently discard the other side: when it also
		// changed, the restricted action is a conflict until --force makes it explicit.
		{"both push-only", true, true, syncOptions{pushOnly: true}, packConflict},
		{"both pull-only", true, true, syncOptions{pullOnly: true}, packConflict},
		{"both push-only forced", true, true, syncOptions{pushOnly: true, force: true}, packPush},
		{"both pull-only forced", true, true, syncOptions{pullOnly: true, force: true}, packNoop},
		{"push-only no local", false, true, syncOptions{pushOnly: true}, packNoop},
		{"pull-only no remote", true, false, syncOptions{pullOnly: true}, packNoop},
		{"push-only local only", true, false, syncOptions{pushOnly: true}, packPush},
		{"pull-only remote only", false, true, syncOptions{pullOnly: true}, packPull},
	}
	for _, c := range cases {
		if got := decidePack(c.local, c.remote, c.opts); got != c.want {
			t.Errorf("%s: decidePack(%v,%v) = %d, want %d", c.name, c.local, c.remote, got, c.want)
		}
	}
}

func TestPartitionDeletesByDownload(t *testing.T) {
	downloads := []syncengine.Entry{{Path: "link/inner.txt"}, {Path: "a/b/c.txt"}, {Path: "top.txt"}, {Path: "foo"}}
	deletes := []string{"link", "a/b", "top.txt", "unrelated", "foo/x", "foo/y"}

	early, late := partitionDeletesByDownload(deletes, downloads)

	// "link" and "a/b" are ancestors of a download path (a file/symlink became a dir),
	// and "foo/x"/"foo/y" are descendants of the download "foo" (a directory became a
	// file), so all run first. "top.txt" equals a download path but does not nest with
	// it (a file replaced by a file, handled by rename), and "unrelated" matches nothing.
	wantEarly := map[string]bool{"link": true, "a/b": true, "foo/x": true, "foo/y": true}
	for _, p := range early {
		if !wantEarly[p] {
			t.Errorf("unexpected early delete %q", p)
		}
		delete(wantEarly, p)
	}
	if len(wantEarly) != 0 {
		t.Errorf("missing early deletes: %v", wantEarly)
	}
	wantLate := map[string]bool{"top.txt": true, "unrelated": true}
	for _, p := range late {
		if !wantLate[p] {
			t.Errorf("unexpected late delete %q", p)
		}
	}
}

// TestPackPullSparesFileCreatedDuringPull covers the 1.4 prune guard: a file that
// appears after the pull's scan (modeled here by a scan taken before it is created) is
// a local add for the next sync, not this version's garbage, so the prune must leave
// it. The same pull still applies the remote edit and prunes a file the remote genuinely
// dropped. Driving pullPack directly with a stale scan makes the download-window race
// deterministic.
func TestPackPullSparesFileCreatedDuringPull(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "A")
	writeTree(t, origin, "stale.txt", "S")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// Origin edits a.txt and drops stale.txt; the remote is now {a.txt: "A2"}.
	writeTree(t, origin, "a.txt", "A2")
	removeTree(t, origin, "stale.txt")
	h.sync(origin)

	// Scan the replica as it stood before the pull, then create a local-only file after
	// that scan: exactly a file landing during the download window.
	localScan, err := syncengine.Scan(replica)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, replica, "created-during-pull.txt", "local-only")

	c, res, ck := replicaPullCtx(t, replica, localScan)
	defer ck.Wipe()
	if err := pullPack(c, res, ck); err != nil {
		t.Fatalf("pullPack: %v", err)
	}

	if got := readTree(t, replica, "a.txt"); got != "A2" {
		t.Fatalf("a.txt = %q, want the pulled edit A2", got)
	}
	assertAbsent(t, replica, "stale.txt") // remote genuinely dropped it
	if got := readTree(t, replica, "created-during-pull.txt"); got != "local-only" {
		t.Fatalf("prune deleted a file created during the pull: %q", got)
	}
}

// TestPackPullKeepsDriftedLocalEdit covers the 1.4 extract guard: a file edited after
// the pull's scan keeps its local bytes instead of being clobbered by the incoming
// tree, and the pull reports a conflict rather than silently overwriting.
func TestPackPullKeepsDriftedLocalEdit(t *testing.T) {
	h := newE2E(t)
	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "A")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "a.txt", "A2")
	h.sync(origin)

	// Scan before an edit that lands during the download window.
	localScan, err := syncengine.Scan(replica)
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, replica, "a.txt", "local edit mid-pull")

	c, res, ck := replicaPullCtx(t, replica, localScan)
	defer ck.Wipe()
	if err := pullPack(c, res, ck); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("drift during pull: want errConflictsRemain, got %v", err)
	}
	if got := readTree(t, replica, "a.txt"); got != "local edit mid-pull" {
		t.Fatalf("drift guard clobbered the local edit: %q", got)
	}
}

// replicaPullCtx assembles the packCtx/resource/key a direct pullPack needs, letting a
// test supply a deliberately stale scan as c.local to reproduce a mid-pull race.
func replicaPullCtx(t *testing.T, dir string, local syncengine.Manifest) (packCtx, api.GetResourceResponse, crypto.ContentKey) {
	t.Helper()
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.GetResource(st.ID)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	sess := syncSession{root: dir, st: st, cl: cl, mk: mk}
	return packCtx{syncSession: sess, local: local, push: &packPushArtifacts{}}, res, ck
}

func writePackConfig(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".aqtconfig"), []byte(`{"pack": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPackSyncDirectoryOnlyChanges is the regression for the pack-and-seal local-change
// gate: it consulted the file planner alone, so a change that touches no file — an
// empty directory appearing or disappearing, or a directory's mode being edited — was
// reported as already synced and never pushed.
func TestPackSyncDirectoryOnlyChanges(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "alpha")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	// An empty directory is the whole change: no file differs on either side.
	if err := os.Mkdir(filepath.Join(origin, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	h.sync(replica)
	assertDir(t, replica, "empty")

	// Removing it is equally invisible to a file-level comparison.
	if err := os.Remove(filepath.Join(origin, "empty")); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	h.sync(replica)
	assertAbsent(t, replica, "empty")
}

// A directory-mode-only edit propagates on platforms where directory permission bits
// round-trip. Windows Chmod carries only the write bit, so a mode-only edit is not
// representable there and the sync would have nothing to observe.
func TestPackSyncDirectoryModeOnlyChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not round-trip on Windows")
	}
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "notes/todo.txt", "buy milk")
	if err := os.Chmod(filepath.Join(origin, "notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	if err := os.Chmod(filepath.Join(origin, "notes"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	h.sync(replica)

	fi, err := os.Stat(filepath.Join(replica, "notes"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode did not propagate: got %o, want 0700", got)
	}
}

func assertDir(t *testing.T, root, rel string) {
	t.Helper()
	fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("stat %s: %v", rel, err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", rel)
	}
}

// An interrupted pack-and-seal pull leaves a tree that is part remote version and
// part stale, which decidePack reads as "changed on both sides". Before the pull
// marker, the printed hint pointed at --force, which maps to a push: the torn tree
// was tarred and committed as the new authoritative version, destroying the intact
// remote folder. A folder with a marker must pull instead, whatever --force says.
func TestInterruptedPackPullResumesInsteadOfPushing(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "v1")
	writeTree(t, origin, "b.txt", "v1")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "a.txt", "v2")
	writeTree(t, origin, "b.txt", "v2")
	writeTree(t, origin, "c.txt", "v2")
	h.sync(origin)

	// The shape an interrupted pull leaves: a.txt already carries the new version,
	// b.txt and c.txt do not, and the marker names the version being landed.
	writeTree(t, replica, "a.txt", "v2")
	if err := beginPullMarker(replica, 2); err != nil {
		t.Fatal(err)
	}

	// A push of a torn tree cannot be right, so --push-only says so rather than
	// shipping it.
	err := runSync(replica, syncOptions{pushOnly: true, force: true})
	if err == nil {
		t.Fatal("--push-only --force pushed a torn tree")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("error does not name the interrupted pull: %v", err)
	}

	// --force would otherwise resolve local-wins by pushing. It must finish the pull.
	h.syncOpts(replica, syncOptions{force: true})
	assertTreeEqual(t, origin, replica)
	if got := readTree(t, replica, "c.txt"); got != "v2" {
		t.Fatalf("resumed pull did not land the remote tree: c.txt = %q", got)
	}
	if _, err := os.Stat(controlPath(replica, pullMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker survived a completed pull: %v", err)
	}

	// The remote is untouched by the recovery: origin still holds its own tree and
	// has nothing to pull back.
	h.sync(origin)
	if got := readTree(t, origin, "b.txt"); got != "v2" {
		t.Fatalf("remote folder was overwritten by the torn tree: b.txt = %q", got)
	}
	assertTreeEqual(t, origin, replica)
}

// A resumed pull guards overwrites against the last-synced base, not the fresh scan:
// the scan holds the half-applied version and any edit made since the interruption,
// and cannot tell them apart. An edit or a new file created in the torn tree must
// survive the resume as a conflict/local add, while half-applied files are finished
// without being flagged.
func TestResumedPullKeepsEditsMadeAfterTheInterruption(t *testing.T) {
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "v1")
	writeTree(t, origin, "b.txt", "v1")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)

	writeTree(t, origin, "a.txt", "v2")
	writeTree(t, origin, "b.txt", "v2")
	writeTree(t, origin, "c.txt", "v2")
	h.sync(origin)

	// The interrupted pull landed a.txt; then, before re-running sync, the user
	// edited b.txt and created new.txt in the torn tree.
	writeTree(t, replica, "a.txt", "v2")
	if err := beginPullMarker(replica, 2); err != nil {
		t.Fatal(err)
	}
	writeTree(t, replica, "b.txt", "mine")
	writeTree(t, replica, "new.txt", "kept")

	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("resume over a post-interruption edit: want errConflictsRemain, got %v", err)
	}
	if got := readTree(t, replica, "b.txt"); got != "mine" {
		t.Fatalf("resumed pull overwrote a post-interruption edit: b.txt = %q", got)
	}
	if got := readTree(t, replica, "new.txt"); got != "kept" {
		t.Fatalf("resumed pull destroyed a post-interruption creation: new.txt = %q", got)
	}
	if got := readTree(t, replica, "c.txt"); got != "v2" {
		t.Fatalf("resume did not finish the pull: c.txt = %q", got)
	}
	if _, err := os.Stat(controlPath(replica, pullMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker survived a completed resume: %v", err)
	}
	// The base records the remote entries, so the kept edit and the new file are
	// ordinary pending local changes for the next sync.
	h.syncOpts(replica, syncOptions{force: true})
	h.sync(origin)
	if got := readTree(t, origin, "b.txt"); got != "mine" {
		t.Fatalf("kept edit did not resolve local-wins on the next sync: b.txt = %q", got)
	}
}

// The marker is written before the extract and cleared only once the pull commits,
// so a pull that fails partway is recognizable on the next run. A pull that succeeds
// must leave nothing behind, or the folder would pull forever.
func TestPackPullMarkerTracksTheTransfer(t *testing.T) {
	var failPacks atomic.Bool
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if failPacks.Load() && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/packs/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		pass(w, r)
	})

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	writeTree(t, origin, "a.txt", "v1")
	h.sync(origin)

	replica := t.TempDir()
	h.clone(h.folderID(origin), replica)
	if _, err := os.Stat(controlPath(replica, pullMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clone left a pull marker: %v", err)
	}

	writeTree(t, origin, "a.txt", "v2")
	h.sync(origin)

	failPacks.Store(true)
	if err := runSync(replica, syncOptions{}); err == nil {
		t.Fatal("pull succeeded while every pack fetch was failing")
	}
	if _, err := os.Stat(controlPath(replica, pullMarkerFile)); err != nil {
		t.Fatalf("a pull that failed mid-transfer left no marker: %v", err)
	}

	failPacks.Store(false)
	h.sync(replica)
	if got := readTree(t, replica, "a.txt"); got != "v2" {
		t.Fatalf("retry did not land the remote tree: %q", got)
	}
	if _, err := os.Stat(controlPath(replica, pullMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker survived a completed pull: %v", err)
	}
}

// An in-place restore replaces the whole tree, so a tree an earlier interrupted pull
// had torn is whole again — and it is the snapshot's. The marker must not survive it,
// or the sync that publishes the rollback pulls the remote back over it instead.
func TestInPlaceRestoreClearsAnInterruptedPull(t *testing.T) {
	h := newE2E(t)
	dir := t.TempDir()
	writePackConfig(t, dir)
	h.init(dir)
	writeTree(t, dir, "a.txt", "v1")
	h.sync(dir)

	runCmd(t, checkpointCmd(), "before", dir)

	writeTree(t, dir, "a.txt", "v2")
	h.sync(dir)
	if err := beginPullMarker(dir, 2); err != nil {
		t.Fatal(err)
	}

	runCmd(t, restoreCmd(), "before", dir, "--in-place", "-y")
	if got := readTree(t, dir, "a.txt"); got != "v1" {
		t.Fatalf("restore was undone by a resumed pull: a.txt = %q", got)
	}
	if _, err := os.Stat(controlPath(dir, pullMarkerFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker survived an in-place restore: %v", err)
	}
}
