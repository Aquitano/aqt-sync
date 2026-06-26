package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// A located-but-missing object surfaces client.ErrNotFound, which the reconcile
// loop maps to a conflict-retry: a manifest whose objects were GC'd by a concurrent
// supersede is re-read against the current version instead of hard-failing.
func TestPackSourceMissingObjectIsNotFound(t *testing.T) {
	src := &packSource{
		locs:  map[string]api.ObjectLocation{},
		spans: map[string]packSpan{},
		cache: newPackCache(1),
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
	var sawMember bool
	for _, e := range entries {
		if e.Kind == kindFolderFile && e.Path == "notes/todo.txt" {
			sawMember = true
		}
	}
	if !sawMember {
		t.Errorf("find did not surface the folder member; entries=%+v", entries)
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
}

func newE2E(t *testing.T) *e2eHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	home := t.TempDir()
	t.Setenv("HOME", home)                                      // darwin config dir
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config")) // linux config dir

	dataDir := t.TempDir()
	store, err := server.OpenStore(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	ts := httptest.NewServer(server.New(store).Router())
	t.Cleanup(ts.Close)

	h := &e2eHarness{t: t, url: ts.URL, dataDir: dataDir}
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
	mk, err := crypto.DeriveMasterKey(pass, kdf)
	if err != nil {
		h.t.Fatal(err)
	}
	resp, err := client.New(h.url, "").CreateAccount(api.CreateAccountRequest{
		Email:      email,
		Kdf:        kdf,
		PublicKey:  crypto.DeriveSigningKey(mk).Public().(ed25519.PublicKey),
		DeviceName: "e2e",
	})
	if err != nil {
		h.t.Fatalf("signup: %v", err)
	}
	if err := identity.Save(&identity.Profile{
		Name: identity.DefaultProfile, Server: h.url, Email: email,
		OwnerHandle: resp.OwnerHandle, DeviceID: resp.DeviceID, Token: resp.Token, Kdf: kdf,
	}); err != nil {
		h.t.Fatalf("save profile: %v", err)
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
	if err := runClone(id, dir); err != nil {
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
