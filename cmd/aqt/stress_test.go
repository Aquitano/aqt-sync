package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// This file is an end-to-end stress suite: it spins up a real in-process server,
// builds a large multi-directory tree, and drives the whole feature surface
// (folder sync + clone + conflict resolution, the single-file pastebin spine,
// pack-and-seal folders, the global CLI flags, and the pull path-traversal guard)
// over the real HTTP API. It assumes the seven in-flight fixes/features are
// merged. Scale shrinks under `go test -short`.

// --- stress helpers ---

// stressScale picks how many module directories the huge tree gets; -short keeps
// CI fast while a full run exercises hundreds of files and thousands of chunks.
func stressScale(t *testing.T) int {
	if testing.Short() {
		return 10
	}
	return 44
}

// fleetScale sizes the shared tree the multi-device test clones onto every device.
// It is a fraction of stressScale: the tree is cloned and reconciled several times
// over (once per device), so it stays smaller to keep the wall clock down.
func fleetScale(t *testing.T) int {
	if testing.Short() {
		return 3
	}
	return 12
}

// resetCLIFlags clears the package-global flag state. Cobra binds the global
// flags to these package vars, so a prior test that drove rootCmd().Execute()
// (e.g. with --json) would otherwise leak that state into a test that calls the
// run* functions directly. Each CLI process is fresh in production; tests share
// one, so they reset explicitly.
func resetCLIFlags() {
	flagServer, flagProfile = "", ""
	flagJSON, flagQuiet, flagVerbose = false, false, false
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	_, _ = rng.Read(b)
	return b
}

func randText(rng *rand.Rand, n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 \n"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.Intn(len(alphabet))]
	}
	return string(b)
}

// genHugeTree writes a deterministic tree of varied files under root: many tiny
// inline text files, an inline JSON config, three chunked binaries of escalating
// size (one of them multi-chunk), a block of content duplicated across every module
// (so dedup has something to collapse), and a couple of deeply nested paths. It
// returns the number of files written.
func genHugeTree(t *testing.T, root string, modules int) int {
	t.Helper()
	rng := rand.New(rand.NewSource(20260626))
	dup := []byte(strings.Repeat("shared-dedup-block-0123456789abcdef\n", 2048)) // identical in every module
	count := 0
	put := func(rel string, content []byte) {
		writeTree(t, root, rel, string(content))
		count++
	}
	for m := 0; m < modules; m++ {
		d := fmt.Sprintf("mod%03d", m)
		for f := 0; f < 8; f++ { // inline (< 2 KiB cutoff)
			put(fmt.Sprintf("%s/small/file%02d.txt", d, f),
				[]byte(fmt.Sprintf("module %d file %d\n%s\n", m, f, randText(rng, 120))))
		}
		put(fmt.Sprintf("%s/config/app.json", d),
			[]byte(fmt.Sprintf("{\"module\":%d,\"name\":%q,\"nonce\":%q}\n", m, d, randText(rng, 48))))
		put(fmt.Sprintf("%s/data/blob.bin", d), randBytes(rng, 3<<10+rng.Intn(9<<10)))     // chunked
		put(fmt.Sprintf("%s/data/medium.bin", d), randBytes(rng, 20<<10+rng.Intn(24<<10))) // chunked
		put(fmt.Sprintf("%s/data/large.bin", d), randBytes(rng, 120<<10+rng.Intn(40<<10))) // multi-chunk
		put(fmt.Sprintf("%s/shared/dup.bin", d), dup)                                      // dedups across modules
		put(fmt.Sprintf("%s/a/b/c/d/deep.txt", d), []byte(fmt.Sprintf("deep %d\n", m)))
		for l := 0; l < 2; l++ { // a couple of deeply nested leaves
			put(fmt.Sprintf("%s/nested/x/y/z/leaf%02d.txt", d, l),
				[]byte(fmt.Sprintf("leaf %d-%d\n%s\n", m, l, randText(rng, 64))))
		}
	}
	return count
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// chdirTemp switches into dir for the duration of the test (restored on cleanup),
// so a default-destination pull writes into a sandbox we can inspect.
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// withStdin feeds content to os.Stdin while fn runs, so `push -` can be driven
// without a terminal.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	go func() {
		_, _ = io.WriteString(w, content)
		_ = w.Close()
	}()
	fn()
	os.Stdin = orig
	_ = r.Close()
}

// pushCapture runs a push and returns the ref/URL/JSON it printed to stdout.
func pushCapture(t *testing.T, path string, opts pushOptions) string {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runPush(path, opts) })
	if err != nil {
		t.Fatalf("push %s: %v", path, err)
	}
	return strings.TrimSpace(out)
}

// --- the huge-repo, all-mutations folder sync lifecycle ---

func TestStressHugeRepoSyncLifecycle(t *testing.T) {
	resetCLIFlags()
	h := newE2E(t)

	origin := t.TempDir()
	h.init(origin)
	nfiles := genHugeTree(t, origin, stressScale(t))
	t.Logf("generated %d files", nfiles)

	h.sync(origin)
	id := h.folderID(origin)
	packs1 := h.countPacks()
	if packs1 == 0 {
		t.Fatal("first sync of a huge tree uploaded no packs")
	}

	// A second machine clones the whole tree byte-for-byte.
	replica := t.TempDir()
	h.clone(id, replica)
	assertTreeEqual(t, origin, replica)

	// Dedup holds: a no-op resync ships nothing new.
	h.sync(origin)
	if got := h.countPacks(); got != packs1 {
		t.Fatalf("no-op resync changed pack count: %d -> %d", packs1, got)
	}

	// A single batch of every mutation kind, applied on origin and reconciled to
	// the replica in one round.
	writeTree(t, origin, "mod000/small/file00.txt", "EDITED content") // edit
	writeTree(t, origin, "newdir/added.txt", "freshly added")         // add
	removeTree(t, origin, "mod001/data/large.bin")                    // delete
	moved := readTree(t, origin, "mod002/small/file00.txt")           // rename = delete + add
	removeTree(t, origin, "mod002/small/file00.txt")
	writeTree(t, origin, "mod002/small/renamed.txt", moved)
	// file -> directory at the same path.
	removeTree(t, origin, "mod003/data/blob.bin")
	writeTree(t, origin, "mod003/data/blob.bin/inside.txt", "now a dir")
	// directory -> file at the same path (the case fix/sync-dir-to-file repairs).
	if err := os.RemoveAll(filepath.Join(origin, "mod004", "small")); err != nil {
		t.Fatal(err)
	}
	writeTree(t, origin, "mod004/small", "now a file")

	h.sync(origin)
	h.sync(replica)
	assertTreeEqual(t, origin, replica)

	if got := readTree(t, replica, "mod004/small"); got != "now a file" {
		t.Fatalf("directory->file change did not pull: %q", got)
	}
	if got := readTree(t, replica, "mod003/data/blob.bin/inside.txt"); got != "now a dir" {
		t.Fatalf("file->directory change did not pull: %q", got)
	}
	assertAbsent(t, replica, "mod001/data/large.bin")
	assertAbsent(t, replica, "mod002/small/file00.txt")
	if got := readTree(t, replica, "mod002/small/renamed.txt"); got != moved {
		t.Fatalf("rename target wrong: %q", got)
	}

	// Permission-only change propagates (Unix only; Windows has no mode bits).
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(origin, "newdir/added.txt"), 0o750); err != nil {
			t.Fatal(err)
		}
		h.sync(origin)
		h.sync(replica)
		fi, err := os.Stat(filepath.Join(replica, "newdir/added.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Fatalf("chmod did not propagate: got %o want 750", fi.Mode().Perm())
		}
	}

	// Same-file edit on both sides is a conflict: abort without --force, local wins
	// with it.
	writeTree(t, origin, "mod005/small/file00.txt", "origin-edit")
	h.sync(origin)
	writeTree(t, replica, "mod005/small/file00.txt", "replica-edit")
	if err := runSync(replica, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected conflict abort, got %v", err)
	}
	h.syncOpts(replica, syncOptions{force: true})
	h.sync(origin)
	assertTreeEqual(t, origin, replica)
	if got := readTree(t, origin, "mod005/small/file00.txt"); got != "replica-edit" {
		t.Fatalf("force conflict resolution did not win: %q", got)
	}
}

// --- the single-file pastebin spine: every push/pull variant and lifecycle verb ---

func TestStressSingleFileFeatureSweep(t *testing.T) {
	resetCLIFlags()
	newE2E(t) // sets up the server + authenticated default profile
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Private push -> ref; pull to disk and cat to stdout both round-trip.
	const secret = "API_KEY=abc123\nDB=postgres://localhost\n"
	ref := pushCapture(t, write("secret.env", secret), pushOptions{quiet: true})
	if !strings.HasPrefix(ref, "aqt://") {
		t.Fatalf("private push ref = %q", ref)
	}
	dst := filepath.Join(dir, "out.env")
	if err := runPull(ref, dst, "", false, false); err != nil {
		t.Fatalf("private pull: %v", err)
	}
	if got := mustRead(t, dst); got != secret {
		t.Fatalf("private pull mismatch: %q", got)
	}
	var catErr error
	catOut := captureStdout(t, func() { catErr = runPull(ref, "", "", true, false) })
	if catErr != nil || catOut != secret {
		t.Fatalf("cat: err=%v out=%q", catErr, catOut)
	}

	// Public push -> the fragment link decrypts with no account.
	pubLink := pushCapture(t, write("deploy.log", "log line\n"), pushOptions{public: true, quiet: true})
	if !strings.Contains(pubLink, "/x/") || !strings.Contains(pubLink, "#") {
		t.Fatalf("public link = %q", pubLink)
	}
	pubDst := filepath.Join(dir, "deploy.out")
	if err := runPull(pubLink, pubDst, "", false, false); err != nil {
		t.Fatalf("public pull: %v", err)
	}
	if mustRead(t, pubDst) != "log line\n" {
		t.Fatal("public pull mismatch")
	}

	// Password-gated push: the right password decrypts, a wrong one fails.
	gatedLink := pushCapture(t, write("gated.txt", "secret-body"), pushOptions{password: "s3cret", quiet: true})
	if !strings.Contains(gatedLink, "#p.") {
		t.Fatalf("gated link should carry a p. fragment: %q", gatedLink)
	}
	gatedDst := filepath.Join(dir, "gated.out")
	if err := runPull(gatedLink, gatedDst, "s3cret", false, false); err != nil {
		t.Fatalf("gated pull with correct password: %v", err)
	}
	if mustRead(t, gatedDst) != "secret-body" {
		t.Fatal("gated pull mismatch")
	}
	if err := runPull(gatedLink, filepath.Join(dir, "nope"), "wrong-password", false, false); err == nil {
		t.Fatal("gated pull with a wrong password should fail")
	}

	// Large private file streams through the chunk/pack pipeline and reassembles.
	rng := rand.New(rand.NewSource(7))
	bigSrc := write("archive.bin", string(randBytes(rng, 9<<20))) // >= 8 MiB stream threshold
	bigRef := pushCapture(t, bigSrc, pushOptions{quiet: true})
	bigDst := filepath.Join(dir, "archive.out")
	if err := runPull(bigRef, bigDst, "", false, false); err != nil {
		t.Fatalf("streamed pull: %v", err)
	}
	if mustRead(t, bigDst) != mustRead(t, bigSrc) {
		t.Fatal("streamed large file did not round-trip")
	}

	// Push from stdin.
	var stdinRef string
	stdinRef = strings.TrimSpace(captureStdout(t, func() {
		withStdin(t, "from stdin\n", func() {
			if err := runPush("-", pushOptions{quiet: true}); err != nil {
				t.Fatalf("stdin push: %v", err)
			}
		})
	}))
	stdinDst := filepath.Join(dir, "stdin.out")
	if err := runPull(stdinRef, stdinDst, "", false, false); err != nil {
		t.Fatalf("stdin pull: %v", err)
	}
	if mustRead(t, stdinDst) != "from stdin\n" {
		t.Fatal("stdin round-trip mismatch")
	}

	// --json output: private has no url, public carries one; both keep ref = aqt://id.
	var privJSON pushJSON
	out := captureStdout(t, func() {
		if err := runPush(write("p.txt", "x"), pushOptions{json: true}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(out), &privJSON); err != nil {
		t.Fatalf("push --json not valid JSON: %v (%q)", err, out)
	}
	if privJSON.ID == "" || privJSON.Ref != "aqt://"+privJSON.ID || privJSON.URL != "" || privJSON.Visibility != "private" {
		t.Fatalf("private push JSON wrong: %+v", privJSON)
	}
	var pubJSON pushJSON
	out = captureStdout(t, func() {
		if err := runPush(write("pub.txt", "y"), pushOptions{public: true, json: true}); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(out), &pubJSON); err != nil {
		t.Fatal(err)
	}
	if pubJSON.Visibility != "public" || pubJSON.URL == "" || pubJSON.Ref != "aqt://"+pubJSON.ID {
		t.Fatalf("public push JSON wrong: %+v", pubJSON)
	}

	// info --json reflects an encrypted name set with -n.
	namedRef := pushCapture(t, write("creds", "data"), pushOptions{name: "production-creds", quiet: true})
	var info lsRow
	infoOut := captureStdout(t, func() {
		if err := runInfo(namedRef, "", true); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(infoOut), &info); err != nil {
		t.Fatal(err)
	}
	if info.Name != "production-creds" {
		t.Fatalf("info --json name = %q, want production-creds", info.Name)
	}

	// find --json indexes the resources we created.
	var index []findEntry
	findOut := captureStdout(t, func() {
		if err := runFind("", true, false); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(findOut), &index); err != nil {
		t.Fatal(err)
	}
	if len(index) == 0 {
		t.Fatal("find --json returned an empty index")
	}

	// share makes a private resource public; private rotates the key so the old
	// link dies while the owner ref still resolves.
	shareRef := pushCapture(t, write("share-me.txt", "shareable"), pushOptions{quiet: true})
	shareLink := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(shareRef, "", true); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	if err := runPull(shareLink, filepath.Join(dir, "shared.out"), "", false, false); err != nil {
		t.Fatalf("pull via share link: %v", err)
	}
	if err := runPrivate(shareRef); err != nil {
		t.Fatalf("private (rotate): %v", err)
	}
	if err := runPull(shareLink, filepath.Join(dir, "dead.out"), "", false, false); err == nil {
		t.Fatal("rotated key must kill the old share link")
	}
	if err := runPull(shareRef, filepath.Join(dir, "owner.out"), "", false, false); err != nil {
		t.Fatalf("owner ref must still resolve after rotation: %v", err)
	}

	// rm deletes the ciphertext: a later pull 404s.
	rmRef := pushCapture(t, write("trash.txt", "delete me"), pushOptions{quiet: true})
	if err := runRemove([]string{rmRef}); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := runPull(rmRef, filepath.Join(dir, "gone.out"), "", false, false); err == nil {
		t.Fatal("pull of a removed resource should fail")
	}
}

// --- pack-and-seal folder, huge and whole-folder reconciled ---

func TestStressPackAndSealHugeFolder(t *testing.T) {
	resetCLIFlags()
	h := newE2E(t)

	origin := t.TempDir()
	writePackConfig(t, origin)
	h.init(origin)
	genHugeTree(t, origin, stressScale(t)/2)
	h.sync(origin)
	id := h.folderID(origin)

	packsAfter := h.countPacks()
	h.sync(origin)
	if got := h.countPacks(); got != packsAfter {
		t.Fatalf("no-op pack resync changed pack count: %d -> %d", packsAfter, got)
	}

	replica := t.TempDir()
	h.clone(id, replica)
	assertTreeEqual(t, origin, replica)

	// An edit re-ships the whole sealed tree; a fresh clone sees it.
	writeTree(t, origin, "mod000/small/file00.txt", "pack-edited")
	removeTree(t, origin, "mod001/data/blob.bin")
	h.sync(origin)
	replica2 := t.TempDir()
	h.clone(id, replica2)
	assertTreeEqual(t, origin, replica2)
	if got := readTree(t, replica2, "mod000/small/file00.txt"); got != "pack-edited" {
		t.Fatalf("pack edit not in re-clone: %q", got)
	}
	assertAbsent(t, replica2, "mod001/data/blob.bin")
}

// --- the documented global CLI flag surface, through the real cobra root ---

func TestStressGlobalCLISurface(t *testing.T) {
	resetCLIFlags()
	h := newE2E(t)

	// --version and -V both print and exit 0 (no network needed).
	for _, args := range [][]string{{"--version"}, {"-V"}} {
		root := rootCmd()
		out := captureStdout(t, func() {
			root.SetArgs(args)
			if err := root.Execute(); err != nil {
				t.Fatalf("%v: %v", args, err)
			}
		})
		if !strings.Contains(out, version) {
			t.Fatalf("%v output %q missing version %q", args, out, version)
		}
	}

	// A resource exists, so `ls --json` (the global --json honored by ls) returns it.
	src := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = pushCapture(t, src, pushOptions{name: "listed", quiet: true})

	var rows []lsRow
	lsOut := captureStdout(t, func() {
		root := rootCmd()
		root.SetArgs([]string{"ls", "--json"})
		if err := root.Execute(); err != nil {
			t.Fatalf("ls --json: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(lsOut), &rows); err != nil {
		t.Fatalf("ls --json not valid JSON: %v (%q)", err, lsOut)
	}
	found := false
	for _, r := range rows {
		if r.Name == "listed" {
			found = true
		}
	}
	if !found {
		t.Fatal("ls --json did not list the pushed resource")
	}

	// A command that never had --json before still accepts the global flag.
	tracked := t.TempDir()
	h.init(tracked)
	root := rootCmd()
	root.SetArgs([]string{"status", tracked, "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("status --json should be accepted: %v", err)
	}
}

// --- pull confines an attacker-chosen name to the working directory ---

func TestStressPullPathTraversalConfined(t *testing.T) {
	resetCLIFlags()
	h := newE2E(t)
	_ = h

	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, []byte("PWNED"), 0o644); err != nil {
		t.Fatal(err)
	}
	// -n carries a traversal name straight into the sealed metadata.
	ref := pushCapture(t, payload, pushOptions{name: "../../evil", quiet: true})

	work := t.TempDir()
	chdirTemp(t, work)
	if err := runPull(ref, "", "", false, false); err != nil {
		t.Fatalf("pull: %v", err)
	}

	// The byte landed at ./evil inside the sandbox, never at ../../evil.
	if got, err := os.ReadFile(filepath.Join(work, "evil")); err != nil || string(got) != "PWNED" {
		t.Fatalf("expected confined ./evil: err=%v got=%q", err, got)
	}
	escaped := filepath.Join(filepath.Dir(filepath.Dir(work)), "evil")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("path traversal wrote outside CWD at %s", escaped)
	}
}

// --- a fleet of simulated devices on one account ---
//
// The folder-sync tests above model "two machines" as two working copies under a
// single device identity. This one models a real fleet: several devices, each
// attached to the same account through the genuine challenge/sign handshake, each
// with its own server-issued device id + bearer token but the same master key.
//
// We host one profile per device in the shared config dir and select the active one
// with flagProfile — the same seam `--profile` drives per process in production.
// Because the server authenticates every request by device token, an attach mints a
// real device and a revoke kills that device's access for real (the token row is
// gone), not as a client-side fiction.

type deviceFleet struct {
	h     *e2eHarness
	mk    crypto.MasterKey
	email string
	kdf   crypto.KdfParams
}

// newFleet bootstraps from the primary device newE2E already created: it recovers
// the account's master key from the cached session (so it can derive the signing key
// that authorizes further attaches) and remembers the email + KDF params every
// device profile shares.
func newFleet(t *testing.T, h *e2eHarness) *deviceFleet {
	t.Helper()
	mk, ok := identity.LoadSession(identity.DefaultProfile)
	if !ok {
		t.Fatal("newE2E should have cached the primary device session")
	}
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		t.Fatalf("load primary profile: %v", err)
	}
	return &deviceFleet{h: h, mk: mk, email: prof.Email, kdf: prof.Kdf}
}

// device is one machine in the fleet, pinned to its own profile (its device id +
// token live in that profile; its cached key in that profile's session).
type device struct {
	t       *testing.T
	profile string
	id      string // server-issued device id
}

// primary returns the account's first device, created by newE2E as the default
// profile.
func (f *deviceFleet) primary() *device {
	prof, err := identity.Load(identity.DefaultProfile)
	if err != nil {
		f.h.t.Fatalf("load primary profile: %v", err)
	}
	return &device{t: f.h.t, profile: identity.DefaultProfile, id: prof.DeviceID}
}

// attach runs the real challenge -> sign -> AttachDevice handshake against the
// server, then stores the new device as its own profile + cached session so the
// run* commands can act as it by setting flagProfile.
func (f *deviceFleet) attach(name string) *device {
	t := f.h.t
	t.Helper()
	signing := crypto.DeriveSigningKey(f.mk)
	cl := client.New(f.h.url, "")
	ch, err := cl.Challenge(f.email)
	if err != nil {
		t.Fatalf("challenge for %s: %v", name, err)
	}
	resp, err := cl.AttachDevice(api.AttachDeviceRequest{
		Email:       f.email,
		ChallengeID: ch.ChallengeID,
		Signature:   ed25519.Sign(signing, ch.Nonce),
		DeviceName:  name,
	})
	if err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	if err := identity.Save(&identity.Profile{
		Name: name, Server: f.h.url, Email: f.email,
		OwnerHandle: resp.OwnerHandle, DeviceID: resp.DeviceID, Token: resp.Token, Kdf: f.kdf,
	}); err != nil {
		t.Fatalf("save profile %s: %v", name, err)
	}
	if err := identity.SaveSession(name, f.mk, time.Hour); err != nil {
		t.Fatalf("cache session %s: %v", name, err)
	}
	return &device{t: t, profile: name, id: resp.DeviceID}
}

// as runs fn with this device's profile active, restoring the previous flagProfile
// afterward (even on a fatal failure, since the defer runs on Goexit). flagProfile
// is the package global the run* functions resolve their token + session through.
func (d *device) as(fn func() error) error {
	prev := flagProfile
	flagProfile = d.profile
	defer func() { flagProfile = prev }()
	return fn()
}

func (d *device) must(op string, fn func() error) {
	d.t.Helper()
	if err := d.as(fn); err != nil {
		d.t.Fatalf("%s as %s: %v", op, d.profile, err)
	}
}

func (d *device) init(dir string)      { d.must("init", func() error { return runInit(dir) }) }
func (d *device) clone(id, dir string) { d.must("clone", func() error { return runClone(id, dir) }) }
func (d *device) sync(dir string)      { d.syncOpts(dir, syncOptions{}) }

func (d *device) syncOpts(dir string, o syncOptions) {
	d.must("sync", func() error { return runSync(dir, o) })
}

// trySync runs a sync expected to fail (a conflict to inspect, or a revoked token)
// and returns the error rather than failing the test.
func (d *device) trySync(dir string, o syncOptions) error {
	return d.as(func() error { return runSync(dir, o) })
}

func (d *device) tryPull(ref, out string) error {
	return d.as(func() error { return runPull(ref, out, "", false, false) })
}

// pushPrivate uploads a private file as this device and returns the printed ref.
func (d *device) pushPrivate(path string) string {
	d.t.Helper()
	var ref string
	d.must("push", func() error {
		var perr error
		out := captureStdout(d.t, func() { perr = runPush(path, pushOptions{quiet: true}) })
		ref = strings.TrimSpace(out)
		return perr
	})
	return ref
}

func (d *device) listDevices() []api.Device {
	d.t.Helper()
	var out []api.Device
	d.must("devices", func() error {
		cl, _, err := authedClient()
		if err != nil {
			return err
		}
		out, err = cl.ListDevices()
		return err
	})
	return out
}

func (d *device) revoke(ids ...string) {
	d.must("revoke", func() error { return runDevicesRemove(ids) })
}
func (d *device) revokeOthers() { d.must("revoke-others", revokeOtherDevices) }

func TestStressMultiDeviceFleet(t *testing.T) {
	resetCLIFlags()
	h := newE2E(t)
	fleet := newFleet(t, h)
	laptop := fleet.primary()

	// The laptop inits and syncs a multi-module tree; a fresh account has one device.
	laptopDir := t.TempDir()
	laptop.init(laptopDir)
	nfiles := genHugeTree(t, laptopDir, fleetScale(t))
	t.Logf("fleet tree: %d files", nfiles)
	laptop.sync(laptopDir)
	folder := h.folderID(laptopDir)
	if got := laptop.listDevices(); len(got) != 1 {
		t.Fatalf("fresh account should have 1 device, got %d", len(got))
	}

	// Two more devices attach to the same account and clone the folder byte-for-byte.
	desktop := fleet.attach("desktop")
	phone := fleet.attach("phone")
	if got := laptop.listDevices(); len(got) != 3 {
		t.Fatalf("after two attaches, want 3 devices, got %d", len(got))
	}
	desktopDir, phoneDir := t.TempDir(), t.TempDir()
	desktop.clone(folder, desktopDir)
	phone.clone(folder, phoneDir)
	assertTreeEqual(t, laptopDir, desktopDir)
	assertTreeEqual(t, laptopDir, phoneDir)

	// Independent edits made on two different devices converge on all three.
	writeTree(t, laptopDir, "mod000/small/file00.txt", "edited on laptop")
	laptop.sync(laptopDir)
	writeTree(t, desktopDir, "mod001/small/file00.txt", "edited on desktop")
	desktop.sync(desktopDir) // pulls laptop's edit, pushes its own
	laptop.sync(laptopDir)   // pulls desktop's edit
	phone.sync(phoneDir)     // pulls both
	assertTreeEqual(t, laptopDir, desktopDir)
	assertTreeEqual(t, laptopDir, phoneDir)
	if got := readTree(t, phoneDir, "mod000/small/file00.txt"); got != "edited on laptop" {
		t.Fatalf("phone missing laptop edit: %q", got)
	}
	if got := readTree(t, phoneDir, "mod001/small/file00.txt"); got != "edited on desktop" {
		t.Fatalf("phone missing desktop edit: %q", got)
	}

	// Two devices edit the same file: the later sync aborts, --force resolves it
	// local-wins, and the winning content propagates to the whole fleet.
	writeTree(t, laptopDir, "mod002/small/file00.txt", "laptop version")
	laptop.sync(laptopDir)
	writeTree(t, desktopDir, "mod002/small/file00.txt", "desktop version")
	if err := desktop.trySync(desktopDir, syncOptions{}); !errors.Is(err, errConflictsRemain) {
		t.Fatalf("expected a cross-device conflict abort, got %v", err)
	}
	desktop.syncOpts(desktopDir, syncOptions{force: true})
	laptop.sync(laptopDir)
	phone.sync(phoneDir)
	for _, wc := range []struct{ name, dir string }{
		{"laptop", laptopDir}, {"desktop", desktopDir}, {"phone", phoneDir},
	} {
		if got := readTree(t, wc.dir, "mod002/small/file00.txt"); got != "desktop version" {
			t.Fatalf("%s did not converge on the forced winner: %q", wc.name, got)
		}
	}

	// A private single-file push on one device is pullable on another device of the
	// same account: one master key, distinct device tokens.
	secretPath := filepath.Join(t.TempDir(), "fleet.env")
	if err := os.WriteFile(secretPath, []byte("TOKEN=fleet-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secretRef := laptop.pushPrivate(secretPath)
	if !strings.HasPrefix(secretRef, "aqt://") {
		t.Fatalf("private push ref = %q", secretRef)
	}
	desktopSecret := filepath.Join(t.TempDir(), "from-laptop.env")
	if err := desktop.tryPull(secretRef, desktopSecret); err != nil {
		t.Fatalf("desktop should pull a same-account private push: %v", err)
	}
	if got := mustRead(t, desktopSecret); got != "TOKEN=fleet-secret\n" {
		t.Fatalf("cross-device private pull mismatch: %q", got)
	}

	// Revoke the phone from the laptop. The fleet drops to two devices; the revoked
	// device loses server access while its already-synced local files stay intact.
	laptop.revoke(phone.id)
	if got := laptop.listDevices(); len(got) != 2 {
		t.Fatalf("after revoking phone, want 2 devices, got %d", len(got))
	}
	assertTreeEqual(t, laptopDir, phoneDir) // local data survives revocation
	// A push attempt from the revoked phone fails: its token no longer authenticates.
	writeTree(t, phoneDir, "mod000/small/phone-after-revoke.txt", "should not upload")
	if err := phone.trySync(phoneDir, syncOptions{}); err == nil {
		t.Fatal("a revoked device must not be able to sync")
	}
	// And it can no longer pull the account's private resources.
	if err := phone.tryPull(secretRef, filepath.Join(t.TempDir(), "denied.env")); err == nil {
		t.Fatal("a revoked device must not be able to pull private resources")
	}

	// `devices --json` from the laptop marks itself current and no longer lists the
	// phone.
	var rows []api.Device
	out := captureStdout(t, func() { _ = laptop.as(func() error { return runDevicesList(true) }) })
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("devices --json not valid JSON: %v (%q)", err, out)
	}
	var sawCurrent bool
	for _, r := range rows {
		if r.ID == phone.id {
			t.Fatal("revoked phone still listed by devices --json")
		}
		if r.ID == laptop.id {
			sawCurrent = r.Current
		}
	}
	if !sawCurrent || len(rows) != 2 {
		t.Fatalf("devices --json wrong after revoke: current=%v rows=%+v", sawCurrent, rows)
	}

	// The surviving devices still sync and converge, and the revoked phone's change
	// never reached the server.
	desktop.sync(desktopDir)
	laptop.sync(laptopDir)
	assertTreeEqual(t, laptopDir, desktopDir)
	assertAbsent(t, desktopDir, "mod000/small/phone-after-revoke.txt")

	// Bulk revoke (the `logout --all-devices` path): the laptop revokes every other
	// device, leaving only itself, and the desktop then loses access too.
	laptop.revokeOthers()
	if got := laptop.listDevices(); len(got) != 1 {
		t.Fatalf("after revoking all others, want 1 device, got %d", len(got))
	}
	writeTree(t, desktopDir, "mod001/small/desktop-after-revoke.txt", "should not upload")
	if err := desktop.trySync(desktopDir, syncOptions{}); err == nil {
		t.Fatal("a bulk-revoked device must not be able to sync")
	}
}
