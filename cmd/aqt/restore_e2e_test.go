// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/cryptotest"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/server"
)

// TestFullBackupRestoreDrill is the backup tool's definition of done, exercised
// end to end: a realistic tree (nested dirs, a multi-chunk binary, a symlink, an
// executable, a Unicode name, an empty file, and a tracked .git) is pushed; the
// server's on-disk data dir is cold-copied as an operator would back it up; a fresh
// server is stood up from that copy; a clean machine with an empty config recovers
// the account from nothing but the email + passphrase and clones the folder; and the
// restored tree is asserted byte-, mode-, and symlink-identical to the original.
//
// It is the in-process twin of scripts/restore-drill.sh, so the "restore proven on
// real data" guarantee is checked on every CI run, not just when someone remembers
// to run the shell drill.
func TestFullBackupRestoreDrill(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the full backup/restore drill under -short")
	}
	gin.SetMode(gin.TestMode)

	const email = "restore-drill@example.com"
	const pass = "correct horse battery staple restore"

	// --- Machine A: config dir, server, account, and a first push. ---
	setConfigHome(t, t.TempDir())
	dataDirA := t.TempDir()
	storeA, err := server.OpenStore(dataDirA)
	if err != nil {
		t.Fatalf("open store A: %v", err)
	}
	srvA := newHTTPServer(t, storeA)
	signupAt(t, srvA.URL, email, pass)

	origin := t.TempDir()
	// Track .git before init so the first sync captures the repo directory too; init
	// leaves an existing .aqtignore untouched.
	writeTree(t, origin, ".aqtignore", "!.git/\nnode_modules/\n")
	hasSymlink := buildRealisticTree(t, origin)

	if err := runInit(origin, nil); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := runSync(origin, syncOptions{}); err != nil {
		t.Fatalf("push: %v", err)
	}
	folderID := folderIDOf(t, origin)
	if n := countPacksIn(t, dataDirA); n == 0 {
		t.Fatal("the binary file should have produced at least one pack")
	}
	want := snapshotDir(t, origin)

	// --- Backup: stop the server and cold-copy its whole data dir. ---
	srvA.Close()
	if err := storeA.Close(); err != nil {
		t.Fatalf("close store A: %v", err)
	}
	backup := t.TempDir()
	copyDir(t, dataDirA, backup)

	// --- Disaster + recovery: a brand-new server on a fresh copy of the backup. ---
	restoredData := t.TempDir()
	copyDir(t, backup, restoredData)
	storeB, err := server.OpenStore(restoredData)
	if err != nil {
		t.Fatalf("open restored store: %v", err)
	}
	srvB := newHTTPServer(t, storeB)
	t.Cleanup(func() { srvB.Close(); storeB.Close() })

	// --- Clean machine: empty config, recover from email + passphrase alone. ---
	setConfigHome(t, t.TempDir())
	reattach(t, srvB.URL, email, pass)

	replica := t.TempDir()
	if err := runClone(folderID, replica, false, ""); err != nil {
		t.Fatalf("clone onto clean machine: %v", err)
	}

	// --- Proof: the restored tree matches the original, byte for byte. ---
	got := snapshotDir(t, replica)
	assertDirsIdentical(t, want, got)
	if _, ok := got[".git/HEAD"]; !ok {
		t.Fatal("the tracked .git directory was not restored")
	}
	if hasSymlink {
		if f, ok := got["link"]; !ok || f.kind != 'l' {
			t.Fatalf("symlink not restored as a symlink: %+v", f)
		}
	}
}

// --- realistic tree ---

// buildRealisticTree writes a spread of file shapes a real backup must survive and
// returns whether a symlink was created (false on hosts that disallow them).
func buildRealisticTree(t *testing.T, root string) (hasSymlink bool) {
	t.Helper()
	writeTree(t, root, "README.md", "# project\n\nnotes and things\n")
	writeTree(t, root, "notes/todo.md", "- [ ] buy milk\n- [ ] restore drill\n")
	writeTree(t, root, "data/café.txt", "unicode filename, unicode body: café ☕\n")
	writeTree(t, root, "empty.txt", "")

	// An executable, to prove the mode round-trips.
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A multi-chunk binary, to prove pack storage backs up and reconstructs.
	big := make([]byte, 5<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "blob.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	// A tracked git repo (opaque files, incl. a binary packfile): the Brain-vault shape.
	gitFiles := map[string]string{
		".git/HEAD":               "ref: refs/heads/main\n",
		".git/config":             "[core]\n\trepositoryformatversion = 0\n",
		".git/refs/heads/main":    "0123456789abcdef0123456789abcdef01234567\n",
		".git/objects/info/packs": "P pack-deadbeef.pack\n",
	}
	for rel, body := range gitFiles {
		writeTree(t, root, rel, body)
	}
	packBytes := make([]byte, 4096)
	if _, err := rand.Read(packBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git", "objects", "pack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "objects", "pack", "pack-deadbeef.pack"), packBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("notes/todo.md", filepath.Join(root, "link")); err == nil {
		return true
	}
	return false
}

// --- account helpers (no interactive prompts) ---

// signupAt creates a new account against serverURL and writes the profile + cached
// session into the active config dir, mirroring `aqt login` on a first machine.
func signupAt(t *testing.T, serverURL, email, pass string) {
	t.Helper()
	kdf := cryptotest.KdfParams(t)
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	uk, err := crypto.DeriveUnlockKey(pass, kdf)
	if err != nil {
		t.Fatal(err)
	}
	wrappedRoot, err := crypto.WrapRoot(mk, uk)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := client.New(serverURL, "")
	if err != nil {
		t.Fatal(err)
	}
	signing := crypto.DeriveSigningKey(mk)
	encPub := crypto.DeriveEncKey(mk).Public()
	resp, err := cl.CreateAccount(api.CreateAccountRequest{
		Email:        email,
		Kdf:          kdf,
		PublicKey:    signing.Public().(ed25519.PublicKey),
		WrappedRoot:  wrappedRoot,
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "machine-a",
		EncPublicKey: encPub,
		EncKeySig:    crypto.SignEncKey(signing, encPub),
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	saveProfileAndSession(t, serverURL, email, kdf, wrappedRoot, resp, mk)
}

// reattach recovers an existing account on a clean machine from just the email and
// passphrase: it bootstraps the KDF params + wrapped root, unwraps the master key,
// signs the device challenge, and attaches a new device — the real disaster-recovery
// path, minus the interactive passphrase prompt.
func reattach(t *testing.T, serverURL, email, pass string) {
	t.Helper()
	cl, err := client.New(serverURL, "")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := cl.Bootstrap(email)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	uk, err := crypto.DeriveUnlockKey(pass, boot.Kdf)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.UnwrapRoot(boot.WrappedRoot, uk)
	if err != nil {
		t.Fatalf("clean-machine unlock failed (restored account not recoverable): %v", err)
	}
	signing := crypto.DeriveSigningKey(rk)
	ch, err := cl.Challenge(email)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	resp, err := cl.AttachDevice(api.AttachDeviceRequest{
		Email:        email,
		ChallengeID:  ch.ChallengeID,
		Signature:    ed25519.Sign(signing, ch.Nonce),
		AuthVerifier: crypto.DeriveAuthVerifier(uk),
		DeviceName:   "clean-machine",
	})
	if err != nil {
		t.Fatalf("attach device: %v", err)
	}
	saveProfileAndSession(t, serverURL, email, boot.Kdf, boot.WrappedRoot, resp, rk)
}

func saveProfileAndSession(t *testing.T, serverURL, email string, kdf crypto.KdfParams, wrappedRoot crypto.SealedBlob, resp api.AuthResponse, mk crypto.MasterKey) {
	t.Helper()
	if err := identity.Save(&identity.Profile{
		Name: identity.DefaultProfile, Server: serverURL, Email: email,
		OwnerHandle: resp.OwnerHandle, DeviceID: resp.DeviceID, Token: resp.Token,
		Kdf: kdf, WrappedRoot: wrappedRoot, AuthEpoch: resp.Epoch,
	}); err != nil {
		t.Fatalf("save profile: %v", err)
	}
	if err := identity.SaveSession(identity.DefaultProfile, mk, time.Hour); err != nil {
		t.Fatalf("save session: %v", err)
	}
}

// --- filesystem drill helpers ---

// fileFacts captures what a restore must reproduce for one tree entry.
type fileFacts struct {
	kind    byte // 'f' regular, 'd' directory, 'l' symlink
	perm    os.FileMode
	content []byte
	link    string
}

// snapshotDir records every tracked entry under root (skipping the .aqt control
// directory) so two trees can be compared for byte, mode, and symlink equality.
func snapshotDir(t *testing.T, root string) map[string]fileFacts {
	t.Helper()
	out := map[string]fileFacts{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == ".aqt" {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			out[rel] = fileFacts{kind: 'l', link: target}
		case d.IsDir():
			out[rel] = fileFacts{kind: 'd', perm: info.Mode().Perm()}
		default:
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[rel] = fileFacts{kind: 'f', perm: info.Mode().Perm(), content: b}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// assertDirsIdentical fails the test on any difference between the original and the
// restored tree. Content and symlink targets are checked everywhere; permission bits
// are checked only off Windows, whose filesystem does not carry POSIX modes.
func assertDirsIdentical(t *testing.T, want, got map[string]fileFacts) {
	t.Helper()
	checkPerm := runtime.GOOS != "windows"
	for rel, w := range want {
		g, ok := got[rel]
		if !ok {
			t.Errorf("%s: present in original, missing from restore", rel)
			continue
		}
		if g.kind != w.kind {
			t.Errorf("%s: kind %c in original, %c in restore", rel, w.kind, g.kind)
			continue
		}
		switch w.kind {
		case 'f':
			if !bytes.Equal(w.content, g.content) {
				t.Errorf("%s: content differs (%d vs %d bytes)", rel, len(w.content), len(g.content))
			}
			if checkPerm && w.perm != g.perm {
				t.Errorf("%s: mode %o in original, %o in restore", rel, w.perm, g.perm)
			}
		case 'l':
			if w.link != g.link {
				t.Errorf("%s: symlink target %q vs %q", rel, w.link, g.link)
			}
		}
	}
	for rel := range got {
		if _, ok := want[rel]; !ok {
			t.Errorf("%s: present in restore but not in original", rel)
		}
	}
}

// copyDir recursively copies src into dst, recreating directories and file bytes.
// It is the test's stand-in for an operator's cold backup of the server data dir.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
}

// countPacksIn counts stored pack files under a server data dir.
func countPacksIn(t *testing.T, dataDir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(filepath.Join(dataDir, "packs"), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipDir
			}
			return err
		}
		if !d.IsDir() && filepath.Ext(d.Name()) == ".bin" {
			n++
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("count packs: %v", err)
	}
	return n
}

func folderIDOf(t *testing.T, dir string) string {
	t.Helper()
	st, err := folderstate.LoadState(dir)
	if err != nil {
		t.Fatalf("load state %s: %v", dir, err)
	}
	return st.ID
}

// setConfigHome points the identity config dir at a fresh location, so a later phase
// of the drill runs as a clean machine with no profile or cached session.
func setConfigHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)                                      // darwin config dir
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config")) // linux config dir
}

func newHTTPServer(t *testing.T, store *server.Store) *httptest.Server {
	t.Helper()
	return httptest.NewServer(server.NewWithConfig(store, server.Config{}).Router())
}
