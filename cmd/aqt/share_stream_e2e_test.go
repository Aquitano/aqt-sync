// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// pushStreamedFile writes data to a temp file, pushes it with opts, and returns the
// resource id and the ref printed to stdout. opts must set quiet so the printed line is
// just the ref.
func pushStreamedFile(t *testing.T, data []byte, opts pushOptions) (id string, printed string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "data.bin")
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	printed = strings.TrimSpace(captureStdout(t, func() {
		if err := runPush(src, opts); err != nil {
			t.Fatalf("push: %v", err)
		}
	}))
	id, _, _ = parseRef(printed)
	if id == "" {
		t.Fatalf("could not parse id from push output %q", printed)
	}
	return id, printed
}

// pushRandomStreamedFile writes size random bytes, pushes them with opts, and returns
// the resource id, the plaintext, and the ref printed to stdout. opts must set quiet so
// the printed line is just the ref.
func pushRandomStreamedFile(t *testing.T, size int, opts pushOptions) (id string, data []byte, printed string) {
	t.Helper()
	data = make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	id, printed = pushStreamedFile(t, data, opts)
	return id, data, printed
}

// withFreshEnv points every platform's UserConfigDir input at an empty temp dir, so
// the callee has no profile, session, or master key — a link holder on a fresh
// machine. The original owner env is restored afterwards (t.Setenv only restores at
// test end, but a mid-test rotate needs to switch back to the owner).
func withFreshEnv(t *testing.T, fn func()) {
	t.Helper()
	home := t.TempDir()
	oldAppData, hadAppData := os.LookupEnv("AppData")
	oldHome, hadHome := os.LookupEnv("HOME")
	oldXDG, hadXDG := os.LookupEnv("XDG_CONFIG_HOME")
	if err := os.Setenv("AppData", home); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	defer func() {
		restoreEnv(t, "AppData", oldAppData, hadAppData)
		restoreEnv(t, "HOME", oldHome, hadHome)
		restoreEnv(t, "XDG_CONFIG_HOME", oldXDG, hadXDG)
	}()
	fn()
}

func restoreEnv(t *testing.T, key, val string, had bool) {
	t.Helper()
	var err error
	if had {
		err = os.Setenv(key, val)
	} else {
		err = os.Unsetenv(key)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// pullFresh pulls ref as a fresh link holder (no credentials) and returns the bytes.
func pullFresh(t *testing.T, ref, password string) []byte {
	t.Helper()
	var got []byte
	withFreshEnv(t, func() {
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := runPull(ref, out, password, false, false); err != nil {
			t.Fatalf("link pull: %v", err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		got = b
	})
	return got
}

// ownerFileRoot opens a streamed resource's root as the owner (authed client, cached
// session), so a test can assert on its structure or pull real object ids.
func ownerFileRoot(t *testing.T, id string) syncengine.FileRoot {
	t.Helper()
	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	root, err := syncengine.OpenFileRoot(res.Blob, ck, id)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestShareStreamedLinkPull is the acceptance-criteria test: an owner shares a streamed
// private file, and a machine with no account credentials pulls it byte-for-byte from
// the share link alone.
func TestShareStreamedLinkPull(t *testing.T) {
	newE2E(t)

	id, data, _ := pushRandomStreamedFile(t, 9<<20, pushOptions{noClip: true, quiet: true})

	link := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, "", true, linkPolicy{}); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	if !strings.Contains(link, "#k.") {
		t.Fatalf("share link %q missing public key fragment", link)
	}

	if got := pullFresh(t, link, ""); !bytes.Equal(got, data) {
		t.Fatal("link pull content mismatch")
	}
}

// TestShareStreamedIndirectLinkPull covers the indirect-root form: a file large enough
// that its chunk list is stored as sealed segments must resolve those segments through
// the public endpoint too, before the content objects.
func TestShareStreamedIndirectLinkPull(t *testing.T) {
	newE2E(t)

	// A chunk list goes indirect strictly above chunkListInlineMax (128) records.
	// Content-defined chunking of a 40 MiB file averages ~160 chunks but is a random
	// variable over the input bytes; with crypto/rand it once cut only 126 in CI,
	// leaving the list inline and failing the assertion below. Seed the payload so the
	// chunk count is reproducible, and size it to sit well clear of the boundary.
	data := make([]byte, 48<<20)
	if _, err := mrand.New(mrand.NewSource(0x5eaf00d)).Read(data); err != nil {
		t.Fatal(err)
	}
	id, _ := pushStreamedFile(t, data, pushOptions{noClip: true, quiet: true})

	// The stored root must be indirect, else the test does not exercise segment reads.
	root := ownerFileRoot(t, id)
	if !root.Indirect() {
		t.Fatalf("expected an indirect chunk list for a 48 MiB file, got %d inline chunks", len(root.Chunks))
	}

	link := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, "", true, linkPolicy{}); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))

	if got := pullFresh(t, link, ""); !bytes.Equal(got, data) {
		t.Fatal("indirect link pull content mismatch")
	}
}

// TestPrivateRotatesStreamedLink proves rotation: after `aqt private`, the old link no
// longer pulls and its objects are no longer public, while the owner still pulls the
// file byte-for-byte (the rotation preserved ChunkRefs and re-sealed the root).
func TestPrivateRotatesStreamedLink(t *testing.T) {
	h := newE2E(t)

	id, data, _ := pushRandomStreamedFile(t, 9<<20, pushOptions{noClip: true, quiet: true})

	// Grab a real content-object id (referenced by the resource) for the public-read
	// assertion after rotation.
	objID := ownerFileRoot(t, id).ChunkIDs()[0]

	cl, err := client.New(h.url, "")
	if err != nil {
		t.Fatal(err)
	}

	link := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, "", true, linkPolicy{}); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	if got := pullFresh(t, link, ""); !bytes.Equal(got, data) {
		t.Fatal("pre-rotation link pull content mismatch")
	}

	if err := runPrivate(id); err != nil {
		t.Fatalf("private: %v", err)
	}

	// The old link is dead: the resource is private again, so an unauthenticated fetch
	// 404s and the public object read is refused.
	withFreshEnv(t, func() {
		out := filepath.Join(t.TempDir(), "dead.bin")
		if err := runPull(link, out, "", false, false); err == nil {
			t.Fatal("old link still pulled after rotation")
		}
	})
	if _, err := cl.PublicObjects(id, []string{objID}); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("PublicObjects after rotation err = %v, want ErrNotFound", err)
	}

	// The owner still pulls it, proving the rotation kept the objects alive and the
	// re-sealed root opens under the new key.
	out := filepath.Join(t.TempDir(), "owner.bin")
	if err := runPull(id, out, "", false, false); err != nil {
		t.Fatalf("owner pull after rotation: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("owner content changed after rotation")
	}
}

// TestPublicStreamedPushLinkPull covers `aqt push --public` on a large file: it streams
// (rather than sealing in memory) and the printed URL pulls from a fresh env.
func TestPublicStreamedPushLinkPull(t *testing.T) {
	newE2E(t)

	_, data, printed := pushRandomStreamedFile(t, 9<<20, pushOptions{public: true, noClip: true, quiet: true})
	if !strings.Contains(printed, "#k.") {
		t.Fatalf("public push output %q missing key fragment", printed)
	}

	if got := pullFresh(t, printed, ""); !bytes.Equal(got, data) {
		t.Fatal("public streamed push link pull mismatch")
	}
}

// TestGatedStreamedShareLinkPull covers a password-gated share of a streamed file: the
// link carries a gated fragment and pulls only with the password.
func TestGatedStreamedShareLinkPull(t *testing.T) {
	newE2E(t)

	const password = "hunter2 correct horse"
	id, data, _ := pushRandomStreamedFile(t, 9<<20, pushOptions{noClip: true, quiet: true})

	link := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, password, true, linkPolicy{}); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	if !strings.Contains(link, "#p.") {
		t.Fatalf("gated share link %q missing gated fragment", link)
	}

	if got := pullFresh(t, link, password); !bytes.Equal(got, data) {
		t.Fatal("gated link pull content mismatch")
	}
}
