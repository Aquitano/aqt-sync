package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// pushSharedFolder inits and syncs a folder with a subdirectory, a multi-chunk file,
// and an empty directory, then returns its resource id and the origin dir.
func pushSharedFolder(t *testing.T, h *e2eHarness) (id, origin string) {
	t.Helper()
	origin = t.TempDir()
	h.init(origin)
	writeTree(t, origin, "docs/readme.txt", "hello folder share")
	writeTree(t, origin, "data/big.bin", bigContent())
	if err := os.MkdirAll(filepath.Join(origin, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sync(origin)
	return h.folderID(origin), origin
}

// shareFolder runs `aqt share` on id and returns the printed link.
func shareFolder(t *testing.T, id, password string, policy linkPolicy) string {
	t.Helper()
	link := strings.TrimSpace(captureStdout(t, func() {
		if err := runShare(id, password, true, policy); err != nil {
			t.Fatalf("share: %v", err)
		}
	}))
	if link == "" {
		t.Fatal("share printed no link")
	}
	return link
}

// ownerTreeRootID opens the folder's root as the owner and returns the root
// directory node's object id — a referenced object usable in public-read assertions.
func ownerTreeRootID(t *testing.T, id string) string {
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
	root, err := syncengine.OpenTreeRoot(res.Blob, ck, id)
	if err != nil {
		t.Fatal(err)
	}
	return root.Root.ID
}

// TestShareFolderLinkCloneAndSubpathPull is the issue #57 acceptance test: an owner
// shares a chunked folder, and a machine with no credentials clones the link and
// pulls single entries through both subpath link forms.
func TestShareFolderLinkCloneAndSubpathPull(t *testing.T) {
	h := newE2E(t)
	id, origin := pushSharedFolder(t, h)

	link := shareFolder(t, id, "", linkPolicy{})
	if !strings.Contains(link, "#k.") {
		t.Fatalf("folder share link %q missing public key fragment", link)
	}

	// --adopt needs an account; a link is read-only.
	if err := runClone(link, t.TempDir(), true, ""); err == nil {
		t.Fatal("clone --adopt of a share link should be refused")
	}

	withFreshEnv(t, func() {
		dest := filepath.Join(t.TempDir(), "clone")
		if err := runClone(link, dest, false, ""); err != nil {
			t.Fatalf("link clone: %v", err)
		}
		assertTreeEqual(t, origin, dest)
		if fi, err := os.Stat(filepath.Join(dest, "empty")); err != nil || !fi.IsDir() {
			t.Fatalf("empty directory did not materialize from the link: err=%v", err)
		}
		// A link clone is not a tracked folder: there is no token to sync with.
		if _, err := os.Stat(filepath.Join(dest, syncengine.ControlDir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("link clone wrote tracking state: err=%v", err)
		}

		// Subpath pull, naive-append form: <whole link>/<path>.
		out := filepath.Join(t.TempDir(), "readme.txt")
		if err := runPull(link+"/docs/readme.txt", out, "", false, false); err != nil {
			t.Fatalf("link subpath pull: %v", err)
		}
		if got, err := os.ReadFile(out); err != nil || string(got) != "hello folder share" {
			t.Fatalf("subpath pull content = %q, err=%v", got, err)
		}

		// Subpath pull, URL form: path segments before the fragment, multi-chunk file.
		urlForm := strings.Replace(link, "#", "/data/big.bin#", 1)
		out2 := filepath.Join(t.TempDir(), "big.bin")
		if err := runPull(urlForm, out2, "", false, false); err != nil {
			t.Fatalf("url-form subpath pull: %v", err)
		}
		if got, err := os.ReadFile(out2); err != nil || string(got) != bigContent() {
			t.Fatalf("url-form subpath pull mismatch (len=%d), err=%v", len(got), err)
		}
	})
}

// TestPrivateRotatesFolderLink proves folder rotation: after `aqt private`, the old
// link neither fetches nor decrypts, its objects are no longer publicly served, the
// owner still clones the folder intact, and a re-share mints a fresh key the old
// fragment cannot substitute for.
func TestPrivateRotatesFolderLink(t *testing.T) {
	h := newE2E(t)
	id, origin := pushSharedFolder(t, h)

	link := shareFolder(t, id, "", linkPolicy{})
	withFreshEnv(t, func() {
		if err := runClone(link, filepath.Join(t.TempDir(), "pre"), false, ""); err != nil {
			t.Fatalf("pre-rotation link clone: %v", err)
		}
	})

	if err := runPrivate(id); err != nil {
		t.Fatalf("private: %v", err)
	}
	rootObjID := ownerTreeRootID(t, id)

	// The owner still clones the folder byte-for-byte: the rotation re-sent the full
	// GC roots and re-sealed the root under the new wrapped key.
	ownerDest := filepath.Join(t.TempDir(), "owner")
	h.clone(id, ownerDest)
	assertTreeEqual(t, origin, ownerDest)

	// The old link is dead: the resource is private, so the fetch 404s and the
	// public object read refuses even a genuinely referenced node object.
	withFreshEnv(t, func() {
		if err := runClone(link, filepath.Join(t.TempDir(), "dead"), false, ""); err == nil {
			t.Fatal("old link still cloned after rotation")
		}
	})
	anon, err := client.New(h.url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anon.PublicObjects(id, []string{rootObjID}); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("PublicObjects after rotation err = %v, want ErrNotFound", err)
	}

	// A re-share mints a new key; the old fragment cannot decrypt the re-shared root.
	relink := shareFolder(t, id, "", linkPolicy{})
	if relink == link {
		t.Fatal("re-share printed the old link; the key did not rotate")
	}
	withFreshEnv(t, func() {
		if err := runClone(relink, filepath.Join(t.TempDir(), "fresh"), false, ""); err != nil {
			t.Fatalf("re-shared link clone: %v", err)
		}
		if err := runClone(link, filepath.Join(t.TempDir(), "stale"), false, ""); err == nil {
			t.Fatal("old fragment decrypted the re-shared folder")
		}
	})
}

// TestGatedFolderShareLinkClone covers a password-gated folder link: it clones with
// the password and refuses without it.
func TestGatedFolderShareLinkClone(t *testing.T) {
	h := newE2E(t)
	const password = "hunter2 correct horse"
	id, origin := pushSharedFolder(t, h)

	link := shareFolder(t, id, password, linkPolicy{})
	if !strings.Contains(link, "#p.") {
		t.Fatalf("gated folder link %q missing gated fragment", link)
	}

	withFreshEnv(t, func() {
		dest := filepath.Join(t.TempDir(), "gated")
		if err := runClone(link, dest, false, password); err != nil {
			t.Fatalf("gated link clone: %v", err)
		}
		assertTreeEqual(t, origin, dest)
		if err := runClone(link, filepath.Join(t.TempDir(), "wrong"), false, "not the password"); err == nil {
			t.Fatal("gated link cloned with the wrong password")
		}
	})
}

// TestFolderLinkBurnCountsCloneAsOneRead pins the lifecycle semantics for folders:
// only the resource fetch counts against --max-reads, so a clone's many object
// requests consume one read, and the next fetch is gone.
func TestFolderLinkBurnCountsCloneAsOneRead(t *testing.T) {
	h := newE2E(t)
	id, origin := pushSharedFolder(t, h)

	policy, err := resolveLinkPolicy("", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	link := shareFolder(t, id, "", policy)

	withFreshEnv(t, func() {
		dest := filepath.Join(t.TempDir(), "burn")
		if err := runClone(link, dest, false, ""); err != nil {
			t.Fatalf("burn link first clone: %v", err)
		}
		assertTreeEqual(t, origin, dest)
		if err := runClone(link, filepath.Join(t.TempDir(), "again"), false, ""); err == nil {
			t.Fatal("burn link cloned twice")
		}
	})
}

// TestFolderLinkIsReadOnly locks in that a link holder can only pull: without a
// token every write surface is refused, and the public object endpoint never serves
// an object the shared folder does not reference (pack-neighbor isolation).
func TestFolderLinkIsReadOnly(t *testing.T) {
	h := newE2E(t)
	id, _ := pushSharedFolder(t, h)
	shareFolder(t, id, "", linkPolicy{})

	// A private streamed file of the same owner shares the pack space; its objects
	// must not be readable through the public folder.
	otherID, _, _ := pushRandomStreamedFile(t, 9<<20, pushOptions{noClip: true, quiet: true})
	neighborObj := ownerFileRoot(t, otherID).ChunkIDs()[0]

	anon, err := client.New(h.url, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anon.PublicObjects(id, []string{neighborObj}); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("neighbor object served through public folder: err = %v, want ErrNotFound", err)
	}

	if _, err := anon.PutResource(api.PutResourceRequest{ID: id, Visibility: api.Public}); err == nil {
		t.Fatal("tokenless PutResource succeeded on a public folder")
	}
	if _, err := anon.SetVisibility(id, api.Private, 0, 0); err == nil {
		t.Fatal("tokenless SetVisibility succeeded on a public folder")
	}
	if err := anon.DeleteResource(id); err == nil {
		t.Fatal("tokenless DeleteResource succeeded on a public folder")
	}

	// The write attempts changed nothing: the owner still sees the folder public
	// and at its original version.
	cl, _, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	if res.Visibility != api.Public {
		t.Fatalf("visibility changed to %q by tokenless writes", res.Visibility)
	}
}

// TestSplitRefPathShareURLForms covers the link subpath forms splitRefPath accepts.
func TestSplitRefPathShareURLForms(t *testing.T) {
	cases := []struct {
		ref, base, sub string
	}{
		{"aqt://abc", "aqt://abc", ""},
		{"aqt://abc/docs/x.txt", "aqt://abc", "docs/x.txt"},
		{"https://s/x/abc#k.KEY", "https://s/x/abc#k.KEY", ""},
		{"https://s/x/abc/docs/x.txt#k.KEY", "https://s/x/abc#k.KEY", "docs/x.txt"},
		{"https://s/x/abc#k.KEY/docs/x.txt", "https://s/x/abc#k.KEY", "docs/x.txt"},
		{"https://s/x/abc#p.GATED/a/b/", "https://s/x/abc#p.GATED", "a/b"},
		{"abc", "abc", ""},
	}
	for _, c := range cases {
		base, sub := splitRefPath(c.ref)
		if base != c.base || sub != c.sub {
			t.Errorf("splitRefPath(%q) = (%q, %q), want (%q, %q)", c.ref, base, sub, c.base, c.sub)
		}
	}
}
