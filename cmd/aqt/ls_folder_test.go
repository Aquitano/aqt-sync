package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/identity"
)

// TestLsFolderListsMembers covers `aqt ls <folder>`: it must list a folder's
// member files from the manifest, resolve the folder by either name or id, and
// reject a file argument. The listing reads only the manifest, so it works
// without materializing the folder's content.
func TestLsFolderListsMembers(t *testing.T) {
	h := newE2E(t)

	// A single-file push, to prove `ls <file>` is rejected with a helpful error.
	fdir := t.TempDir()
	fpath := filepath.Join(fdir, "secret.env")
	if err := os.WriteFile(fpath, []byte("API_KEY=xyz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(fpath, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}

	// A tracked folder with nested files.
	folder := t.TempDir()
	h.init(folder)
	writeTree(t, folder, "notes/todo.txt", "buy milk")
	writeTree(t, folder, "keys/.env", "TOKEN=1")
	h.sync(folder)

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("expected a cached session")
	}

	name := filepath.Base(folder)
	id := h.folderID(folder)

	// Resolving by name and by id must land on the same folder.
	gotID, gotName, err := resolveOwnedFolder(cl, mk, name)
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	if gotID != id || gotName != name {
		t.Fatalf("resolve by name = (%s,%s), want (%s,%s)", gotID, gotName, id, name)
	}
	if idByID, _, err := resolveOwnedFolder(cl, mk, id); err != nil || idByID != id {
		t.Fatalf("resolve by id = (%s, %v), want %s", idByID, err, id)
	}

	// The human listing shows every member path.
	out := captureStdout(t, func() {
		if err := listFolder(cl, mk, name); err != nil {
			t.Fatalf("listFolder: %v", err)
		}
	})
	// init seeds a default .aqtignore, so the folder holds the two written files
	// plus that one.
	for _, want := range []string{"notes/todo.txt", "keys/.env", "3 files"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls %s output missing %q:\n%s", name, want, out)
		}
	}

	// A file argument is not a folder and must be rejected, not listed empty.
	if _, _, err := resolveOwnedFolder(cl, mk, "secret.env"); err == nil ||
		!strings.Contains(err.Error(), "file, not a folder") {
		t.Errorf("resolve of a file err = %v, want a 'file, not a folder' error", err)
	}

	// An unknown name is a clear error rather than an empty listing.
	if _, _, err := resolveOwnedFolder(cl, mk, "no-such-thing"); err == nil ||
		!strings.Contains(err.Error(), "no resource named") {
		t.Errorf("resolve of unknown name err = %v, want a 'no resource named' error", err)
	}
}
