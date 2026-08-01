package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMaterializeStaged(t *testing.T) {
	t.Run("commits a complete result", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "a", "b", "out")
		err := materializeStaged(dest, func(staging string) error {
			return os.WriteFile(filepath.Join(staging, "f.txt"), []byte("x"), 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := readTree(t, dest, "f.txt"); got != "x" {
			t.Fatalf("f.txt = %q", got)
		}
		if supportsPOSIXPermissions {
			want := os.FileMode(0o755) &^ currentUmask()
			if fi, err := os.Stat(dest); err != nil || fi.Mode().Perm() != want {
				t.Fatalf("dest mode = %v err=%v, want %v", fi.Mode(), err, want)
			}
		}
	})

	// The destination must not be more permissive than a plain MkdirAll would have
	// made it: `umask 077; aqt clone <id> ~/secrets` has to land 0700, not 0755.
	t.Run("the destination mode respects the umask", func(t *testing.T) {
		if !supportsPOSIXPermissions {
			t.Skip("Windows has no POSIX umask")
		}
		restore := setUmask(t, 0o077)
		defer restore()

		dest := filepath.Join(t.TempDir(), "secrets")
		if err := materializeStaged(dest, func(staging string) error {
			return os.WriteFile(filepath.Join(staging, "f.txt"), []byte("x"), 0o600)
		}); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dest)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Fatalf("dest mode under umask 077 = %v, want 0700", fi.Mode().Perm())
		}
	})

	t.Run("a failing fn leaves no destination", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "out")
		err := materializeStaged(dest, func(staging string) error {
			if err := os.WriteFile(filepath.Join(staging, "partial"), []byte("x"), 0o644); err != nil {
				return err
			}
			return errors.New("interrupted")
		})
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Fatalf("err = %v", err)
		}
		if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed materialization left %s behind", dest)
		}
		entries, err := os.ReadDir(filepath.Dir(dest))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("staging debris left behind: %v", entries)
		}
	})

	t.Run("a non-empty destination is refused before any work", func(t *testing.T) {
		dest := t.TempDir()
		writeTree(t, dest, "existing.txt", "keep me")
		ran := false
		err := materializeStaged(dest, func(string) error { ran = true; return nil })
		if err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("err = %v", err)
		}
		if ran {
			t.Fatal("fn ran although the destination collision was known up front")
		}
		if got := readTree(t, dest, "existing.txt"); got != "keep me" {
			t.Fatalf("existing content touched: %q", got)
		}
	})

	t.Run("a file at the destination is refused", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "out")
		if err := os.WriteFile(dest, []byte("a file"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := materializeStaged(dest, func(string) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an existing empty directory is replaced", func(t *testing.T) {
		dir := t.TempDir()
		dest := filepath.Join(dir, "out")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatal(err)
		}
		err := materializeStaged(dest, func(staging string) error {
			return os.WriteFile(filepath.Join(staging, "f.txt"), []byte("x"), 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := readTree(t, dest, "f.txt"); got != "x" {
			t.Fatalf("f.txt = %q", got)
		}
	})

	t.Run("an unwritable parent fails without debris", func(t *testing.T) {
		if !supportsPOSIXPermissions {
			t.Skip("POSIX directory write permissions are not enforced on Windows")
		}
		if os.Geteuid() == 0 {
			t.Skip("running as root; permission bits do not apply")
		}
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0o755) })
		err := materializeStaged(filepath.Join(parent, "out"), func(string) error { return nil })
		if err == nil {
			t.Fatal("expected a permission error")
		}
	})
}

// An interrupted clone (transfer dies mid-download) must leave no destination
// directory at all, not a partial tree.
func TestCloneInterruptedLeavesNoDestination(t *testing.T) {
	var failPacks atomic.Bool
	h := newE2EWithProxy(t, func(w http.ResponseWriter, r *http.Request, pass http.HandlerFunc) {
		if failPacks.Load() && strings.Contains(r.URL.Path, "/packs") {
			http.Error(w, "injected transfer failure", http.StatusInternalServerError)
			return
		}
		pass(w, r)
	})
	origin := t.TempDir()
	h.init(origin)
	writeTree(t, origin, "a.txt", strings.Repeat("data", 1024))
	h.sync(origin)
	id := h.folderID(origin)

	dest := filepath.Join(t.TempDir(), "copy")
	failPacks.Store(true)
	if err := runClone(id, dest, false, ""); err == nil {
		t.Fatal("clone with failing transfers succeeded")
	}
	if _, err := os.Stat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted clone left %s behind", dest)
	}

	failPacks.Store(false)
	h.clone(id, dest)
	assertTreeEqual(t, origin, dest)
}
