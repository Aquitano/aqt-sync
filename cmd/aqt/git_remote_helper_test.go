package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/gitremote"
)

func TestGitRemoteHelperCapabilitiesAndOptions(t *testing.T) {
	input := strings.NewReader("capabilities\noption verbosity 2\noption progress true\noption object-format true\noption unknown value\n")
	var output bytes.Buffer
	h := &remoteHelper{
		remoteName: "origin", rawURL: "aqt::brain", in: input,
		out: bufio.NewWriter(&output), errOut: &bytes.Buffer{},
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	want := "fetch\npush\noption\nobject-format\n\nok\nok\nok\nunsupported\n"
	if output.String() != want {
		t.Fatalf("protocol output:\n%q\nwant:\n%q", output.String(), want)
	}
	if h.verbosity != 2 || !h.progress || !h.objectFormat {
		t.Fatalf("options not recorded: verbosity=%d progress=%t object-format=%t", h.verbosity, h.progress, h.objectFormat)
	}
}

func TestParsePushRefspec(t *testing.T) {
	tests := []struct {
		in               string
		src, dst         string
		force, deleteRef bool
	}{
		{"refs/heads/main:refs/heads/main", "refs/heads/main", "refs/heads/main", false, false},
		{"+HEAD:refs/heads/main", "HEAD", "refs/heads/main", true, false},
		{":refs/tags/v1", "", "refs/tags/v1", false, true},
	}
	for _, tt := range tests {
		got, err := parsePushRefspec(tt.in)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.in, err)
		}
		if got.src != tt.src || got.dst != tt.dst || got.force != tt.force || got.delete != tt.deleteRef {
			t.Fatalf("parse %q = %+v", tt.in, got)
		}
	}
	for _, bad := range []string{"main", "main:", "main:main"} {
		if _, err := parsePushRefspec(bad); err == nil {
			t.Fatalf("parsePushRefspec(%q) succeeded", bad)
		}
	}
}

func TestApplyPushesInitializesHeadAndHandlesDeletion(t *testing.T) {
	root := applyPushes(gitremote.NewRefsRoot(), []helperPush{
		{dst: "refs/tags/v1", localOID: "tag"},
		{dst: "refs/heads/main", localOID: "main"},
	}, "sha1")
	if root.Head != "refs/heads/main" || root.ObjectFormat != "sha1" || root.Refs["refs/tags/v1"] != "tag" {
		t.Fatalf("initial root = %+v", root)
	}
	root = applyPushes(root, []helperPush{
		{dst: "refs/heads/next", localOID: "next"},
		{dst: "refs/heads/main", delete: true},
	}, "sha1")
	if root.Head != "refs/heads/next" {
		t.Fatalf("HEAD after deletion = %q", root.Head)
	}
	if _, ok := root.Refs["refs/heads/main"]; ok {
		t.Fatal("deleted branch remains in refs")
	}
}

func TestValidGitOID(t *testing.T) {
	sha1 := strings.Repeat("a", 40)
	sha256 := strings.Repeat("0123456789abcdef", 4)
	for _, ok := range []string{sha1, sha256} {
		if !validGitOID(ok) {
			t.Fatalf("valid oid %q rejected", ok)
		}
	}
	for _, bad := range []string{
		"", "-" + sha1[1:], strings.ToUpper(sha1), sha1[:39], sha1 + "a",
		"refs/heads/main", "main", sha1[:20] + " " + sha1[21:],
	} {
		if validGitOID(bad) {
			t.Fatalf("invalid oid %q accepted", bad)
		}
	}
}

func TestGitRemoteTarget(t *testing.T) {
	if got, err := gitRemoteTarget("aqt::brain"); err != nil || got != "brain" {
		t.Fatalf("target = %q err=%v", got, err)
	}
	if got, err := gitRemoteTarget("brain"); err != nil || got != "brain" {
		t.Fatalf("Git-stripped target = %q err=%v", got, err)
	}
	for _, raw := range []string{"https://example.com", "aqt::"} {
		if _, err := gitRemoteTarget(raw); err == nil {
			t.Fatalf("gitRemoteTarget(%q) succeeded", raw)
		}
	}
}

// `git bundle create` refuses to overwrite, so the path handed to it must not exist.
// It must still be unreachable to other local users: the bundle is the repository in
// plaintext, and a name reserved and released in the shared temp directory can be
// claimed by a symlink before Git creates the file.
func TestNewBundlePathIsPrivate(t *testing.T) {
	path, cleanup, err := newBundlePath("aqt-test-bundle-")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("bundle path already exists (git bundle create would refuse it): %v", err)
	}
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("bundle directory mode = %#o, want no group or other access", perm)
		}
	}
	if dir == os.TempDir() {
		t.Error("bundle was placed directly in the shared temp directory")
	}

	// Git creates the file itself; cleanup has to take the directory with it.
	if err := os.WriteFile(path, []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("cleanup left %s behind: %v", dir, err)
	}
}
