package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/gitremote"
)

func TestGitRemoteHelperCapabilitiesAndOptions(t *testing.T) {
	input := strings.NewReader("capabilities\noption verbosity 2\noption progress true\noption unknown value\n")
	var output bytes.Buffer
	h := &remoteHelper{
		remoteName: "origin", rawURL: "aqt::brain", in: input,
		out: bufio.NewWriter(&output), errOut: &bytes.Buffer{},
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	want := "fetch\npush\noption\n\nok\nok\nunsupported\n"
	if output.String() != want {
		t.Fatalf("protocol output:\n%q\nwant:\n%q", output.String(), want)
	}
	if h.verbosity != 2 || !h.progress {
		t.Fatalf("options not recorded: verbosity=%d progress=%t", h.verbosity, h.progress)
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

func TestSafeRemoteNameCannotEscapeStateDirectory(t *testing.T) {
	if got := safeRemoteName("../../evil/remote"); strings.Contains(got, "/") || got == "." || got == ".." {
		t.Fatalf("unsafe remote name %q", got)
	}
}
