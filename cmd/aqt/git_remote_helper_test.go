package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
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
	want := "fetch\noption\n\nok\nok\nunsupported\n"
	if output.String() != want {
		t.Fatalf("protocol output:\n%q\nwant:\n%q", output.String(), want)
	}
	if h.verbosity != 2 || !h.progress {
		t.Fatalf("options not recorded: verbosity=%d progress=%t", h.verbosity, h.progress)
	}
}

func TestGitRemoteTarget(t *testing.T) {
	if got, err := gitRemoteTarget("aqt::brain"); err != nil || got != "brain" {
		t.Fatalf("target = %q err=%v", got, err)
	}
	for _, raw := range []string{"brain", "aqt::"} {
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
