package main

import (
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// withStdin points os.Stdin at a pipe carrying s for the duration of the test.
func withStdin(t *testing.T, s string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig; r.Close() })
	go func() {
		defer w.Close()
		_, _ = w.WriteString(s)
	}()
}

func TestPasswordFlagsResolve(t *testing.T) {
	t.Run("flag value passes through", func(t *testing.T) {
		pw := passwordFlags{value: "hunter2"}
		got, err := pw.resolve()
		if err != nil || got != "hunter2" {
			t.Fatalf("resolve() = %q, %v; want hunter2", got, err)
		}
	})

	t.Run("stdin strips one trailing newline", func(t *testing.T) {
		withStdin(t, "hunter2\n")
		pw := passwordFlags{fromStdin: true}
		got, err := pw.resolve()
		if err != nil || got != "hunter2" {
			t.Fatalf("resolve() = %q, %v; want hunter2", got, err)
		}
	})

	// A password may legitimately contain spaces, so only the trailing newline goes.
	t.Run("stdin keeps interior spaces", func(t *testing.T) {
		withStdin(t, "correct horse battery staple\n")
		pw := passwordFlags{fromStdin: true}
		got, err := pw.resolve()
		if err != nil || got != "correct horse battery staple" {
			t.Fatalf("resolve() = %q, %v", got, err)
		}
	})

	t.Run("flag and stdin are mutually exclusive", func(t *testing.T) {
		pw := passwordFlags{value: "a", fromStdin: true}
		if _, err := pw.resolve(); err == nil {
			t.Fatal("resolve() accepted both --password and --password-stdin")
		}
	})
}

// The TUI collects the share password in a masked prompt, so it must never hand it
// to the child in argv, where any local user can read it out of ps.
func TestTUISharePasswordNeverHitsArgv(t *testing.T) {
	m := testModel(t)
	m.setFocus(tuiPanelResources)

	// s opens the share menu; its "p" entry opens the password prompt.
	m.handleKey(key("s"))
	menu, ok := m.dialog.(*tuiMenu)
	if !ok {
		t.Fatalf("s opened %T, want the share menu", m.dialog)
	}
	var open tea.Cmd
	for _, o := range menu.options {
		if o.key == "p" {
			open = o.cmd
		}
	}
	if open == nil {
		t.Fatal("share menu has no password-gated entry")
	}
	dlg, ok := open().(tuiOpenDialogMsg)
	if !ok {
		t.Fatalf("password entry produced %T, want a dialog", open())
	}
	in, ok := dlg.dialog.(*tuiInput)
	if !ok {
		t.Fatalf("password entry opened %T, want an input", dlg.dialog)
	}
	if in.input.EchoMode != textinput.EchoPassword {
		t.Fatal("the share password prompt is not masked")
	}

	msg, ok := in.submit("swordfish")().(tuiExecRequestMsg)
	if !ok {
		t.Fatal("submitting the password did not request an action")
	}

	for _, a := range msg.sub {
		if a == "-P" || a == "--password" {
			t.Fatalf("share action argv %v carries the password flag; it belongs on stdin", msg.sub)
		}
		if strings.Contains(a, "swordfish") {
			t.Fatalf("share action argv %v contains the password itself", msg.sub)
		}
	}
	if !contains(msg.sub, "--password-stdin") {
		t.Fatalf("share action argv %v does not ask the child to read stdin", msg.sub)
	}
	if strings.TrimRight(msg.stdin, "\n") != "swordfish" {
		t.Fatalf("stdin payload = %q, want the password", msg.stdin)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
