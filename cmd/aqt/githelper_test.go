package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/update"
)

// Git execs the helper under its own name, so argv[0] alone decides whether this
// binary is a client or a remote helper. The match must be exact: a name that
// merely starts with the helper's must stay an ordinary aqt invocation.
func TestMultiCallArgsDispatchesOnExactName(t *testing.T) {
	helper := helperLinkName()
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"bare helper name", []string{helper, "origin", "aqt::notes"},
			[]string{helper, "git-remote-helper", "origin", "aqt::notes"}},
		{"absolute path", []string{"/usr/local/bin/" + helper, "origin", "aqt::notes"},
			[]string{"/usr/local/bin/" + helper, "git-remote-helper", "origin", "aqt::notes"}},
		{"client", []string{"aqt", "status"}, []string{"aqt", "status"}},
		{"prefix only", []string{helperName + "-old", "origin", "aqt::notes"},
			[]string{helperName + "-old", "origin", "aqt::notes"}},
		{"suffix only", []string{"my-" + helperName, "origin"}, []string{"my-" + helperName, "origin"}},
		{"no argv", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := multiCallArgs(tc.argv)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("multiCallArgs(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// The rewritten command line has to reach the hidden subcommand that carries the
// helper protocol, with Git's two arguments intact.
func TestMultiCallArgsReachTheHelperSubcommand(t *testing.T) {
	root := rootCmd()
	argv := multiCallArgs([]string{helperLinkName(), "origin", "aqt::notes"})
	cmd, flags, err := root.Find(argv[1:])
	if err != nil {
		t.Fatalf("find %q: %v", argv, err)
	}
	if cmd.Name() != "git-remote-helper" {
		t.Fatalf("argv resolved to %q, want git-remote-helper", cmd.Name())
	}
	if err := cmd.Args(cmd, flags); err != nil {
		t.Errorf("helper rejected Git's arguments %q: %v", flags, err)
	}
}

func TestGitSetupCreatesLinkAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, helperLinkName())

	if err := runGitSetup(dir, false); err != nil {
		t.Fatalf("git setup: %v", err)
	}
	if !sameExecutable(link, exe) {
		t.Fatalf("%s does not resolve to the running binary", link)
	}
	if err := runGitSetup(dir, false); err != nil {
		t.Errorf("second git setup: %v", err)
	}
}

// Upgrading from the standalone helper means replacing a real binary that sits
// under the same name; without --yes and without a terminal, that must not happen.
func TestGitSetupReplacesAnExistingHelperOnlyWithConsent(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, helperLinkName())
	if err := os.WriteFile(link, []byte("old standalone helper"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := runGitSetup(dir, false); err == nil {
		t.Error("git setup replaced an existing helper without confirmation")
	}
	if data, err := os.ReadFile(link); err != nil || string(data) != "old standalone helper" {
		t.Fatalf("existing helper was modified: %q, %v", data, err)
	}

	if err := runGitSetup(dir, true); err != nil {
		t.Fatalf("git setup -y: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !sameExecutable(link, exe) {
		t.Errorf("%s still does not resolve to the running binary", link)
	}
}

// A hard link or a copy stays bound to the binary `aqt update` replaced, so the
// upgrade has to be able to spot one and say so.
func TestHelperLinkStaleDetectsUnlinkedCopies(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "aqt")
	if err := os.WriteFile(exe, []byte("new client"), 0o755); err != nil {
		t.Fatal(err)
	}
	if helperLinkStale(dir, exe) {
		t.Error("a missing link reads as stale")
	}

	link := filepath.Join(dir, helperLinkName())
	if err := os.WriteFile(link, []byte("client from the previous release"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !helperLinkStale(dir, exe) {
		t.Error("a copy of the replaced binary does not read as stale")
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := linkHelper(exe, link); err != nil {
		t.Fatal(err)
	}
	if helperLinkStale(dir, exe) {
		t.Error("a freshly created link reads as stale")
	}
}

// A package manager records every file it installs, so aqt must not add one to a
// directory it does not own, and must say where the link can go instead.
func TestDefaultHelperDirRefusesPackageManagedInstalls(t *testing.T) {
	exe := filepath.Join("/opt/aqt/bin", "aqt")

	for _, owner := range []update.Owner{update.OwnerStandalone, update.OwnerSource} {
		dir, err := defaultHelperDir(exe, update.Install{Owner: owner})
		if err != nil {
			t.Errorf("defaultHelperDir(%s) = %v, want the binary's directory", owner, err)
		}
		if dir != filepath.Dir(exe) {
			t.Errorf("defaultHelperDir(%s) = %q, want %q", owner, dir, filepath.Dir(exe))
		}
	}

	in := update.Install{Owner: update.OwnerHomebrew, Dir: "/opt/homebrew/bin", UpgradeCommand: "brew upgrade aqt"}
	_, err := defaultHelperDir(exe, in)
	if err == nil {
		t.Fatal("defaultHelperDir accepted a Homebrew-owned install")
	}
	for _, want := range []string{"homebrew", in.Dir, "--dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}
