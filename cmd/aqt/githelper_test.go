// SPDX-License-Identifier: AGPL-3.0-or-later

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
		name   string
		argv   []string
		want   []string
		helper bool
	}{
		{"bare helper name", []string{helper, "origin", "aqt::notes"},
			[]string{"git-remote-helper", "origin", "aqt::notes"}, true},
		{"absolute path", []string{"/usr/local/bin/" + helper, "origin", "aqt::notes"},
			[]string{"git-remote-helper", "origin", "aqt::notes"}, true},
		{"client", []string{"aqt", "status"}, nil, false},
		{"prefix only", []string{helperName + "-old", "origin", "aqt::notes"}, nil, false},
		{"suffix only", []string{"my-" + helperName, "origin"}, nil, false},
		{"no argv", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, helper := multiCallArgs(tc.argv)
			if helper != tc.helper {
				t.Fatalf("multiCallArgs(%q) dispatched = %v, want %v", tc.argv, helper, tc.helper)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("multiCallArgs(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// The rewritten command line has to reach the hidden subcommand that carries the
// helper protocol, with Git's two arguments intact. That subcommand is also what a
// standalone git-remote-aqt from an older release execs, so its shape is a
// compatibility promise, not just an internal detail.
func TestMultiCallArgsReachTheHelperSubcommand(t *testing.T) {
	root := rootCmd()
	args, _ := multiCallArgs([]string{helperLinkName(), "origin", "aqt::notes"})
	cmd, flags, err := root.Find(args)
	if err != nil {
		t.Fatalf("find %q: %v", args, err)
	}
	if cmd.Name() != "git-remote-helper" {
		t.Fatalf("argv resolved to %q, want git-remote-helper", cmd.Name())
	}
	if err := cmd.Args(cmd, flags); err != nil {
		t.Errorf("helper rejected Git's arguments %q: %v", flags, err)
	}
}

// Git's arguments are protocol: aqt's own rewrite of dash-leading legacy ids must
// not reach them, or a remote whose name has that shape resolves to something else.
func TestHelperArgumentsBypassTheLegacyIDRewrite(t *testing.T) {
	root := rootCmd()
	remote := "-9_8_7_6_54"
	if got := escapeLeadingDashIDs(root, []string{"cat", remote}); got[1] == remote {
		t.Fatalf("premise broken: %q is no longer rewritten for a client invocation", remote)
	}

	args := rootArgs(root, []string{helperLinkName(), remote, "aqt::notes"})
	if got, want := strings.Join(args, " "), "git-remote-helper "+remote+" aqt::notes"; got != want {
		t.Fatalf("helper args = %q, want %q", got, want)
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
	if !samePath(link, exe) {
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
	if !samePath(link, exe) {
		t.Errorf("%s still does not resolve to the running binary", link)
	}
}

// A hard link or a copy stays bound to the binary `aqt update` replaced, so the
// upgrade has to be able to spot one and say so. Git finds the helper on PATH, so
// that is where the check has to look, whatever directory setup put it in.
func TestStaleHelperLinkDetectsUnlinkedCopies(t *testing.T) {
	dir := t.TempDir()
	onPath := t.TempDir()
	t.Setenv("PATH", onPath)
	exe := filepath.Join(dir, "aqt")
	if err := os.WriteFile(exe, []byte("new client"), 0o755); err != nil {
		t.Fatal(err)
	}
	in := update.Install{Path: exe, Dir: dir, Owner: update.OwnerStandalone}
	if _, stale := staleHelperLink(in); stale {
		t.Error("a missing link reads as stale")
	}

	link := filepath.Join(dir, helperLinkName())
	if err := os.WriteFile(link, []byte("client from the previous release"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, stale := staleHelperLink(in); !stale {
		t.Error("a copy of the replaced binary does not read as stale")
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := linkHelper(exe, link); err != nil {
		t.Fatal(err)
	}
	if _, stale := staleHelperLink(in); stale {
		t.Error("a freshly created link reads as stale")
	}

	// A link somewhere else on PATH is the one Git runs, so it decides.
	elsewhere := filepath.Join(onPath, helperLinkName())
	if err := os.WriteFile(elsewhere, []byte("client from the previous release"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, stale := staleHelperLink(in)
	if !stale {
		t.Error("a stale link earlier on PATH does not read as stale")
	}
	if got != elsewhere {
		t.Errorf("stale link reported as %q, want %q", got, elsewhere)
	}
}

// A package manager records every file it installs, so aqt must not add one to a
// directory it does not own, and must say where the link can go instead. --dir is
// the way out of that, not a way back into the same directory.
func TestHelperDirRefusesPackageManagedInstalls(t *testing.T) {
	exe := filepath.Join("/opt/aqt/bin", "aqt")

	for _, owner := range []update.Owner{update.OwnerStandalone, update.OwnerSource} {
		dir, err := helperDir("", exe, update.Install{Owner: owner})
		if err != nil {
			t.Errorf("helperDir(%s) = %v, want the binary's directory", owner, err)
		}
		if dir != filepath.Dir(exe) {
			t.Errorf("helperDir(%s) = %q, want %q", owner, dir, filepath.Dir(exe))
		}
	}

	in := update.Install{Owner: update.OwnerHomebrew, Dir: "/opt/homebrew/bin", UpgradeCommand: "brew upgrade aqt"}
	_, err := helperDir("", exe, in)
	if err == nil {
		t.Fatal("helperDir accepted a Homebrew-owned install")
	}
	for _, want := range []string{"homebrew", in.Dir, "--dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}

	owned := t.TempDir()
	if dir, err := helperDir(owned, exe, in); err != nil || dir != owned {
		t.Errorf("helperDir(%q) = %q, %v; want the directory the user named", owned, dir, err)
	}
}

// --dir naming the package's own directory is the same mistake spelled explicitly,
// including by a path that only resolves to it.
func TestHelperDirRefusesAnExplicitPackageDirectory(t *testing.T) {
	packaged := t.TempDir()
	in := update.Install{Owner: update.OwnerHomebrew, Dir: packaged, UpgradeCommand: "brew upgrade aqt"}
	exe := filepath.Join(packaged, "aqt")

	if _, err := helperDir(packaged, exe, in); err == nil {
		t.Error("helperDir accepted the package's own directory")
	}

	alias := filepath.Join(t.TempDir(), "bin")
	if err := os.Symlink(packaged, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := helperDir(alias, exe, in); err == nil {
		t.Error("helperDir accepted a symlink to the package's own directory")
	}
}
