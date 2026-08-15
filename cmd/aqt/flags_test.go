// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGlobalFlagWiring pins the docs/cli.md global flag surface: the persistent
// flags live on root, --version/-v print and exit 0, and the per-command --json
// duplicates were consolidated onto the global.
func TestGlobalFlagWiring(t *testing.T) {
	root := rootCmd()

	for _, name := range []string{"server", "profile", "json", "quiet"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("root is missing persistent flag --%s", name)
		}
	}
	if root.PersistentFlags().Lookup("quiet").Shorthand != "q" {
		t.Errorf("--quiet shorthand = %q, want q", root.PersistentFlags().Lookup("quiet").Shorthand)
	}
	if root.PersistentFlags().Lookup("verbose") != nil {
		t.Error("root still exposes the no-op --verbose flag")
	}

	if root.Version == "" {
		t.Fatal("root.Version is unset; --version/-v would error")
	}
	vf := root.Flags().Lookup("version")
	if vf == nil {
		t.Fatal("root has no --version flag")
	}
	if vf.Shorthand != "v" {
		t.Errorf("--version shorthand = %q, want v", vf.Shorthand)
	}

	// Commands that previously owned a local --json must now inherit the global,
	// not redeclare it (a local duplicate would shadow the persistent flag).
	for _, name := range []string{"ls", "find", "info", "devices"} {
		sub := subcommand(t, root, name)
		if sub.Flags().Lookup("json") != nil {
			t.Errorf("%s still declares a local --json flag", name)
		}
	}

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("`aqt --version` returned an error: %v", err)
	}
	if !strings.Contains(out.String(), version) {
		t.Errorf("`aqt --version` output %q does not contain version %q", out.String(), version)
	}
}

func TestStandardizedCLIForms(t *testing.T) {
	assertOutFlag := func(name string, cmd *cobra.Command) {
		t.Helper()
		out := cmd.Flags().Lookup("out")
		if out == nil || out.Shorthand != "o" {
			t.Errorf("%s --out shorthand = %v, want -o", name, out)
		}
	}
	assertOutFlag("pull", pullCmd())
	assertOutFlag("restore", restoreCmd())
	assertOutFlag("snapshot export", snapshotExportCmd())

	contacts := contactsCmd()
	rm, _, err := contacts.Find([]string{"remove"})
	if err != nil || rm.Name() != "rm" {
		t.Fatalf("contacts remove alias resolved to %v, err=%v; want rm", rm, err)
	}

	snapshot := snapshotCmd()
	subcommand(t, snapshot, "unanchor")
	if subcommand(t, snapshot, "anchor").Flags().Lookup("remove") != nil {
		t.Error("snapshot anchor still exposes --remove")
	}
	prune := subcommand(t, snapshot, "prune")
	if prune.Flags().Lookup("before") == nil || prune.Flags().Lookup("older-than") != nil {
		t.Error("snapshot prune should expose --before, not --older-than")
	}
	create := subcommand(t, snapshot, "create")
	if err := create.Args(create, []string{".", "release"}); err != nil {
		t.Errorf("snapshot create rejected a positional label: %v", err)
	}

	pull := pullCmd()
	if pull.Flags().Lookup("stdout") != nil {
		t.Error("pull still exposes --stdout; use cat instead")
	}
	ls := lsCmd()
	if err := ls.Args(ls, []string{"aqt://id", "path"}); err == nil {
		t.Error("ls still accepts a second positional subpath")
	}
}

func subcommand(t *testing.T, root *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range root.Commands() {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("subcommand %q not found", name)
	return nil
}
