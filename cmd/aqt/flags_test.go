// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Global output flags are inherited by commands; --version/-v prints the build version.
func TestGlobalFlagWiring(t *testing.T) {
	app := &application{ctx: context.Background()}

	root := app.rootCmd()

	for _, name := range []string{"server", "profile", "json", "quiet"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("root is missing persistent flag --%s", name)
		}
	}
	if root.PersistentFlags().Lookup("quiet").Shorthand != "q" {
		t.Errorf("--quiet shorthand = %q, want q", root.PersistentFlags().Lookup("quiet").Shorthand)
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
	app := &application{ctx: context.Background()}

	assertOutFlag := func(name string, cmd *cobra.Command) {
		t.Helper()
		out := cmd.Flags().Lookup("out")
		if out == nil || out.Shorthand != "o" {
			t.Errorf("%s --out shorthand = %v, want -o", name, out)
		}
	}
	assertOutFlag("pull", app.pullCmd())
	assertOutFlag("restore", app.restoreCmd())

	contacts := app.contactsCmd()
	rm, _, err := contacts.Find([]string{"remove"})
	if err != nil || rm.Name() != "rm" {
		t.Fatalf("contacts remove alias resolved to %v, err=%v; want rm", rm, err)
	}

	snapshot := app.snapshotCmd()
	subcommand(t, snapshot, "unanchor")
	prune := subcommand(t, snapshot, "prune")
	if prune.Flags().Lookup("before") == nil {
		t.Error("snapshot prune is missing --before")
	}
	create := subcommand(t, snapshot, "create")
	if err := create.Args(create, []string{".", "release"}); err != nil {
		t.Errorf("snapshot create rejected a positional label: %v", err)
	}

	ls := app.lsCmd()
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

// Pushing a directory must explain the folder workflow before attempting to read it.
func TestPushDirectoryPointsAtInitSync(t *testing.T) {
	app := &application{ctx: context.Background()}

	dir := t.TempDir()
	err := app.runPush(dir, pushOptions{})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("runPush(dir) = %v, want a directory explanation", err)
	}
	for _, want := range []string{"aqt init", "aqt sync"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

// Backticks in flag descriptions control Cobra's value-type display.
func TestPushHelpRendersNameFlagType(t *testing.T) {
	app := &application{ctx: context.Background()}

	usage := app.pushCmd().Flags().FlagUsages()
	if !strings.Contains(usage, "--name string") {
		t.Errorf("--name does not render as a string flag:\n%s", usage)
	}
}
