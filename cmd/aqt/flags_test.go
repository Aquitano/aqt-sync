package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGlobalFlagWiring pins the DESIGN §3 global flag surface: the persistent
// flags live on root, --version/-V print and exit 0, and the per-command --json
// duplicates were consolidated onto the global.
func TestGlobalFlagWiring(t *testing.T) {
	root := rootCmd()

	for _, name := range []string{"server", "profile", "json", "quiet", "verbose"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("root is missing persistent flag --%s", name)
		}
	}
	if root.PersistentFlags().Lookup("quiet").Shorthand != "q" {
		t.Errorf("--quiet shorthand = %q, want q", root.PersistentFlags().Lookup("quiet").Shorthand)
	}
	if root.PersistentFlags().Lookup("verbose").Shorthand != "v" {
		t.Errorf("--verbose shorthand = %q, want v", root.PersistentFlags().Lookup("verbose").Shorthand)
	}

	if root.Version == "" {
		t.Fatal("root.Version is unset; --version/-V would error")
	}
	vf := root.Flags().Lookup("version")
	if vf == nil {
		t.Fatal("root has no --version flag")
	}
	if vf.Shorthand != "V" {
		t.Errorf("--version shorthand = %q, want V", vf.Shorthand)
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
