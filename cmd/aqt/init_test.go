// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteStarterIgnore(t *testing.T) {
	t.Run("default ignores git", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := writeStarterIgnore(dir, false); err != nil {
			t.Fatal(err)
		}
		body := readIgnore(t, dir)
		if !strings.Contains(body, "\n.git/\n") {
			t.Fatalf("starter ignore must list .git/, got:\n%s", body)
		}
		if strings.Contains(body, "!.git/") {
			t.Fatal("the default starter must not re-include .git")
		}
		for _, want := range []string{"node_modules/", ".next/", "target/", "__pycache__/", "dist/"} {
			if !strings.Contains(body, "\n"+want+"\n") {
				t.Fatalf("starter ignore must exclude %q by default, got:\n%s", want, body)
			}
		}
	})

	t.Run("syncGit re-includes git", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := writeStarterIgnore(dir, true); err != nil {
			t.Fatal(err)
		}
		body := readIgnore(t, dir)
		if !strings.Contains(body, "!.git/") {
			t.Fatalf("syncGit starter must contain !.git/, got:\n%s", body)
		}
	})

	t.Run("never clobbers an existing file", func(t *testing.T) {
		dir := t.TempDir()
		existing := "# mine\nbuild/\n"
		if err := os.WriteFile(filepath.Join(dir, ".aqtignore"), []byte(existing), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := writeStarterIgnore(dir, true); err != nil {
			t.Fatal(err)
		}
		if got := readIgnore(t, dir); got != existing {
			t.Fatalf("existing .aqtignore was overwritten: %q", got)
		}
	})
}

// Without a terminal (as in tests), promptYesNo returns the default without
// reading stdin, so init stays scriptable.
func TestPromptYesNoNonTerminalReturnsDefault(t *testing.T) {
	for _, def := range []bool{true, false} {
		got, err := promptYesNo("ignored? ", def)
		if err != nil {
			t.Fatal(err)
		}
		if got != def {
			t.Fatalf("non-terminal promptYesNo = %v, want default %v", got, def)
		}
	}
}

func readIgnore(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".aqtignore"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
