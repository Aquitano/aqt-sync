package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A local file error satisfies net.Error via its Timeout method; it must exit 1
// (generic), not 5 (retryable network), or cron retries a permanent failure forever.
func TestExitCodeLocalFileErrorIsNotNetwork(t *testing.T) {
	_, err := os.Open(filepath.Join(t.TempDir(), "missing"))
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("test setup: %T is not a PathError", err)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exitCode(missing-file error) = %d, want 1", got)
	}
	if got := exitCode(fmt.Errorf("push: %w", err)); got != 1 {
		t.Errorf("exitCode(wrapped missing-file error) = %d, want 1", got)
	}
}

// A typo'd subcommand must error as an unknown command, never upload a file that
// happens to share the typo's name.
func TestBarePushSugarRejectsBareWords(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	// A bare word that is not a file: unknown command.
	if err := runPushSugar("statsu"); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("runPushSugar(statsu) = %v, want unknown command", err)
	}

	// A bare word that IS a file: without a terminal to confirm on, still refuse.
	if err := os.WriteFile(filepath.Join(dir, "statsu"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runPushSugar("statsu")
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("runPushSugar(existing bare word, no tty) = %v, want unknown command", err)
	}
	if !strings.Contains(err.Error(), "aqt push") {
		t.Errorf("error %v does not point at `aqt push`", err)
	}
}

// Pushing a directory must explain the folder workflow instead of dying later with
// a raw read error (which, pre-fix, also exited 5 via the net.Error mismatch).
func TestPushDirectoryPointsAtInitSync(t *testing.T) {
	dir := t.TempDir()
	err := runPush(dir, pushOptions{})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("runPush(dir) = %v, want a directory explanation", err)
	}
	for _, want := range []string{"aqt init", "aqt sync"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

// Bare -P/--password prompts on a terminal; without one it must error rather than
// hang or silently take an empty password. docs/cli.md promises the prompt.
func TestPasswordFlagPromptsWithoutValue(t *testing.T) {
	cmd := pushCmd()
	f := cmd.Flags().Lookup("password")
	if f == nil {
		t.Fatal("push has no --password flag")
	}
	if f.NoOptDefVal == "" {
		t.Fatal("--password requires a value; bare -P cannot prompt")
	}

	pw := passwordFlags{value: f.NoOptDefVal}
	withStdin(t, "") // a pipe, not a terminal
	if _, err := pw.resolve(); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("resolve() with sentinel and no tty = %v, want a terminal error", err)
	}
}

func TestPasswordFlagHelpIsPrintable(t *testing.T) {
	cmd := pushCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Help(); err != nil {
		t.Fatal(err)
	}
	help := out.String()
	if strings.ContainsRune(help, '\x00') {
		t.Fatalf("push help contains a NUL byte:\n%q", help)
	}
	if strings.Contains(help, passwordPromptSentinel) {
		t.Fatalf("push help exposes the internal password sentinel:\n%s", help)
	}
	if !strings.Contains(help, `--password string[="prompt"]`) {
		t.Fatalf("push help does not describe the optional prompt value:\n%s", help)
	}
}

// push --help must render --name as a plain string flag: backticks in the usage
// string are cobra's value-type syntax and turned it into `--name aqt ls`.
func TestPushHelpRendersNameFlagType(t *testing.T) {
	usage := pushCmd().Flags().FlagUsages()
	if strings.Contains(usage, "--name aqt ls") {
		t.Errorf("--name renders its type as \"aqt ls\":\n%s", usage)
	}
	if !strings.Contains(usage, "--name string") {
		t.Errorf("--name does not render as a string flag:\n%s", usage)
	}
}
