package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// passwordFlags binds the link-password flags. -P/--password takes the secret on the
// command line, where it lands in the process's argv: /proc/<pid>/cmdline is
// world-readable, so any local user can read it for as long as the command runs.
// --password-stdin keeps it out of the process table entirely, and is what the TUI
// uses. -P stays for scripts and backwards compatibility.
type passwordFlags struct {
	value     string
	fromStdin bool
}

func (p *passwordFlags) bind(cmd *cobra.Command, usage string) {
	f := cmd.Flags()
	f.StringVarP(&p.value, "password", "P", "", usage+" (appears in ps; prefer --password-stdin)")
	f.BoolVar(&p.fromStdin, "password-stdin", false, "read the password from stdin instead of the command line")
}

// resolve returns the password, reading stdin when --password-stdin is set. A single
// trailing newline is stripped so `echo hunter2 | aqt share x --password-stdin` works;
// anything else is taken literally, since a password may legitimately contain spaces.
func (p *passwordFlags) resolve() (string, error) {
	if !p.fromStdin {
		return p.value, nil
	}
	if p.value != "" {
		return "", errors.New("--password and --password-stdin are mutually exclusive")
	}
	// Reading a terminal here would block forever with no indication why; the flag is
	// for a pipe (`... | aqt share x --password-stdin`) or a parent process like the TUI.
	if interactiveStdin() {
		return "", errors.New("--password-stdin expects the password on stdin, but stdin is a terminal")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read password from stdin: %w", err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
