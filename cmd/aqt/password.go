// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// passwordPromptSentinel marks `-P`/`--password` given without a value, so resolve
// can prompt for it. Keep it printable: pflag includes NoOptDefVal in some generated
// output, and a control byte there corrupts its internal help-column separator.
const passwordPromptSentinel = "__aqt_internal_password_prompt__"

// passwordFlags binds the link-password flags. -P/--password with an inline value
// takes the secret on the command line, where it lands in the process's argv:
// /proc/<pid>/cmdline is world-readable, so any local user can read it for as long
// as the command runs. Bare -P prompts for it instead (hidden, on a terminal), and
// --password-stdin keeps it out of the process table for pipes and parent processes
// like the TUI. Because the flag takes an optional value, an inline secret must be
// attached (-Psecret or --password=secret), not passed as a separate argument.
type passwordFlags struct {
	value     string
	fromStdin bool
}

func (p *passwordFlags) bind(cmd *cobra.Command, usage string) {
	f := cmd.Flags()
	f.StringVarP(&p.value, "password", "P", "", usage+" (bare -P prompts; -P<value> appears in ps, prefer --password-stdin)")
	f.Lookup("password").NoOptDefVal = passwordPromptSentinel
	f.BoolVar(&p.fromStdin, "password-stdin", false, "read the password from stdin instead of the command line")

	// pflag prints a string flag's NoOptDefVal in help. The parser needs the unique
	// sentinel above, but users should see the behavior it represents, not an
	// implementation token. Swap only while Cobra renders help or usage.
	help := cmd.HelpFunc()
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		withPasswordPromptHelpValue(c, func() { help(c, args) })
	})
	usageFunc := cmd.UsageFunc()
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		var err error
		withPasswordPromptHelpValue(c, func() { err = usageFunc(c) })
		return err
	})
}

func withPasswordPromptHelpValue(cmd *cobra.Command, render func()) {
	f := cmd.Flags().Lookup("password")
	if f == nil {
		render()
		return
	}
	noOpt := f.NoOptDefVal
	f.NoOptDefVal = "prompt"
	defer func() { f.NoOptDefVal = noOpt }()
	render()
}

// resolve returns the password, reading stdin when --password-stdin is set and
// prompting when the flag was given without a value. A single trailing newline is
// stripped so `echo hunter2 | aqt share x --password-stdin` works; anything else is
// taken literally, since a password may legitimately contain spaces.
func (p *passwordFlags) resolve() (string, error) {
	if p.fromStdin {
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
	if p.value == passwordPromptSentinel {
		return promptPassword()
	}
	return p.value, nil
}

// promptPassword reads the link password without echo. It insists on a terminal:
// unlike promptPassphrase there is no piped fallback, because a pipe should use
// --password-stdin explicitly rather than have a bare -P silently consume input
// meant for something else.
func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("--password given without a value, but stdin is not a terminal to prompt on; use --password-stdin (or --password=<value>)")
	}
	fmt.Fprint(os.Stderr, "Link password: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	return pw, nil
}
