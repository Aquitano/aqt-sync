// Command aqt is the zero-knowledge encrypted sync CLI.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/identity"
)

const defaultServer = "http://localhost:8080"

var (
	flagServer  string
	flagProfile string
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "aqt",
		Short:         "Zero-knowledge encrypted file & folder sync",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		// Bare `aqt <path>` is sugar for `aqt push <path>` (private default).
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return runPush(args[0], pushOptions{})
		},
	}
	root.PersistentFlags().StringVar(&flagServer, "server", "", "server URL override")
	root.PersistentFlags().StringVar(&flagProfile, "profile", "", "profile name")

	root.AddCommand(loginCmd(), whoamiCmd(), pushCmd(), pullCmd(), lsCmd())
	return root
}

// loadProfile loads the active profile and applies a --server override.
func loadProfile() (*identity.Profile, error) {
	p, err := identity.Load(flagProfile)
	if err != nil {
		return nil, err
	}
	if flagServer != "" {
		p.Server = flagServer
	}
	return p, nil
}

// loadProfileOptional returns the active profile, or nil if none is configured.
// Used by commands that can run without auth (e.g. pulling a public link).
func loadProfileOptional() *identity.Profile {
	p, err := loadProfile()
	if err != nil {
		return nil
	}
	return p
}

func authedClient() (*client.Client, *identity.Profile, error) {
	p, err := loadProfile()
	if err != nil {
		return nil, nil, err
	}
	return client.New(p.Server, p.Token), p, nil
}

// serverURL resolves a server for commands that may run without a profile (e.g.
// pulling a public link on a fresh machine).
func serverURL() string {
	if flagServer != "" {
		return flagServer
	}
	if p, err := identity.Load(flagProfile); err == nil && p.Server != "" {
		return p.Server
	}
	return defaultServer
}

// promptPassphrase reads a passphrase without echoing it on a real terminal.
// When stdin is not a terminal (pipe/CI), it reads a single line instead so the
// CLI stays scriptable.
func promptPassphrase(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, label)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	line, err := stdinReader().ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// sharedStdin is a single buffered reader so multiple piped prompts (e.g. the
// signup passphrase + confirmation) don't lose lines to per-call buffering.
var sharedStdin *bufio.Reader

func stdinReader() *bufio.Reader {
	if sharedStdin == nil {
		sharedStdin = bufio.NewReader(os.Stdin)
	}
	return sharedStdin
}

// copyToClipboard is best-effort: a failure (e.g. headless box) is reported but
// never fatal.
func copyToClipboard(s string) bool {
	return clipboard.WriteAll(s) == nil
}
