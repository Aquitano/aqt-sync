// Command aqt is the zero-knowledge encrypted sync CLI.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/update"
)

const defaultServer = "http://localhost:8080"

// version is reported by `aqt --version` / `-v`, overridable at build time via
// -ldflags "-X main.version=...". The default names no release on purpose: a
// hardcoded number goes stale the moment it is tagged, and claiming a version this
// build is not is worse than admitting it has none.
var version = "dev"

// buildKind records where this binary came from. The release workflow stamps
// "release" on a tagged build; anything else is a source build whose version
// string says nothing about which release it corresponds to, so `aqt update`
// reports it as unsupported rather than guessing. Overridable at build time via
// -ldflags "-X main.buildKind=release", so the value stays a plain string literal.
var buildKind = "dev"

// defaultSessionTTL bounds how long the unlocked master key stays cached after a
// passphrase prompt. `aqt login --ttl` overrides it; `aqt lock` clears it.
const defaultSessionTTL = 8 * time.Hour

// exitDeferred (EX_TEMPFAIL) marks a `watch --once` run that declined to sync
// because git stayed busy: not a failure, retry later. Distinct from 0 so cron
// can tell "synced" from "skipped".
const exitDeferred = 75

// errSessionRequired means the master key could not be unlocked: no cached
// session and no passphrase supplied (an empty entry, or a detached daemon with
// no terminal to prompt). Retrying without re-login cannot fix it.
var errSessionRequired = errors.New("no unlocked session and no passphrase provided; run `aqt login`")

var (
	flagServer   string
	flagProfile  string
	flagJSON     bool
	flagQuiet    bool
	flagProgress bool
)

func main() {
	root := rootCmd()
	root.SetArgs(rootArgs(root, os.Args))
	cmd, err := root.ExecuteC()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", explainError(err))
		os.Exit(exitCode(err))
	}
	// Only after the command succeeded and printed what it was asked for: the
	// update policy is off by default, and even when on it never affects this
	// command's output or status.
	maybeBackgroundUpdate(cmd)
}

// idLikeArg matches the shape of a server-minted resource or snapshot id that
// begins with a dash. Ids are base64url of 8 random bytes, so 11 characters from
// that alphabet; the leading dash is what cobra would otherwise parse as a flag
// cluster. Servers no longer mint these, but ids handed out before that stay valid
// forever, and no server-side change can reach them.
var idLikeArg = regexp.MustCompile(`^-[A-Za-z0-9_-]{10}$`)

// escapeLeadingDashIDs rewrites an otherwise-bare legacy dash-leading id into its
// aqt:// form, which the ref parser accepts and cobra does not treat as flags. Flag
// values must be identified first: profile names, labels, output paths, and similar
// strings may legitimately have exactly the same shape as an old id.
func escapeLeadingDashIDs(root *cobra.Command, args []string) []string {
	valueFlags := make(map[string]bool)
	knownShorthands := make(map[byte]bool)
	valueShorthands := make(map[byte]bool)
	var collect func(*cobra.Command)
	collect = func(cmd *cobra.Command) {
		for _, flags := range []*pflag.FlagSet{cmd.LocalNonPersistentFlags(), cmd.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				if len(flag.Shorthand) == 1 {
					knownShorthands[flag.Shorthand[0]] = true
				}
				if flag.NoOptDefVal != "" {
					return
				}
				valueFlags[flag.Name] = true
				if len(flag.Shorthand) == 1 {
					valueShorthands[flag.Shorthand[0]] = true
				}
			})
		}
		for _, child := range cmd.Commands() {
			collect(child)
		}
	}
	collect(root)

	out := make([]string, len(args))
	copy(out, args)
	wantValue := false
	for i, a := range out {
		if a == "--" {
			return out
		}
		if wantValue {
			wantValue = false
			continue
		}
		if strings.HasPrefix(a, "--") {
			name, _, attached := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			wantValue = !attached && valueFlags[name]
			continue
		}
		if len(a) >= 2 && a[0] == '-' {
			isFlag := true
			for j := 1; j < len(a); j++ {
				short := a[j]
				if !knownShorthands[short] {
					isFlag = false
					break
				}
				if valueShorthands[short] {
					// The first value-taking shorthand consumes the rest of the token,
					// or the next argument when it is the final shorthand. Attached short
					// values are inherently ambiguous with an old id and retain flag
					// semantics; the positional can still use -- or an aqt:// prefix.
					wantValue = j == len(a)-1
					break
				}
			}
			if isFlag {
				continue
			}
		}
		if idLikeArg.MatchString(a) {
			out[i] = "aqt://" + a
		}
	}
	return out
}

// explainError renders an error for the terminal, expanding the conditions whose
// recovery depends on facts only the binary knows. Everything else passes through.
func explainError(err error) error {
	var upgrade *client.UpgradeRequiredError
	if errors.As(err, &upgrade) {
		// Detection failing is not worth failing the message over: fall back to the
		// standalone route, whose action is `aqt update` — and that command explains
		// the package-manager routing itself when it runs.
		return errors.New(upgradeGuidance(upgrade, detectedInstall()))
	}
	return err
}

// detectedInstall classifies this binary for messaging. Detection failing is not
// worth failing a message over: fall back to the standalone route, whose action is
// `aqt update` — and that command explains the package-manager routing itself when
// it runs.
func detectedInstall() update.Install {
	install, err := update.DetectInstall(update.Build{Version: version, Kind: buildKind})
	if err != nil {
		return update.Install{Owner: update.OwnerStandalone}
	}
	return install
}

// upgradeAction names the command that upgrades *this* installation. Only a
// standalone copy is `aqt update`'s to replace; anything else was put there by a
// tool that keeps its own records, so the action routes to that tool rather than to
// a command which would refuse.
func upgradeAction(install update.Install) string {
	if install.Replaceable() {
		return "run `aqt update`"
	}
	if install.UpgradeCommand != "" {
		return fmt.Sprintf("upgrade with `%s` (%s installed this copy)", install.UpgradeCommand, install.Owner)
	}
	if why := install.Why(); why != "" {
		return why
	}
	return "run `aqt update`"
}

// upgradeGuidance states the 426 mismatch in terms of this build — its version and
// the capability it declares — and names the action that upgrades it.
func upgradeGuidance(e *client.UpgradeRequiredError, install update.Install) string {
	msg := fmt.Sprintf("aqt %s reads capability %d formats; that resource needs capability %d or newer — %s",
		version, e.Capability, e.MinClient, upgradeAction(install))
	// Detail is already sanitized by the client; quoting it keeps the server's voice
	// clearly separate from ours.
	if e.Detail != "" {
		msg += fmt.Sprintf(" (server said: %s)", e.Detail)
	}
	return msg
}

// exitCode maps an error to the documented CLI contract (docs/cli.md):
// 0 ok · 1 generic · 3 auth/locked · 4 sync conflict · 5 network · 6 upgrade
// required · 7 link gone (expired/exhausted). Scripts and cron (`--once`) use it to
// tell a retryable network blip from re-login from a conflict needing resolution from a
// client too old to read the remote from a link that has expired.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, identity.ErrNoProfile), errors.Is(err, errSessionRequired):
		return 3
	case errors.Is(err, errConflictsRemain), errors.Is(err, errSyncRace), errors.Is(err, client.ErrConflict),
		errors.Is(err, errRollback):
		return 4
	// Exhausted rate limiting is temporary by definition, so it maps to the
	// retryable network code: cron and `watch --once` must treat a throttled run as
	// "try again later", not as a permanent failure.
	case isNetworkError(err), errors.Is(err, client.ErrRateLimited):
		return 5
	case errors.Is(err, client.ErrUpgradeRequired):
		return 6
	case errors.Is(err, client.ErrGone):
		return 7
	case errors.Is(err, errWatchSkipped):
		return exitDeferred
	default:
		return 1
	}
}

func isNetworkError(err error) bool {
	// *fs.PathError has a Timeout method, so it satisfies net.Error; a local file
	// error (`aqt push missing-file`) must not map to the retryable network exit
	// code, or cron treats a permanent failure as a blip worth retrying.
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "aqt",
		Short:         "Zero-knowledge encrypted file & folder sync",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		// --json, -q and --progress are global flags, so a command that does not
		// implement one must say so rather than accept it and behave identically:
		// silently printing prose a script would try to parse, or promising a bar it
		// never draws.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if flagJSON && cmd.Annotations[jsonAnnotation] == "" {
				return fmt.Errorf("%s does not support --json", cmd.CommandPath())
			}
			if flagQuiet && cmd.Annotations[quietAnnotation] == "" {
				return fmt.Errorf("%s does not support -q/--quiet", cmd.CommandPath())
			}
			if flagProgress && cmd.Annotations[progressAnnotation] == "" {
				return fmt.Errorf("%s does not support --progress", cmd.CommandPath())
			}
			return nil
		},
		// Bare `aqt <path>` is sugar for `aqt push <path>` (private default), but only
		// when the argument unambiguously looks like a path: a typo'd subcommand
		// (`aqt statsu`) must never silently upload a file that happens to match it.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				if flagJSON {
					return errors.New("aqt does not support --json without a command or path")
				}
				return cmd.Help()
			}
			return runPushSugar(args[0])
		},
	}
	root.PersistentFlags().StringVar(&flagServer, "server", "", "server URL override")
	root.PersistentFlags().StringVar(&flagProfile, "profile", "", "profile name")
	root.PersistentFlags().BoolVar(&flagJSON, "json", false, "output as JSON")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "print only essential output")
	root.PersistentFlags().BoolVar(&flagProgress, "progress", false, "show a live transfer progress bar (on a terminal, for pull/sync/clone/watch/restore)")

	root.AddCommand(signupCmd(), loginCmd(), lockCmd(), logoutCmd(), whoamiCmd(), usageCmd(), passphraseCmd(), accountCmd(), devicesCmd(), pushCmd(), pullCmd(), catCmd(), lsCmd(), infoCmd(), findCmd(), shareCmd(), unshareCmd(), rmCmd(), renameCmd())
	root.AddCommand(initCmd(), untrackCmd(), statusCmd(), diffCmd(), syncCmd(), cloneCmd(), watchCmd(), agentCmd())
	root.AddCommand(snapshotCmd(), checkpointCmd(), restoreCmd())
	root.AddCommand(sharesCmd(), contactsCmd())
	root.AddCommand(repoCmd(), gitCmd())
	root.AddCommand(gitRemoteHelperCmd())
	root.AddCommand(tuiCmd(), updateCmd())

	// The bare-path push sugar runs push's own printer, so root carries push's flags.
	markJSONSupported(root)
	markQuietSupported(root)

	// root.Version makes cobra print the version when the flag is set; register the
	// flag explicitly so it carries the conventional -v shorthand.
	root.Version = version
	root.Flags().BoolP("version", "v", false, "version for aqt")
	return root
}

// These annotations mark a command as implementing one of the global output flags;
// the root PersistentPreRunE refuses a flag on any command without its annotation.
const (
	jsonAnnotation     = "supports-json"
	quietAnnotation    = "supports-quiet"
	progressAnnotation = "supports-progress"
)

// markJSONSupported annotates commands (and `aqt help <cmd>`-visible subcommands
// passed explicitly) as honoring --json.
func markJSONSupported(cmds ...*cobra.Command) { markSupported(jsonAnnotation, cmds...) }

// markQuietSupported annotates commands whose output -q/--quiet reduces to the one
// machine-readable line (a ref, an id, a path) or suppresses entirely.
func markQuietSupported(cmds ...*cobra.Command) { markSupported(quietAnnotation, cmds...) }

// markProgressSupported annotates commands that can draw a transfer bar.
func markProgressSupported(cmds ...*cobra.Command) { markSupported(progressAnnotation, cmds...) }

func markSupported(annotation string, cmds ...*cobra.Command) {
	for _, c := range cmds {
		if c.Annotations == nil {
			c.Annotations = map[string]string{}
		}
		c.Annotations[annotation] = "true"
	}
}

// confirmDestructive gates a destructive action: --yes skips the prompt, a terminal
// asks (defaulting to abort), and a non-interactive run without --yes aborts so a
// piped invocation can never destroy anything by accident.
func confirmDestructive(prompt string, assumeYes bool) error {
	if assumeYes {
		return nil
	}
	if err := requireConfirmable(assumeYes); err != nil {
		return err
	}
	ok, err := promptYesNo(prompt, false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted")
	}
	return nil
}

// errNotConfirmable means a destructive command needed a confirmation that the
// run could never answer (no terminal, no -y/--yes).
var errNotConfirmable = errors.New("confirmation required: pass -y/--yes to proceed non-interactively")

// requireConfirmable fails fast when a later destructive confirmation could never
// be answered, so commands that resolve refs before prompting abort before doing
// any auth or network work.
func requireConfirmable(assumeYes bool) error {
	if !assumeYes && !interactiveStdin() {
		return errNotConfirmable
	}
	return nil
}

// runPushSugar handles a bare `aqt <arg>`. An argument with a path separator is
// clearly a file and pushes directly; a bare word that exists as a regular file
// pushes only after an interactive confirmation; anything else is an unknown
// command. This keeps the sugar while closing the typo'd-command upload hole.
func runPushSugar(arg string) error {
	if strings.ContainsRune(arg, os.PathSeparator) || strings.ContainsRune(arg, '/') {
		return runPush(arg, pushOptions{})
	}
	if info, err := os.Stat(arg); err == nil && info.Mode().IsRegular() {
		if !interactiveStdin() {
			return fmt.Errorf("unknown command %q for \"aqt\"; to upload the file %q, run `aqt push %s`", arg, arg, arg)
		}
		ok, err := promptYesNo(fmt.Sprintf("Upload the file %q? [y/N] ", arg), false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted")
		}
		return runPush(arg, pushOptions{})
	}
	return fmt.Errorf("unknown command %q for \"aqt\"; run `aqt --help` for the command list", arg)
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
	c, err := client.New(p.Server, p.Token)
	if err != nil {
		return nil, nil, err
	}
	return c, p, nil
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

// linkServer resolves which server to talk to for a ref that may carry its own
// host (a share URL), and whether the target is the user's own server. Server
// precedence: explicit --server > host embedded in the ref > profile server >
// default. ownServer reports whether the account token may be attached: only when
// the operator chose the server explicitly (--server) or the resolved host matches
// the profile's server. A foreign host from a share link is never the own server.
func linkServer(origin string, prof *identity.Profile) (server string, ownServer bool) {
	switch {
	case flagServer != "":
		return flagServer, true
	case origin != "":
		return origin, prof != nil && sameServer(origin, prof.Server)
	case prof != nil && prof.Server != "":
		return prof.Server, true
	default:
		return defaultServer, true
	}
}

// newLinkClient builds a client for a possibly self-contained ref. The account
// token is attached only when talking to the user's own server; a public link
// decrypts from its #key fragment and public resources need no auth, so dropping
// the token for a foreign host loses nothing for the intended flow while a crafted
// link cannot exfiltrate the device credential to an attacker host. client.New's
// loopback/HTTPS guard still applies to the resolved host as defense in depth.
func newLinkClient(origin string, prof *identity.Profile) (*client.Client, error) {
	server, own := linkServer(origin, prof)
	token := ""
	if own && prof != nil {
		token = prof.Token
	}
	return client.New(server, token)
}

// sameServer compares two server URLs ignoring a trailing slash. A mismatch only
// drops the token (a public fetch still works), so exact host matching is the safe
// default: over-strict harmlessly withholds the token, over-loose risks leaking it.
func sameServer(a, b string) bool {
	return b != "" && strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
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

// promptLine reads one echoed line (e.g. an email) from the shared stdin reader.
// All interactive input goes through this single reader so a later prompt never
// loses bytes a different reader buffered ahead.
func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := stdinReader().ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// interactiveStdin reports whether stdin is a terminal, so prompts that must not
// block a scripted run (e.g. the first-run "create account?" confirm) can be skipped.
func interactiveStdin() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// promptYesNo asks a yes/no question and returns def when the answer is empty.
// Without a terminal (pipe/CI) it returns def without reading, so a scripted run
// takes the default instead of blocking — and never consumes a line a later
// prompt (e.g. the passphrase) is waiting on.
func promptYesNo(label string, def bool) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def, nil
	}
	line, err := promptLine(label)
	if err != nil {
		return def, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return def, nil
	}
}

// sharedStdin is a single buffered reader so multiple prompts (the email, plus
// the signup passphrase + confirmation) don't lose lines to per-call buffering.
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

// unlockMaster returns the master key from the session cache, or prompts for the
// passphrase (refusing an empty one), derives the key, and caches it.
func unlockMaster(prof *identity.Profile) (crypto.MasterKey, error) {
	if mk, ok := identity.LoadSession(prof.Name); ok {
		return mk, nil
	}
	pass, err := promptPassphrase("Passphrase: ")
	if err != nil {
		return crypto.MasterKey{}, err
	}
	if pass == "" {
		return crypto.MasterKey{}, errSessionRequired
	}
	mk, err := prof.Unlock(pass)
	if err != nil {
		return crypto.MasterKey{}, err
	}
	if err := identity.SaveSession(prof.Name, mk, sessionTTL(prof)); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not cache session:", err)
	}
	return mk, nil
}

func sessionTTL(prof *identity.Profile) time.Duration {
	if prof != nil && prof.SessionTTLSet {
		return time.Duration(prof.SessionTTLSeconds) * time.Second
	}
	return defaultSessionTTL
}
