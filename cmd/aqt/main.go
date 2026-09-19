// SPDX-License-Identifier: AGPL-3.0-or-later

// Command aqt is the zero-knowledge encrypted sync CLI.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/aquitano/aqt-sync/internal/client"
	"github.com/aquitano/aqt-sync/internal/cliutil"
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

// application owns one command invocation's flags and cancellation context.
// Commands and the work they start share this instance, never process-wide flags.
type application struct {
	server   string
	profile  string
	json     bool
	quiet    bool
	progress bool
	ctx      context.Context
}

// childArgs passes the current server and profile to a child aqt command.
func (app *application) childArgs(sub []string) []string {
	args := append([]string(nil), sub...)
	if app.server != "" {
		args = append(args, "--server", app.server)
	}
	if app.profile != "" {
		args = append(args, "--profile", app.profile)
	}
	return args
}

func main() { os.Exit(run()) }

// run holds main's body so the signal-handler restore in its defer actually runs;
// os.Exit skips deferred calls.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := &application{ctx: ctx}
	go func() {
		// After the first signal starts a graceful abort, restore default handling
		// so a second ^C kills a process that is wedged in cleanup.
		<-ctx.Done()
		stop()
	}()

	root := app.rootCmd()
	root.SetArgs(rootArgs(os.Args))
	cmd, err := root.ExecuteC()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", explainError(err))
		return exitCode(err)
	}
	// Only after the command succeeded and printed what it was asked for: the
	// update policy is off by default, and even when on it never affects this
	// command's output or status.
	app.maybeBackgroundUpdate(cmd)
	return 0
}

// explainError renders an error for the terminal, expanding the conditions whose
// recovery depends on facts only the binary knows. Everything else passes through.
func explainError(err error) error {
	var upgrade *client.UpgradeRequiredError
	if errors.As(err, &upgrade) {
		return errors.New(upgradeGuidance(upgrade, detectedInstall()))
	}
	// A ^C mid-transfer otherwise prints transport plumbing ("request PUT
	// /v1/packs/…: context canceled") for something the user did on purpose.
	if errors.Is(err, context.Canceled) {
		return errors.New("interrupted")
	}
	return err
}

// detectedInstall classifies this binary for messaging. Detection failing is not
// worth failing a message over: fall back to the standalone route, whose action is
// `aqt update`.
func detectedInstall() update.Install {
	install, err := update.DetectInstall(update.Build{Version: version, Kind: buildKind})
	if err != nil {
		return update.Install{Owner: update.OwnerStandalone}
	}
	return install
}

// upgradeAction names the command that upgrades this installation.
func upgradeAction(install update.Install) string {
	if install.Replaceable() {
		return "run `aqt update`"
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
// required · 7 link gone (expired/exhausted) · 130 interrupted. Scripts and cron
// (`--once`) use it to tell a retryable network blip from re-login from a conflict
// needing resolution from a client too old to read the remote from a link that has
// expired.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	// Checked before the network case: a canceled request surfaces as a *url.Error
	// wrapping context.Canceled, which would otherwise read as a retryable blip and
	// make cron re-run a command the user deliberately killed.
	case errors.Is(err, context.Canceled):
		return 130
	case errors.Is(err, identity.ErrNoProfile), errors.Is(err, errSessionRequired):
		return 3
	case errors.Is(err, errConflictsRemain), errors.Is(err, errSyncRace), errors.Is(err, client.ErrConflict),
		errors.Is(err, errRollback):
		return 4
	// Exhausted rate limiting is temporary by definition, so it maps to the
	// retryable network code: cron and `watch --once` must treat a throttled run as
	// "try again later", not as a permanent failure. A stalled transfer is the same
	// family — a link that wedged, worth retrying — not a generic failure.
	case isNetworkError(err), errors.Is(err, client.ErrRateLimited), errors.Is(err, client.ErrStalled):
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

func (app *application) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "aqt",
		Short:         "Zero-knowledge encrypted file & folder sync",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		// --json, -q and --progress are global flags, so a command that does not
		// implement one must say so rather than accept it and behave identically:
		// silently printing prose a script would try to parse, or promising a bar it
		// never draws.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if app.json && cmd.Annotations[jsonAnnotation] == "" {
				return fmt.Errorf("%s does not support --json", cmd.CommandPath())
			}
			if app.quiet && cmd.Annotations[quietAnnotation] == "" {
				return fmt.Errorf("%s does not support -q/--quiet", cmd.CommandPath())
			}
			if app.progress && cmd.Annotations[progressAnnotation] == "" {
				return fmt.Errorf("%s does not support --progress", cmd.CommandPath())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	root.PersistentFlags().StringVar(&app.server, "server", "", "server URL override")
	root.PersistentFlags().StringVar(&app.profile, "profile", "", "profile name")
	root.PersistentFlags().BoolVar(&app.json, "json", false, "output as JSON")
	root.PersistentFlags().BoolVarP(&app.quiet, "quiet", "q", false, "print only essential output")
	root.PersistentFlags().BoolVar(&app.progress, "progress", false, "show a live transfer progress bar (on a terminal, for pull/sync/clone/watch/restore)")

	root.AddCommand(app.signupCmd(), app.loginCmd(), app.lockCmd(), app.logoutCmd(), app.whoamiCmd(), app.usageCmd(), app.pruneCmd(), app.passphraseCmd(), app.accountCmd(), app.devicesCmd(), app.pushCmd(), app.pullCmd(), app.catCmd(), app.lsCmd(), app.infoCmd(), app.findCmd(), app.shareCmd(), app.unshareCmd(), app.rmCmd(), app.renameCmd())
	root.AddCommand(app.initCmd(), app.untrackCmd(), app.statusCmd(), app.diffCmd(), app.syncCmd(), app.cloneCmd(), app.watchCmd(), app.agentCmd())
	root.AddCommand(app.snapshotCmd(), app.checkpointCmd(), app.restoreCmd())
	root.AddCommand(app.sharesCmd(), app.contactsCmd())
	root.AddCommand(app.repoCmd(), app.gitCmd())
	root.AddCommand(app.gitRemoteHelperCmd())
	root.AddCommand(app.tuiCmd(), app.updateCmd())

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

// confirmDestructive gates a destructive action. The prompt carries its own [y/N]
// hint and is answered on the stdin reader every other aqt prompt shares.
func confirmDestructive(prompt string, assumeYes bool) error {
	return cliutil.Confirm(prompt, assumeYes, interactiveStdin(), func(p string) (bool, error) {
		return promptYesNo(p, false)
	})
}

// requireConfirmable fails fast when a later destructive confirmation could never
// be answered, so commands that resolve refs before prompting abort before doing
// any auth or network work.
func requireConfirmable(assumeYes bool) error {
	if !assumeYes && !interactiveStdin() {
		return cliutil.ErrNotConfirmable
	}
	return nil
}

// loadProfile loads the active profile and applies a --server override.
func (app *application) loadProfile() (*identity.Profile, error) {
	p, err := identity.Load(app.profile)
	if err != nil {
		return nil, err
	}
	if app.server != "" {
		p.Server = app.server
	}
	return p, nil
}

// loadProfileOptional returns the active profile, or nil if none is configured.
// Used by commands that can run without auth (e.g. pulling a public link).
func (app *application) loadProfileOptional() *identity.Profile {
	p, err := app.loadProfile()
	if err != nil {
		return nil
	}
	return p
}

// newBoundClient is client.New bound to the process's root signal context, so a
// ^C reaches every request the client sends. All CLI client construction goes
// through here.
func (app *application) newBoundClient(server, token string) (*client.Client, error) {
	c, err := client.New(server, token)
	if err != nil {
		return nil, err
	}
	return c.WithContext(app.ctx), nil
}

func (app *application) authedClient() (*client.Client, *identity.Profile, error) {
	p, err := app.loadProfile()
	if err != nil {
		return nil, nil, err
	}
	c, err := app.newBoundClient(p.Server, p.Token)
	if err != nil {
		return nil, nil, err
	}
	return c, p, nil
}

// serverURL resolves a server for commands that may run without a profile (e.g.
// pulling a public link on a fresh machine).
func (app *application) serverURL() string {
	if app.server != "" {
		return app.server
	}
	if p, err := identity.Load(app.profile); err == nil && p.Server != "" {
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
func (app *application) linkServer(origin string, prof *identity.Profile) (server string, ownServer bool) {
	switch {
	case app.server != "":
		return app.server, true
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
func (app *application) newLinkClient(origin string, prof *identity.Profile) (*client.Client, error) {
	server, own := app.linkServer(origin, prof)
	token := ""
	if own && prof != nil {
		token = prof.Token
	}
	return app.newBoundClient(server, token)
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
func (app *application) promptPassphrase(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, label)
		state, err := term.GetState(fd)
		if err != nil {
			return "", err
		}
		// term.ReadPassword blocks in a read no context can interrupt (Go's
		// signal handlers restart syscalls), so a ^C at the prompt would look
		// hung until a second one killed the process with echo still off. Read
		// on the side and, on cancel, restore the terminal ourselves; the reader
		// goroutine stays blocked but the process is about to exit 130.
		type read struct {
			b   []byte
			err error
		}
		ch := make(chan read, 1)
		go func() {
			b, err := term.ReadPassword(fd)
			ch <- read{b, err}
		}()
		select {
		case r := <-ch:
			fmt.Fprintln(os.Stderr)
			if r.err != nil {
				return "", r.err
			}
			return strings.TrimRight(string(r.b), "\r\n"), nil
		case <-app.ctx.Done():
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr)
			return "", context.Canceled
		}
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
func (app *application) unlockMaster(prof *identity.Profile) (crypto.MasterKey, error) {
	if mk, ok := identity.LoadSession(prof.Name); ok {
		return mk, nil
	}
	pass, err := app.promptPassphrase("Passphrase: ")
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

// sessionTTL is the cache lifetime the profile recorded at signup/login, where zero
// means cache until lock or logout. Without a profile there is nothing recorded, so
// the flag default stands in.
func sessionTTL(prof *identity.Profile) time.Duration {
	if prof == nil {
		return defaultSessionTTL
	}
	return time.Duration(prof.SessionTTLSeconds) * time.Second
}
