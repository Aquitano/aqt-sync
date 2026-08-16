// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/cliutil"
	"github.com/aquitano/aqt-sync/internal/update"
)

// updateBaseURLEnv points the check at a static metadata origin instead of the
// GitHub release assets. Tests use it, and it is how a mirror or a self-hoster
// serves update metadata from their own origin.
const updateBaseURLEnv = "AQT_UPDATE_BASE_URL"

// updateCheckTimeout bounds the metadata check. The metadata is a few kilobytes,
// so a check that has not finished by now is not going to.
const updateCheckTimeout = 30 * time.Second

// updateApplyTimeout bounds one download-and-install. Generous, because it covers
// fetching tens of megabytes over whatever connection the user has.
const updateApplyTimeout = 15 * time.Minute

// updateTrustRoots is the set of release-signing keys this build accepts. It is a
// variable so tests can drive the command with their own fixture key.
var updateTrustRoots = update.TrustRoots

// updateStore locates the persisted policy and the watch-agent registry. A
// variable so tests never touch the real user config directory.
var updateStore = update.DefaultStore

type updateOptions struct {
	checkOnly      bool
	prerelease     bool
	assumeYes      bool
	acceptRollback bool
	asJSON         bool
}

func updateCmd() *cobra.Command {
	var opts updateOptions
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check for and install a newer aqt release",
		Long: `Check for and install a newer aqt release.

The check verifies a signed release manifest against the signing keys compiled
into this build before it trusts any of its contents. Installing replaces only a
published release binary. A build from source reports how to rebuild instead and
is never overwritten.

The previous binary is kept until the new one has run and reported the version the
manifest promised; every failure puts it back.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.asJSON = flagJSON
			return runUpdate(opts)
		},
	}
	cmd.Flags().BoolVar(&opts.checkOnly, "check", false, "report what is available without installing anything")
	cmd.Flags().BoolVar(&opts.prerelease, "prerelease", false, "use the beta channel, which includes prereleases")
	cmd.Flags().BoolVarP(&opts.assumeYes, "yes", "y", false, "install without asking for confirmation")
	cmd.Flags().BoolVar(&opts.acceptRollback, "accept-rollback", false, "accept a release older than the newest one this machine has authenticated (after an upstream retraction)")
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	cmd.AddCommand(updatePolicyCmd())
	return cmd
}

// updateReport is the machine-readable result of `aqt update`. It embeds the
// check result rather than replacing it, so `--check --json` keeps emitting
// exactly the fields it emitted before.
type updateReport struct {
	update.Result
	Installed bool   `json:"installed"`
	Owner     string `json:"owner,omitempty"`
}

func runUpdate(opts updateOptions) error {
	ch := update.ChannelStable
	if opts.prerelease {
		ch = update.ChannelBeta
	}
	// The freshness floor lives in the same state file as the policy. A store that
	// cannot be read fails open (no floor): the ceiling is replay hardening on top
	// of signature verification, and a broken config dir must not block updating.
	// The load error is deliberately dropped for the floor read only — all writes
	// below go through the Store helpers, which re-read and skip the save when
	// the file is unreadable, so a transient read failure never persists defaults.
	store, storeErr := updateStore()
	var st update.State
	if storeErr == nil {
		st, _ = store.Load()
	}
	floor := st.Ceiling(ch)
	if opts.acceptRollback {
		floor = ""
	}
	ctx, cancel := context.WithTimeout(rootCtx, updateCheckTimeout)
	res, err := update.Check(ctx, update.Options{
		Build:   update.Build{Version: version, Kind: buildKind},
		Channel: ch,
		Source:  updateSource(),
		Roots:   updateTrustRoots(),
		Floor:   floor,
	})
	cancel()
	if errors.Is(err, update.ErrStaleManifest) {
		return fmt.Errorf("%w; if the release was genuinely retracted upstream, re-run with --accept-rollback", err)
	}
	if err != nil {
		return err
	}
	// Only a fully authenticated manifest reaches this point with a version.
	// Raising is always safe (it never lowers), so it happens up front; the
	// --accept-rollback lowering is deferred to the moment the older release is
	// actually accepted — installed, or confirmed as the version already running.
	// A declined prompt, a --check, or a non-replaceable install therefore
	// leaves the old ceiling standing.
	if storeErr == nil && res.AvailableVersion != "" {
		_ = store.RaiseCeiling(ch, res.AvailableVersion)
		// A beta check that lands on a stable release authenticated a stable
		// version; record it for stable checks too, or a prerelease-track user
		// would never establish the ceiling the stable-only background path
		// consults.
		if update.Channel(res.Channel) == update.ChannelStable && ch != update.ChannelStable {
			_ = store.RaiseCeiling(update.ChannelStable, res.AvailableVersion)
		}
	}
	acceptCeiling := func() {
		if storeErr == nil && opts.acceptRollback && res.AvailableVersion != "" {
			_ = store.ResetCeiling(ch, res.AvailableVersion)
		}
	}

	report := updateReport{Result: res}
	if res.Status != update.StatusUpdateAvailable {
		// Up to date: the served release is the one already running, so accepting
		// it cannot move below the running build.
		acceptCeiling()
		if opts.asJSON {
			return printJSON(report)
		}
		printCheckResult(res)
		return nil
	}

	in, err := update.DetectInstall(update.Build{Version: version, Kind: buildKind})
	if err != nil {
		return err
	}
	report.Owner = string(in.Owner)

	if opts.checkOnly {
		if opts.asJSON {
			return printJSON(report)
		}
		printAvailable(res)
		if !in.Replaceable() && !flagQuiet {
			fmt.Printf("note:    %s\n", in.Why())
		}
		return nil
	}

	// A source build is reported, never replaced: its checkout is the source of
	// truth and its version does not identify a published artifact safely.
	if !in.Replaceable() {
		return fmt.Errorf("%s -> %s is available, but %s", res.CurrentVersion, res.AvailableVersion, in.Why())
	}
	if res.Artifact == nil {
		return fmt.Errorf("the release has no build for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	if !opts.asJSON {
		printAvailable(res)
	}
	prompt := fmt.Sprintf("Replace %s with %s? [y/N] ", in.Path, res.AvailableVersion)
	if err := confirmDestructive(prompt, opts.assumeYes); err != nil {
		return err
	}

	applied, err := applyUpdate(rootCtx, in, res)
	if err != nil {
		return err
	}
	// The older release is installed and verified — now the acceptance is real.
	acceptCeiling()
	report.Installed = true
	if opts.asJSON {
		return printJSON(report)
	}
	fmt.Printf("installed %s -> %s\n", applied.FromVersion, applied.ToVersion)
	if applied.RollbackPath != "" && !flagQuiet {
		fmt.Println("the previous binary is still open by this process; the next update that installs removes it")
	}
	if link, stale := staleHelperLink(in); stale && !flagQuiet {
		fmt.Printf("%s still points at the previous binary; run `aqt git setup` to relink it\n", link)
	}
	return nil
}

// applyUpdate performs the replacement described by an already-verified result.
func applyUpdate(ctx context.Context, in update.Install, res update.Result) (update.ApplyResult, error) {
	ctx, cancel := context.WithTimeout(ctx, updateApplyTimeout)
	defer cancel()

	applied, err := update.Apply(ctx, update.ApplyOptions{
		Install:  in,
		Version:  res.AvailableVersion,
		Artifact: *res.Artifact,
		Source:   updateArtifactSource(),
	})
	if err != nil {
		return applied, err
	}
	applied.FromVersion = res.CurrentVersion
	return applied, nil
}

func printCheckResult(res update.Result) {
	switch res.Status {
	case update.StatusUnsupported:
		fmt.Printf("aqt %s is a development build; automatic updates cover published releases only.\n", res.CurrentVersion)
		if !flagQuiet {
			fmt.Printf("Install a release from https://github.com/%s/releases, or keep building from source with `make build`.\n", update.DefaultRepo)
		}
	case update.StatusUpToDate:
		fmt.Printf("aqt %s is the latest %s release.\n", res.CurrentVersion, res.Channel)
	}
}

func printAvailable(res update.Result) {
	fmt.Printf("update available: %s -> %s (%s)\n", res.CurrentVersion, res.AvailableVersion, res.Channel)
	if flagQuiet {
		return
	}
	fmt.Printf("release: %s\n", res.ReleaseURL)
	if res.Artifact != nil {
		fmt.Printf("asset:   %s (%s)\n", res.Artifact.Name, cliutil.HumanBytes(res.Artifact.Size))
	}
}

// updateSource fetches public GitHub release assets over HTTPS. Tests and
// self-hosted release origins can override that endpoint explicitly.
func updateSource() update.ReleaseSource {
	if base := os.Getenv(updateBaseURLEnv); base != "" {
		return update.HTTPSource{BaseURL: base}
	}
	return update.GHWebSource{Repo: update.DefaultRepo}
}

// updateArtifactSource fetches the archive itself, over the same transports as the
// metadata. Its contents are checked against the signed size and digest, so this is
// a delivery mechanism and not a trust boundary. A variable because artifact URLs
// are pinned to github.com, which is the one thing a test cannot serve.
var updateArtifactSource = func() update.ArtifactSource {
	return updateSource()
}

func updatePolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy [off|notify|auto]",
		Short: "Show or set what ordinary commands do about updates",
		Long: `Show or set what ordinary commands do about updates.

  off     never check outside an explicit ` + "`aqt update`" + ` (the default)
  notify  check at most once a day and print one line when a release is available
  auto    additionally install a stable release once nothing is using the binary

Background checks run only after a command that succeeded on a terminal. They are
skipped for --json, --quiet, scripts, and watch agents, and a failed check never
changes the exit status of the command that triggered it.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := updateStore()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				st, err := store.Load()
				if err != nil {
					return err
				}
				if flagJSON {
					return printJSON(st)
				}
				fmt.Println(st.Policy)
				return nil
			}
			p, err := update.ParsePolicy(args[0])
			if err != nil {
				return err
			}
			if err := store.SetPolicy(p); err != nil {
				return err
			}
			if !flagQuiet {
				fmt.Printf("update policy: %s\n", p)
			}
			return nil
		},
	}
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}
