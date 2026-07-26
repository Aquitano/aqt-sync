package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/update"
)

// updateBaseURLEnv points the check at a static metadata origin instead of the
// GitHub CLI. Tests use it, and it is the switch for serving update metadata from
// a public origin once the repository is public.
const updateBaseURLEnv = "AQT_UPDATE_BASE_URL"

// updateCheckTimeout bounds the whole check. The metadata is a few kilobytes, so a
// check that has not finished by now is not going to.
const updateCheckTimeout = 30 * time.Second

// updateTrustRoots is the set of release-signing keys this build accepts. It is a
// variable so tests can drive the command with their own fixture key.
var updateTrustRoots = update.TrustRoots

func updateCmd() *cobra.Command {
	var prerelease bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Check whether a newer aqt release is published",
		Long: `Check whether a newer aqt release is published.

The check verifies a signed release manifest against the signing keys compiled
into this build before it trusts any of its contents, and reports what it found.
It is read-only: nothing here modifies the installed binary.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdateCheck(prerelease, flagJSON)
		},
	}
	// --check is accepted because reporting is the only supported mode today;
	// keeping the flag means scripts written now keep meaning "do not touch my
	// installation" when applying updates lands.
	cmd.Flags().Bool("check", false, "report only, never modify the installation (the only supported mode)")
	cmd.Flags().BoolVar(&prerelease, "prerelease", false, "check the beta channel, which includes prereleases")
	markJSONSupported(cmd)
	return cmd
}

func runUpdateCheck(prerelease, asJSON bool) error {
	ch := update.ChannelStable
	if prerelease {
		ch = update.ChannelBeta
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()

	res, err := update.Check(ctx, update.Options{
		Build:   update.Build{Version: version, Kind: buildKind},
		Channel: ch,
		Source:  updateSource(),
		Roots:   updateTrustRoots(),
	})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(res)
	}

	switch res.Status {
	case update.StatusUnsupported:
		fmt.Printf("aqt %s is a development build; automatic updates cover published releases only.\n", res.CurrentVersion)
		if !flagQuiet {
			fmt.Printf("Install a release from https://github.com/%s/releases, or keep building from source with `make build`.\n", update.DefaultRepo)
		}
	case update.StatusUpToDate:
		fmt.Printf("aqt %s is the latest %s release.\n", res.CurrentVersion, res.Channel)
	case update.StatusUpdateAvailable:
		fmt.Printf("update available: %s -> %s (%s)\n", res.CurrentVersion, res.AvailableVersion, res.Channel)
		if !flagQuiet {
			fmt.Printf("release: %s\n", res.ReleaseURL)
			if res.Artifact != nil {
				fmt.Printf("asset:   %s (%s)\n", res.Artifact.Name, humanBytes(res.Artifact.Size))
			}
			fmt.Println("\nInstalling updates is not supported yet; download the asset above and replace this binary.")
		}
	}
	return nil
}

// updateSource picks how release metadata is fetched. The repository is private,
// so release assets are only reachable with the user's own credentials: gh is the
// default. The signature is verified either way, so neither transport is trusted.
func updateSource() update.Source {
	if base := os.Getenv(updateBaseURLEnv); base != "" {
		return update.HTTPSource{BaseURL: base}
	}
	return update.GHSource{Repo: update.DefaultRepo}
}
