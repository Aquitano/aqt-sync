// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/folderstate"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func (app *application) initCmd() *cobra.Command {
	var git, noGit bool
	cmd := &cobra.Command{
		Use:   "init [dir]",
		Short: "Mark a folder as tracked for sync",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if git && noGit {
				return errors.New("--git and --no-git are mutually exclusive")
			}
			var syncGit *bool
			if git || noGit {
				syncGit = &git
			}
			return app.runInit(dirArg(args), syncGit)
		},
	}
	cmd.Flags().BoolVar(&git, "git", false, "track the .git directory too, instead of asking")
	cmd.Flags().BoolVar(&noGit, "no-git", false, "leave .git ignored, instead of asking")
	markQuietSupported(cmd)
	return cmd
}

// runInit tracks dir. gitChoice decides whether a git repository inside it is
// synced too; nil asks (the interactive default), which is why --git/--no-git exist:
// a scripted or TUI-driven init has nobody to answer the prompt.
func (app *application) runInit(dir string, gitChoice *bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(abs, syncengine.ControlDir)); err == nil {
		return errors.New("already a tracked folder; to track it against a different resource, " +
			"account, or server — or to recover one whose remote resource was deleted — run " +
			"`aqt untrack` first (your files are left alone)")
	}
	cl, prof, err := app.authedClient()
	if err != nil {
		return err
	}
	mk, err := app.unlockMaster(prof)
	if err != nil {
		return err
	}
	defer mk.Wipe()

	// aqt ignores .git by default; offer to track it when this tree holds a repo.
	syncGit := false
	if repo, ok := firstGitRepo(abs); ok {
		if gitChoice != nil {
			syncGit = *gitChoice
		} else if syncGit, err = promptSyncGit(repo); err != nil {
			return err
		}
	}

	// Parse .aqtconfig before anything remote exists, so a broken config fails here
	// rather than on the first sync. Nothing in init consults its values.
	if _, err := syncengine.LoadConfig(abs); err != nil {
		return err
	}

	// Stage the local control state before touching the server: creating .aqt and
	// the starter ignore up front surfaces permission problems while there is still
	// nothing remote to orphan. Everything staged here is removed again if a later
	// step fails.
	if err := os.MkdirAll(filepath.Join(abs, syncengine.ControlDir), 0o700); err != nil {
		return err
	}
	wroteIgnore, err := writeStarterIgnore(abs, syncGit)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(abs, syncengine.ControlDir))
		return err
	}
	cleanupLocal := func() {
		_ = os.RemoveAll(filepath.Join(abs, syncengine.ControlDir))
		if wroteIgnore {
			_ = os.Remove(filepath.Join(abs, ".aqtignore"))
		}
	}

	// Register an empty private folder resource with an empty Merkle-DAG tree
	// root; the first `sync` fills it.
	ck, err := crypto.GenerateContentKey()
	if err != nil {
		cleanupLocal()
		return err
	}
	defer ck.Wipe()
	manifest := syncengine.Manifest{Version: syncengine.TreeManifestVersion}
	conv := crypto.DeriveConvergenceKey(mk)
	resp, err := app.createFolder(cl, conv, manifest, ck, mk, abs)
	conv.Wipe()
	if err != nil {
		cleanupLocal()
		return err
	}

	if err := commitInitState(abs, prof, resp, manifest); err != nil {
		// The resource was just created and nothing references it yet; deleting it
		// keeps a failed init side-effect-free instead of leaving an orphan the
		// user cannot see locally.
		cleanupLocal()
		if delErr := cl.DeleteResourceVersion(resp.ID, resp.Version); delErr != nil {
			//nolint:errorlint // secondary cleanup error must not reach exitCode
			return fmt.Errorf("%w (additionally, the just-created remote resource %s could not be removed: %v; `aqt rm %s` deletes it)", err, resp.ID, delErr, resp.ID)
		}
		return err
	}
	if app.quiet {
		fmt.Printf("aqt://%s\n", resp.ID)
		return nil
	}
	fmt.Printf("tracking %s\naqt://%s\n", abs, resp.ID)
	fmt.Fprintln(os.Stderr, "run `aqt sync` to push the current contents")
	return nil
}

// commitInitState writes the tracking pointer and empty base for a fresh init.
// Split out (as a var) so a test can fail the local commit and assert the remote
// resource is cleaned up.
var commitInitState = func(abs string, prof *identity.Profile, resp api.PutResourceResponse, manifest syncengine.Manifest) error {
	profileName, account, fingerprint := stateIdentity(prof)
	if err := folderstate.SaveState(abs, folderstate.State{
		ID: resp.ID, Server: prof.Server,
		Profile: profileName, Account: account, Fingerprint: fingerprint,
		RemoteVersion: resp.Version,
	}); err != nil {
		return err
	}
	return folderstate.SaveBase(abs, prof.Name, manifest)
}

// defaultIgnoreBody is the build-artifact and cache exclude set every starter
// .aqtignore carries. These are regenerable outputs that otherwise dominate a
// sync (a Next.js .next/ measured ~915 MB, ~90% of one payload) and, being the
// largest packs, are the flakiest to transfer. Everything here is overridable:
// delete a line, or re-include a path with a trailing `!rule`. The ambiguous
// output dirs (dist/, build/, out/, bin/) sometimes hold committed assets, so
// they are called out for the user to prune.
const defaultIgnoreBody = `
# JS/TS / web
node_modules/
.next/
.nuxt/
.svelte-kit/
.astro/
.turbo/
.parcel-cache/
.cache/
.vite/
coverage/
*.tsbuildinfo

# Rust
target/

# Java / JVM (Gradle/Maven)
.gradle/
*.class

# Python
__pycache__/
*.pyc
.venv/
venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/

# Build outputs (may hold committed assets; remove lines that do not apply)
dist/
build/
out/
bin/

# General
.DS_Store
Thumbs.db
*.log
`

const starterIgnore = `# aqt ignore patterns (gitignore syntax)
.git/
` + defaultIgnoreBody

// starterIgnoreWithGit re-includes .git for a user who chose to track their git
// history at init: aqt always ignores .git, and a leading ! overrides that.
const starterIgnoreWithGit = `# aqt ignore patterns (gitignore syntax)
# track the git repository (aqt ignores .git by default; ! re-includes it)
!.git/
` + defaultIgnoreBody

// writeStarterIgnore writes the starter .aqtignore, reporting whether it created
// the file so a failed init can remove exactly what it added.
func writeStarterIgnore(root string, syncGit bool) (created bool, err error) {
	path := filepath.Join(root, ".aqtignore")
	if _, err := os.Stat(path); err == nil {
		return false, nil // do not clobber an existing one
	}
	body := starterIgnore
	if syncGit {
		body = starterIgnoreWithGit
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// promptSyncGit asks whether to track the git repository at repo (relative to the
// tracked root, "." for the root). Declined by default — syncing a live .git
// captures its locks and loose objects, which most users do not want.
func promptSyncGit(repo string) (bool, error) {
	where := "this folder is a git repository"
	if repo != "." {
		where = fmt.Sprintf("this folder contains a git repository at %s", repo)
	}
	fmt.Fprintf(os.Stderr, "%s; aqt ignores .git by default.\n", where)
	return promptYesNo("Sync the .git directory too? [y/N]: ", false)
}
