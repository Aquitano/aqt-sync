// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aquitano/aqt-sync/internal/update"
)

// helperName is the program Git execs to resolve an aqt:: URL. aqt is a
// multi-call binary: a link of this name pointing at it is the whole integration,
// so there is no second executable that can fall out of step with the client.
const helperName = "git-remote-aqt"

// multiCallArgs reports the arguments an invocation made under the helper name
// stands for: the hidden `git-remote-helper` subcommand followed by whatever Git
// passed. The name must match exactly, never as a prefix, so renaming the binary
// cannot change what it runs.
func multiCallArgs(argv []string) ([]string, bool) {
	if len(argv) == 0 || !isHelperName(filepath.Base(argv[0])) {
		return nil, false
	}
	return append([]string{"git-remote-helper"}, argv[1:]...), true
}

// rootArgs is the command line the root command runs. Git's arguments belong to the
// remote-helper protocol and reach it verbatim; the legacy dash-id rewrite applies
// only to what a user typed, where a dash-leading id cannot be told from a flag.
func rootArgs(root *cobra.Command, argv []string) []string {
	if args, ok := multiCallArgs(argv); ok {
		return args
	}
	return escapeLeadingDashIDs(root, argv[1:])
}

func isHelperName(base string) bool {
	if runtime.GOOS != "windows" {
		return base == helperName
	}
	// Windows resolves PATH entries case-insensitively and through PATHEXT, so both
	// spellings reach the same file.
	return strings.EqualFold(base, helperName) || strings.EqualFold(base, helperName+".exe")
}

// helperLinkName is the file name Git looks for. Windows PATH lookup considers
// only PATHEXT suffixes, so an extensionless link there is invisible to it.
func helperLinkName() string {
	if runtime.GOOS == "windows" {
		return helperName + ".exe"
	}
	return helperName
}

func gitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "git", Short: "Wire Git up to aqt:: remotes", Args: cobra.NoArgs}
	cmd.AddCommand(gitSetupCmd())
	return cmd
}

func gitSetupCmd() *cobra.Command {
	var dir string
	var yes bool
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install the git-remote-aqt link so Git can resolve aqt:: URLs",
		Long: `Install the git-remote-aqt link so Git can resolve aqt:: URLs.

Git discovers a remote helper by exec'ing a program named git-remote-<transport>,
and aqt answers to that name itself, so the link is the entire integration: one
binary, nothing to upgrade separately. The link is created beside the running
binary unless --dir says otherwise, and an install owned by Homebrew, WinGet, or
Scoop is left alone because its own package provides the link.

Re-running this is safe; it reports a link that is already correct and changes
nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGitSetup(dir, yes)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "directory to create the link in (default: beside this binary)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "replace an existing git-remote-aqt without asking")
	markJSONSupported(cmd)
	markQuietSupported(cmd)
	return cmd
}

// gitSetupReport is the machine-readable result of `aqt git setup`. Method is
// empty when the link was already correct.
type gitSetupReport struct {
	Link    string `json:"link"`
	Target  string `json:"target"`
	Method  string `json:"method,omitempty"`
	Created bool   `json:"created"`
}

func runGitSetup(dir string, assumeYes bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating the running executable: %w", err)
	}
	in, err := update.DetectInstall(update.Build{Version: version, Kind: buildKind})
	if err != nil {
		return err
	}
	dir, err = helperDir(dir, exe, in)
	if err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	link := filepath.Join(dir, helperLinkName())
	report := gitSetupReport{Link: link, Target: exe}

	if samePath(link, exe) {
		if !flagJSON {
			fmt.Printf("%s already points at this binary\n", link)
		}
	} else {
		if _, err := os.Lstat(link); err == nil {
			// Anything else under this name is either a pre-multi-call helper binary or a
			// link to a different aqt, and both mean Git runs something other than this
			// client. Replacing it is the point of the command, so only confirm it.
			if err := confirmDestructive(fmt.Sprintf("Replace %s? [y/N] ", link), assumeYes); err != nil {
				return err
			}
			if err := os.Remove(link); err != nil {
				return err
			}
		}
		method, err := linkHelper(exe, link)
		if err != nil {
			return fmt.Errorf("creating %s: %w", link, err)
		}
		report.Method, report.Created = method, true
		if !flagJSON {
			fmt.Printf("installed %s (%s)\n", link, method)
			if method != "symlink" && !flagQuiet {
				fmt.Printf("note: a %s does not follow `aqt update`; re-run `aqt git setup` after upgrading\n", method)
			}
		}
	}

	// A link Git cannot reach is the failure this command exists to prevent, so the
	// warning is worth emitting even when the link was already correct or the caller
	// asked for JSON; it goes to stderr and leaves the report intact.
	warnHelperUnreachable(link)
	if flagJSON {
		return printJSON(report)
	}
	return nil
}

// helperDir resolves where the link goes. A package manager records every file it
// installs, so a sibling dropped into its tree leaves it describing a directory it
// no longer matches; its own packaging is what should create the link. --dir is the
// way out of that, but not a way back into the same directory.
func helperDir(dir, exe string, in update.Install) (string, error) {
	packageOwned := in.Owner != update.OwnerStandalone && in.Owner != update.OwnerSource
	if dir == "" {
		if packageOwned {
			return "", packageOwnedDirErr(in, "pass --dir to create one in a directory you own")
		}
		return filepath.Dir(exe), nil
	}
	if packageOwned && samePath(dir, in.Dir) {
		return "", packageOwnedDirErr(in, "name a directory you own instead")
	}
	return dir, nil
}

func packageOwnedDirErr(in update.Install, hint string) error {
	return fmt.Errorf("%s owns %s and provides the %s link in its own package; %s", in.Owner, in.Dir, helperName, hint)
}

// linkHelper points link at exe by the cheapest mechanism that works and reports
// which one it used. Windows symlinks need Developer Mode or an elevated shell;
// hard links need neither, as long as both paths sit on one volume. Only a symlink
// resolves by name, so it is the only variant `aqt update` carries along; a copy
// always works but duplicates the binary, which is why it is the last resort.
func linkHelper(exe, link string) (string, error) {
	target := exe
	if filepath.Dir(link) == filepath.Dir(exe) {
		target = filepath.Base(exe) // relative, so moving the install directory keeps it valid
	}
	if err := os.Symlink(target, link); err == nil {
		return "symlink", nil
	}
	if err := os.Link(exe, link); err == nil {
		return "hard link", nil
	}
	if err := copyExecutable(exe, link); err != nil {
		return "", err
	}
	return "copy", nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+helperName+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// samePath reports whether both paths name one file or directory, through a
// symlink, a hard link, or being the same location spelled differently. A copy is
// deliberately not the same file: it can go stale, and every caller here wants to
// notice that.
func samePath(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// staleHelperLink finds the helper Git would run and reports whether it still names
// the installed client. Git resolves it through PATH, so that is what decides;
// `aqt git setup --dir` can put the link anywhere, and only when PATH holds none
// does the sibling of the client — where setup puts one by default — matter.
//
// `aqt update` replaces the client by renaming a staged file over it. A symlink
// resolves by name and follows; a hard link or a copy stays bound to the file that
// was renamed away and keeps serving the previous client.
func staleHelperLink(in update.Install) (string, bool) {
	link, err := exec.LookPath(helperName)
	if err != nil {
		link = filepath.Join(in.Dir, helperLinkName())
		if _, err := os.Lstat(link); err != nil {
			return "", false
		}
	}
	return link, !samePath(link, in.Path)
}

// warnHelperUnreachable covers the two ways a correct link still leaves Git
// reporting `Unknown URL transport`: the directory is not on PATH, or an earlier
// entry answers to the same name.
func warnHelperUnreachable(link string) {
	found, err := exec.LookPath(helperName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s is not on PATH; add %s to it before cloning\n", helperName, filepath.Dir(link))
		return
	}
	if !samePath(found, link) {
		fmt.Fprintf(os.Stderr, "warning: Git resolves %s to %s, which comes earlier on PATH\n", helperName, found)
	}
}
