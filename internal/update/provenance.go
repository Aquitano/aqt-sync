package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Owner names who controls the installed binary. Only a standalone install is
// ours to replace: everything else was put there by something that keeps its own
// records, and overwriting it in place would leave that owner describing a file
// it no longer matches.
type Owner string

const (
	// OwnerStandalone is a release archive unpacked by hand or by the install
	// script. Nothing else tracks it, so `aqt update` may replace it.
	OwnerStandalone Owner = "standalone"
	// OwnerSource is a build from this repository. Its version string says nothing
	// about which release it corresponds to.
	OwnerSource Owner = "source"

	OwnerHomebrew Owner = "homebrew"
	OwnerWinGet   Owner = "winget"
	OwnerScoop    Owner = "scoop"
)

// ErrNotReplaceable means the running binary is not ours to replace. Install
// carries the upgrade command its real owner expects.
var ErrNotReplaceable = errors.New("this installation is not managed by aqt update")

// Install describes where the running binary came from and what may be done to it.
type Install struct {
	// Path is the executable with every symlink resolved, which is the file a
	// replacement would actually overwrite. Detection reads this rather than
	// whatever `aqt` resolves to on PATH, so a shim in front of a package-managed
	// binary does not read as standalone.
	Path string
	// Dir is Path's directory: where a same-filesystem temporary file goes.
	Dir string
	// Owner is who controls Path.
	Owner Owner
	// Package is the owner's name for this install (`aqt`, `Aquitano.aqt`), empty
	// for standalone and source builds.
	Package string
	// UpgradeCommand is what the user should run instead, empty when Owner is
	// OwnerStandalone. aqt never runs it: invoking a package manager from inside a
	// binary that manager owns is how an update ends up half-applied.
	UpgradeCommand string
}

// Replaceable reports whether `aqt update` may write to this install.
func (i Install) Replaceable() bool { return i.Owner == OwnerStandalone }

// Why explains a refusal in one line, phrased as the next thing to run.
func (i Install) Why() string {
	switch i.Owner {
	case OwnerSource:
		return "this is a build from source; rebuild it with `make build` or install a release"
	case OwnerStandalone:
		return ""
	default:
		return fmt.Sprintf("%s installed this copy; upgrade it with `%s`", i.Owner, i.UpgradeCommand)
	}
}

// env is the ambient state detection reads. Tests supply their own so no case
// depends on the machine the tests run on.
type env struct {
	executable func() (string, error)
	evalSymlin func(string) (string, error)
	stat       func(string) (os.FileInfo, error)
}

func realEnv() env {
	return env{
		executable: os.Executable,
		evalSymlin: filepath.EvalSymlinks,
		stat:       os.Stat,
	}
}

// DetectInstall classifies the running binary. A source build is decided from
// build metadata alone and never touches the filesystem; everything else is
// decided from the resolved executable path and the receipts a package manager
// leaves beside it.
func DetectInstall(b Build) (Install, error) {
	return detectInstall(b, realEnv())
}

func detectInstall(b Build, e env) (Install, error) {
	if b.Kind != KindRelease {
		return Install{Owner: OwnerSource}, nil
	}
	exe, err := e.executable()
	if err != nil {
		return Install{}, fmt.Errorf("locating the running executable: %w", err)
	}
	// A package manager usually publishes a symlink or shim on PATH and keeps the
	// real file in its own store. Resolving first is what makes the receipt checks
	// below look at the right directory.
	if resolved, err := e.evalSymlin(exe); err == nil {
		exe = resolved
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}

	in := Install{Path: exe, Dir: filepath.Dir(exe), Owner: OwnerStandalone}
	for _, detect := range []func(string, env) (Install, bool){
		detectHomebrew,
		detectScoop,
		detectWinGet,
	} {
		if managed, ok := detect(exe, e); ok {
			managed.Path, managed.Dir = exe, filepath.Dir(exe)
			return managed, nil
		}
	}
	return in, nil
}

// detectHomebrew matches the Cellar layout: <prefix>/Cellar/<formula>/<version>/bin/aqt,
// confirmed by the receipt brew writes beside it. The receipt is what separates a
// real formula from a directory that happens to be called Cellar.
func detectHomebrew(exe string, e env) (Install, bool) {
	parts := splitPath(exe)
	for i := len(parts) - 1; i >= 0; i-- {
		if !strings.EqualFold(parts[i], "Cellar") || i+2 >= len(parts) {
			continue
		}
		formula := parts[i+1]
		versionDir := filepath.Join(parts[:i+3]...)
		if !exists(e, filepath.Join(versionDir, "INSTALL_RECEIPT.json")) {
			continue
		}
		return Install{
			Owner:          OwnerHomebrew,
			Package:        formula,
			UpgradeCommand: "brew upgrade " + formula,
		}, true
	}
	return Install{}, false
}

// detectScoop matches <root>/apps/<app>/<version>/aqt.exe. Scoop's shims directory
// is a sibling of apps, and every installed version carries an install.json, so
// requiring both keeps an unrelated "apps" directory from matching.
func detectScoop(exe string, e env) (Install, bool) {
	parts := splitPath(exe)
	for i := len(parts) - 1; i >= 0; i-- {
		if !strings.EqualFold(parts[i], "apps") || i+2 >= len(parts) {
			continue
		}
		root := filepath.Join(parts[:i]...)
		app := parts[i+1]
		versionDir := filepath.Join(parts[:i+3]...)
		if !exists(e, filepath.Join(root, "shims")) {
			continue
		}
		if !exists(e, filepath.Join(versionDir, "install.json")) && !exists(e, filepath.Join(versionDir, "manifest.json")) {
			continue
		}
		return Install{
			Owner:          OwnerScoop,
			Package:        app,
			UpgradeCommand: "scoop update " + app,
		}, true
	}
	return Install{}, false
}

// detectWinGet matches the package store WinGet unpacks portable packages into:
// <LocalAppData>/Microsoft/WinGet/Packages/<PackageId>_<hash>/aqt.exe. The package
// id is the directory name up to the first underscore, which is what `winget
// upgrade` expects.
func detectWinGet(exe string, e env) (Install, bool) {
	parts := splitPath(exe)
	for i := len(parts) - 1; i >= 0; i-- {
		if !strings.EqualFold(parts[i], "Packages") || i < 2 || i+1 >= len(parts) {
			continue
		}
		if !strings.EqualFold(parts[i-1], "WinGet") || !strings.EqualFold(parts[i-2], "Microsoft") {
			continue
		}
		id, _, _ := strings.Cut(parts[i+1], "_")
		if id == "" {
			continue
		}
		return Install{
			Owner:          OwnerWinGet,
			Package:        id,
			UpgradeCommand: "winget upgrade " + id,
		}, true
	}
	return Install{}, false
}

func exists(e env, path string) bool {
	_, err := e.stat(path)
	return err == nil
}

func splitPath(p string) []string {
	p = filepath.Clean(p)
	vol := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, vol)
	parts := strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == '\\' })
	if vol != "" {
		return append([]string{vol + string(filepath.Separator)}, parts...)
	}
	if strings.HasPrefix(rest, "/") {
		return append([]string{"/"}, parts...)
	}
	return parts
}
