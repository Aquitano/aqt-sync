// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEnv resolves a fixed executable path and answers stat from a set of paths
// the test declares to exist, so detection is exercised without laying down a
// package manager's directory tree.
//
// Fixture paths are rooted at a real temporary directory rather than written as
// literals: detection absolutizes what it resolves, and on Windows a literal like
// "\opt\homebrew" grows a volume letter that would no longer match this map.
func fakeEnv(exe string, existing ...string) env {
	present := make(map[string]bool, len(existing))
	for _, p := range existing {
		present[filepath.Clean(p)] = true
	}
	return env{
		executable: func() (string, error) { return exe, nil },
		evalSymlin: func(p string) (string, error) { return p, nil },
		stat: func(p string) (os.FileInfo, error) {
			if present[filepath.Clean(p)] {
				return nil, nil
			}
			return nil, fs.ErrNotExist
		},
	}
}

func releaseBuildKind() Build { return Build{Version: "v0.4.0", Kind: KindRelease} }

// A source build is decided from build metadata alone: its version string says
// nothing about which release it corresponds to, so no amount of path inspection
// would help.
func TestDetectSourceBuildWithoutTouchingTheFilesystem(t *testing.T) {
	e := env{
		executable: func() (string, error) {
			t.Error("a source build inspected the filesystem")
			return "", nil
		},
	}
	in, err := detectInstall(Build{Version: "0.4.0-dev", Kind: KindDev}, e)
	if err != nil {
		t.Fatal(err)
	}
	if in.Owner != OwnerSource {
		t.Fatalf("owner = %q, want source", in.Owner)
	}
	if in.Replaceable() {
		t.Fatal("a source build offered to replace itself")
	}
	if in.Why() == "" {
		t.Fatal("a refusal with no explanation")
	}
}

func TestDetectStandaloneInstall(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "usr", "local", "bin", "aqt")

	in, err := detectInstall(releaseBuildKind(), fakeEnv(exe))
	if err != nil {
		t.Fatal(err)
	}
	if in.Owner != OwnerStandalone {
		t.Fatalf("owner = %q, want standalone", in.Owner)
	}
	if !in.Replaceable() {
		t.Fatal("a standalone install refused replacement")
	}
	if in.Why() != "" {
		t.Fatalf("a replaceable install explained a refusal: %q", in.Why())
	}
	if in.Path != exe || in.Dir != filepath.Dir(exe) {
		t.Fatalf("path = %q, dir = %q", in.Path, in.Dir)
	}
}

func TestDetectPackageManagedInstalls(t *testing.T) {
	cases := []struct {
		name     string
		exe      []string
		existing [][]string
		owner    Owner
		pkg      string
		upgrade  string
	}{
		{
			name:     "homebrew",
			exe:      []string{"opt", "homebrew", "Cellar", "aqt", "0.4.0", "bin", "aqt"},
			existing: [][]string{{"opt", "homebrew", "Cellar", "aqt", "0.4.0", "INSTALL_RECEIPT.json"}},
			owner:    OwnerHomebrew,
			pkg:      "aqt",
			upgrade:  "brew upgrade aqt",
		},
		{
			name: "scoop",
			exe:  []string{"scoop", "apps", "aqt", "0.4.0", "aqt.exe"},
			existing: [][]string{
				{"scoop", "shims"},
				{"scoop", "apps", "aqt", "0.4.0", "install.json"},
			},
			owner:   OwnerScoop,
			pkg:     "aqt",
			upgrade: "scoop update aqt",
		},
		{
			name:    "winget",
			exe:     []string{"AppData", "Local", "Microsoft", "WinGet", "Packages", "Aquitano.aqt_Microsoft.Winget.Source_8wekyb3d8bbwe", "aqt.exe"},
			owner:   OwnerWinGet,
			pkg:     "Aquitano.aqt",
			upgrade: "winget upgrade Aquitano.aqt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := filepath.Join(append([]string{root}, tc.exe...)...)
			existing := make([]string, 0, len(tc.existing))
			for _, parts := range tc.existing {
				existing = append(existing, filepath.Join(append([]string{root}, parts...)...))
			}

			in, err := detectInstall(releaseBuildKind(), fakeEnv(exe, existing...))
			if err != nil {
				t.Fatal(err)
			}
			if in.Owner != tc.owner {
				t.Fatalf("owner = %q, want %q", in.Owner, tc.owner)
			}
			if in.Package != tc.pkg {
				t.Fatalf("package = %q, want %q", in.Package, tc.pkg)
			}
			if in.UpgradeCommand != tc.upgrade {
				t.Fatalf("upgrade = %q, want %q", in.UpgradeCommand, tc.upgrade)
			}
			if in.Replaceable() {
				t.Fatalf("a %s install offered to replace itself", tc.owner)
			}
			// The refusal has to name the command that actually works, or the user is
			// left with a message that tells them nothing.
			if why := in.Why(); !strings.Contains(why, tc.upgrade) {
				t.Fatalf("Why() = %q, does not name %q", why, tc.upgrade)
			}
		})
	}
}

// The receipt is what separates a real formula from a directory that merely has
// the right name, so a lookalike path stays replaceable rather than being refused
// on a guess.
func TestDetectRequiresPackageReceipts(t *testing.T) {
	cases := []struct {
		name     string
		exe      []string
		existing [][]string
	}{
		{
			name: "a Cellar directory with no brew receipt",
			exe:  []string{"home", "me", "Cellar", "aqt", "0.4.0", "bin", "aqt"},
		},
		{
			name:     "an apps directory with no scoop shims",
			exe:      []string{"home", "me", "apps", "aqt", "0.4.0", "aqt"},
			existing: [][]string{{"home", "me", "apps", "aqt", "0.4.0", "install.json"}},
		},
		{
			name:     "a scoop layout with no install manifest",
			exe:      []string{"home", "me", "apps", "aqt", "0.4.0", "aqt"},
			existing: [][]string{{"home", "me", "shims"}},
		},
		{
			name: "a Packages directory that is not WinGet's",
			exe:  []string{"srv", "Packages", "aqt_1", "aqt"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			exe := filepath.Join(append([]string{root}, tc.exe...)...)
			existing := make([]string, 0, len(tc.existing))
			for _, parts := range tc.existing {
				existing = append(existing, filepath.Join(append([]string{root}, parts...)...))
			}

			in, err := detectInstall(releaseBuildKind(), fakeEnv(exe, existing...))
			if err != nil {
				t.Fatal(err)
			}
			if in.Owner != OwnerStandalone {
				t.Fatalf("owner = %q, want standalone", in.Owner)
			}
		})
	}
}

// A package manager publishes a shim on PATH and keeps the real file in its own
// store. Classifying the shim rather than its target is how a managed install
// gets mistaken for a standalone one and overwritten.
func TestDetectResolvesSymlinksBeforeClassifying(t *testing.T) {
	root := t.TempDir()
	shim := filepath.Join(root, "homebrew", "bin", "aqt")
	target := filepath.Join(root, "homebrew", "Cellar", "aqt", "0.4.0", "bin", "aqt")
	receipt := filepath.Join(root, "homebrew", "Cellar", "aqt", "0.4.0", "INSTALL_RECEIPT.json")

	e := fakeEnv(shim, receipt)
	e.evalSymlin = func(p string) (string, error) {
		if p == shim {
			return target, nil
		}
		return p, nil
	}

	in, err := detectInstall(releaseBuildKind(), e)
	if err != nil {
		t.Fatal(err)
	}
	if in.Owner != OwnerHomebrew {
		t.Fatalf("owner = %q, want homebrew; the shim was classified instead of its target", in.Owner)
	}
	if in.Path != target {
		t.Fatalf("path = %q, want the resolved target %q", in.Path, target)
	}
}

func TestDetectReportsAnUnlocatableExecutable(t *testing.T) {
	e := env{executable: func() (string, error) { return "", errors.New("no /proc") }}
	if _, err := detectInstall(releaseBuildKind(), e); err == nil {
		t.Fatal("detection succeeded without locating the executable")
	}
}
