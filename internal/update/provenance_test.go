// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"errors"
	"path/filepath"
	"testing"
)

func fakeEnv(exe string) env {
	return env{
		executable: func() (string, error) { return exe, nil },
		evalSymlin: func(p string) (string, error) { return p, nil },
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

func TestDetectResolvesSymlinksBeforeReplacing(t *testing.T) {
	root := t.TempDir()
	shim := filepath.Join(root, "bin", "aqt")
	target := filepath.Join(root, "releases", "aqt")

	e := fakeEnv(shim)
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
	if in.Owner != OwnerStandalone {
		t.Fatalf("owner = %q, want standalone", in.Owner)
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
