// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Owner names how the installed binary was built. Only a standalone release is
// ours to replace; source builds should be rebuilt from their checkout.
type Owner string

const (
	// OwnerStandalone is a release archive unpacked by hand or by the install
	// script. Nothing else tracks it, so `aqt update` may replace it.
	OwnerStandalone Owner = "standalone"
	// OwnerSource is a build from this repository. Its version string says nothing
	// about which release it corresponds to.
	OwnerSource Owner = "source"
)

// ErrNotReplaceable means the running binary is not ours to replace.
var ErrNotReplaceable = errors.New("this installation is not managed by aqt update")

// Install describes where the running binary came from and what may be done to it.
type Install struct {
	// Path is the executable with every symlink resolved, which is the file a
	// replacement would actually overwrite.
	Path string
	// Dir is Path's directory: where a same-filesystem temporary file goes.
	Dir string
	// Owner is who controls Path.
	Owner Owner
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
		return "this installation cannot be updated automatically"
	}
}

// env is the ambient state detection reads. Tests supply their own so no case
// depends on the machine the tests run on.
type env struct {
	executable func() (string, error)
	evalSymlin func(string) (string, error)
}

func realEnv() env {
	return env{
		executable: os.Executable,
		evalSymlin: filepath.EvalSymlinks,
	}
}

// DetectInstall classifies the running binary. A source build is decided from
// build metadata alone and never touches the filesystem; a release build resolves
// its executable path so an update replaces the actual binary rather than a link.
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
	if resolved, err := e.evalSymlin(exe); err == nil {
		exe = resolved
	}
	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}

	return Install{Path: exe, Dir: filepath.Dir(exe), Owner: OwnerStandalone}, nil
}
