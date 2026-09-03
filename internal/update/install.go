// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// verifyTimeout bounds the post-install probe. It runs the freshly installed
// binary with --version; one that has not answered by now is not going to, and
// hanging here would leave the install half-swapped.
const verifyTimeout = 20 * time.Second

var (
	// ErrVerifyFailed means the newly written binary did not run and report the
	// version the manifest promised. The old binary is put back before this is
	// returned.
	ErrVerifyFailed = errors.New("the installed binary failed verification")
	// ErrRolledBack accompanies a failure that was undone. It is informational:
	// the installation is exactly as it was before.
	ErrRolledBack = errors.New("the update was rolled back")
)

// capWriter refuses to buffer more than max bytes, which stops a broken child
// process from being read into memory without limit.
type capWriter struct {
	buf  bytes.Buffer
	max  int64
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if int64(w.buf.Len()+len(p)) > w.max {
		w.over = true
		return 0, ErrTooLarge
	}
	return w.buf.Write(p)
}

// ApplyOptions describes one replacement.
type ApplyOptions struct {
	Install  Install
	Version  string
	Artifact Artifact
	Source   ArtifactSource
	Platform Platform
	// VerifyExec runs a candidate binary and reports whether it is the release it
	// claims to be. Tests substitute it; nil means actually execute the file.
	VerifyExec func(ctx context.Context, path, wantVersion string) error
}

// ApplyResult reports what changed.
type ApplyResult struct {
	FromVersion string
	ToVersion   string
	Path        string
	// RollbackPath is the previous binary, kept when the OS could not delete it
	// while it is still running. It is debris, not state: any later update removes
	// it, and nothing reads it after this call returns.
	RollbackPath string
}

// Apply downloads, verifies, and replaces the installed binary, keeping the
// previous one until the new one has proved it runs.
//
// The sequence is the same on every platform, because the one operation Windows
// refuses is overwriting a running image — not renaming it. So the running binary
// is first renamed aside (permitted everywhere, and on Unix the inode stays live
// for this process either way), and only then is the new file renamed into the
// path. Every failure after that point renames the old file back, so there is no
// window in which the install path holds nothing.
func Apply(ctx context.Context, opts ApplyOptions) (ApplyResult, error) {
	in := opts.Install
	if !in.Replaceable() {
		return ApplyResult{}, fmt.Errorf("%w: %s", ErrNotReplaceable, in.Why())
	}
	if opts.Version == "" || opts.Artifact.Name == "" {
		return ApplyResult{}, errors.New("apply requires a version and an artifact")
	}
	platform := opts.Platform
	if platform == (Platform{}) {
		platform = Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}
	}
	res := ApplyResult{ToVersion: opts.Version, Path: in.Path}

	// Debris from an interrupted earlier run would otherwise accumulate in the
	// user's bin directory, and on Windows one of those files is a locked image
	// this process can only clear on a later run.
	CleanStale(in.Dir, "")

	archive, err := DownloadArtifact(ctx, opts.Source, opts.Version, opts.Artifact, in.Dir)
	if err != nil {
		return res, err
	}
	defer func() { _ = os.Remove(archive) }()

	staged, err := os.CreateTemp(in.Dir, TempPrefix+"*.new")
	if err != nil {
		return res, err
	}
	stagedPath := staged.Name()
	_ = staged.Close() // ExtractExecutable owns the contents; this only reserved the name
	defer func() { _ = os.Remove(stagedPath) }()

	if err := ExtractExecutable(archive, platform, stagedPath); err != nil {
		return res, err
	}
	if err := os.Chmod(stagedPath, installMode(in.Path)); err != nil {
		return res, err
	}

	// Prove the candidate runs before the installed binary is disturbed at all. A
	// broken download that got this far stops here, with nothing to undo.
	if err := verifyExec(ctx, opts, stagedPath); err != nil {
		return res, fmt.Errorf("%w before installing: %w", ErrVerifyFailed, err)
	}

	rollback := filepath.Join(in.Dir, TempPrefix+"previous.old")
	_ = os.Remove(rollback)
	if err := os.Rename(in.Path, rollback); err != nil {
		return res, fmt.Errorf("moving the current binary aside: %w", err)
	}
	if err := os.Rename(stagedPath, in.Path); err != nil {
		restore(rollback, in.Path)
		return res, fmt.Errorf("%w: installing the new binary: %w", ErrRolledBack, err)
	}
	if err := verifyExec(ctx, opts, in.Path); err != nil {
		_ = os.Remove(in.Path)
		restore(rollback, in.Path)
		return res, fmt.Errorf("%w: %w (%w)", ErrVerifyFailed, err, ErrRolledBack)
	}

	// The rollback copy is this process's own running image on Windows, which the
	// OS keeps locked until exit. Failing to remove it is expected there and is not
	// an error: CleanStale collects it the next time an update runs.
	if err := os.Remove(rollback); err != nil {
		res.RollbackPath = rollback
	}
	return res, nil
}

// restore puts the previous binary back after a failed installation. Nothing can
// be done if this fails, but the rollback file is still on disk under a known
// name, which is what the error message points at.
func restore(rollback, path string) {
	if err := os.Rename(rollback, path); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: could not restore the previous binary; it is at %s and can be moved back to %s manually: %v\n",
			rollback, path, err)
	}
}

// installMode derives the mode for the new binary from the one being replaced, so
// a deliberately group-readable or restricted install keeps its permissions. Only
// the permission bits are carried over, which is what drops setuid, setgid, and
// the sticky bit: they are never meaningful on this binary, and preserving them
// from an unexpected source is how a replacement escalates. Owner-execute is
// forced on, since a binary that cannot be run is not a successful install.
func installMode(path string) os.FileMode {
	mode := os.FileMode(0o755)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return mode | 0o100
}

func verifyExec(ctx context.Context, opts ApplyOptions, path string) error {
	if opts.VerifyExec != nil {
		return opts.VerifyExec(ctx, path, opts.Version)
	}
	return runVersionProbe(ctx, path, opts.Version)
}

// runVersionProbe executes a candidate binary and requires it to report the
// version the signed manifest named. This is what catches a truncated or
// architecture-mismatched file that nonetheless hashed correctly, which a
// checksum alone cannot: the bytes can be exactly what was published and still be
// unrunnable here.
func runVersionProbe(ctx context.Context, path, wantVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--version")
	stdout := &capWriter{max: 4 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s --version: %w", filepath.Base(path), err)
	}
	out := strings.TrimSpace(stdout.buf.String())
	if !strings.Contains(out, wantVersion) {
		return fmt.Errorf("it reports %q, want %s", out, wantVersion)
	}
	return nil
}
