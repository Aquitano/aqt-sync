// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeArtifactSource serves fixture bytes in place of a release download, so no
// test needs gh, a network, or a real release.
type fakeArtifactSource struct {
	data []byte
	err  error
}

func (f fakeArtifactSource) FetchArtifact(_ context.Context, _ string, _ Artifact, w io.Writer) error {
	if f.err != nil {
		return f.err
	}
	_, err := w.Write(f.data)
	return err
}

// artifactFor describes fixture bytes the way a signed manifest would: exact name,
// exact length, exact digest.
func artifactFor(name string, data []byte) Artifact {
	sum := sha256.Sum256(data)
	return Artifact{
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		Name:   name,
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
		URL:    AssetURL(DefaultRepo, "v9.9.9", name),
	}
}

// standaloneInstall lays down a fake installed binary and describes it the way
// detection would.
func standaloneInstall(t *testing.T, contents string) Install {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ExecutableName(here()))
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
	return Install{Path: path, Dir: dir, Owner: OwnerStandalone}
}

func here() Platform { return Platform{OS: runtime.GOOS, Arch: runtime.GOARCH} }

// releaseArchive packs contents the way the release workflow does for this
// platform: one flat entry, zip on Windows and tar.gz everywhere else.
func releaseArchive(t *testing.T, contents string) (name string, data []byte) {
	t.Helper()
	entry := archiveEntry{name: ExecutableName(here()), body: contents}
	if runtime.GOOS == "windows" {
		return "aqt_v9.9.9_windows_amd64.zip", zipArchive(t, entry)
	}
	return fmt.Sprintf("aqt_v9.9.9_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH), tarGz(t, entry)
}

// applyFixture runs Apply against fixture bytes with the version probe stubbed,
// because a fixture "binary" is not runnable.
func applyFixture(t *testing.T, in Install, contents string, verify func(path string) error) (ApplyResult, error) {
	t.Helper()
	name, data := releaseArchive(t, contents)
	return Apply(context.Background(), ApplyOptions{
		Install:  in,
		Version:  "v9.9.9",
		Artifact: artifactFor(name, data),
		Source:   fakeArtifactSource{data: data},
		Platform: here(),
		VerifyExec: func(_ context.Context, path, _ string) error {
			if verify == nil {
				return nil
			}
			return verify(path)
		},
	})
}

// debris lists the update temporaries left in dir. A successful update leaves
// none, and a failed one must not leave any either.
func debris(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), TempPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyReplacesTheBinary(t *testing.T) {
	in := standaloneInstall(t, "old binary")

	res, err := applyFixture(t, in, "new binary", nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := mustRead(t, in.Path); got != "new binary" {
		t.Fatalf("installed %q", got)
	}
	if res.ToVersion != "v9.9.9" {
		t.Fatalf("result = %+v", res)
	}
	if left := debris(t, in.Dir); len(left) != 0 {
		t.Fatalf("update left debris behind: %v", left)
	}
}

// The new binary is run before the old one is disturbed, so a download that got
// all the way through verification and still does not work changes nothing.
func TestApplyLeavesTheInstallAloneWhenTheNewBinaryDoesNotRun(t *testing.T) {
	in := standaloneInstall(t, "old binary")

	_, err := applyFixture(t, in, "new binary", func(string) error {
		return errors.New("exec format error")
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("got %v, want ErrVerifyFailed", err)
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("the installed binary changed: %q", got)
	}
	if left := debris(t, in.Dir); len(left) != 0 {
		t.Fatalf("failed update left debris behind: %v", left)
	}
}

// The post-install probe is the one that runs the binary from its real path. When
// it fails the previous binary goes back, byte for byte.
func TestApplyRollsBackAFailedPostInstallVerification(t *testing.T) {
	in := standaloneInstall(t, "old binary")

	_, err := applyFixture(t, in, "new binary", func(path string) error {
		// Passing while staged and failing once installed is what a binary that
		// depends on its own path, or a swap that went wrong, would look like.
		if path == in.Path {
			return errors.New("cannot execute")
		}
		return nil
	})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("got %v, want ErrVerifyFailed", err)
	}
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("got %v, want it to report the rollback", err)
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("rollback did not restore the old binary: %q", got)
	}
	if left := debris(t, in.Dir); len(left) != 0 {
		t.Fatalf("rollback left debris behind: %v", left)
	}
}

func TestApplyRefusesAnInstallItDoesNotOwn(t *testing.T) {
	in := standaloneInstall(t, "old binary")
	in.Owner = OwnerSource

	_, err := applyFixture(t, in, "new binary", nil)
	if !errors.Is(err, ErrNotReplaceable) {
		t.Fatalf("got %v, want ErrNotReplaceable", err)
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("a source build was modified")
	}
}

func TestCapWriterRefusesToBufferBeyondItsLimit(t *testing.T) {
	w := &capWriter{max: 8}
	if _, err := w.Write([]byte("12345678")); err != nil {
		t.Fatalf("write at the limit: %v", err)
	}
	if _, err := w.Write([]byte("9")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if !w.over {
		t.Fatal("the overflow was not recorded")
	}
}

// Debris from an interrupted earlier update is cleared rather than accumulating in
// the user's bin directory. On Windows one of those files is a previously running
// image that only a later run can delete.
func TestApplyClearsStaleDebris(t *testing.T) {
	in := standaloneInstall(t, "old binary")
	stale := []string{TempPrefix + "previous.old", TempPrefix + "abc.part", TempPrefix + "def.new"}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(in.Dir, name), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := applyFixture(t, in, "new binary", nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if left := debris(t, in.Dir); len(left) != 0 {
		t.Fatalf("stale files survived: %v", left)
	}
}

func TestApplyRefusesACorruptedDownload(t *testing.T) {
	name, data := releaseArchive(t, "new binary")
	good := artifactFor(name, data)

	cases := []struct {
		name     string
		artifact Artifact
		served   []byte
		want     error
	}{
		{
			name:     "the bytes hash to something else",
			artifact: func() Artifact { a := good; a.SHA256 = strings.Repeat("00", 32); return a }(),
			served:   data,
			want:     ErrHashMismatch,
		},
		{
			name:     "more bytes than the manifest declares",
			artifact: func() Artifact { a := good; a.Size = int64(len(data)) - 1; return a }(),
			served:   data,
			want:     ErrSizeMismatch,
		},
		{
			name:     "fewer bytes than the manifest declares",
			artifact: func() Artifact { a := good; a.Size = int64(len(data)) + 1; return a }(),
			served:   data,
			want:     ErrSizeMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := standaloneInstall(t, "old binary")

			_, err := Apply(context.Background(), ApplyOptions{
				Install:    in,
				Version:    "v9.9.9",
				Artifact:   tc.artifact,
				Source:     fakeArtifactSource{data: tc.served},
				Platform:   here(),
				VerifyExec: func(context.Context, string, string) error { return nil },
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if got := mustRead(t, in.Path); got != "old binary" {
				t.Fatalf("the installed binary changed: %q", got)
			}
			if left := debris(t, in.Dir); len(left) != 0 {
				t.Fatalf("a rejected download left debris behind: %v", left)
			}
		})
	}
}

// An interrupted transfer is the same failure as a short one: nothing is written
// and nothing is left behind.
func TestApplySurvivesAnInterruptedDownload(t *testing.T) {
	in := standaloneInstall(t, "old binary")
	name, data := releaseArchive(t, "new binary")

	_, err := Apply(context.Background(), ApplyOptions{
		Install:    in,
		Version:    "v9.9.9",
		Artifact:   artifactFor(name, data),
		Source:     fakeArtifactSource{err: io.ErrUnexpectedEOF},
		Platform:   here(),
		VerifyExec: func(context.Context, string, string) error { return nil },
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want the transfer error", err)
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("the installed binary changed: %q", got)
	}
	if left := debris(t, in.Dir); len(left) != 0 {
		t.Fatalf("an interrupted download left debris behind: %v", left)
	}
}

// The replacement keeps the mode the old binary had, so a deliberately restricted
// install does not silently widen. Windows has no meaningful permission bits here.
func TestApplyPreservesTheExecutableMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	in := standaloneInstall(t, "old binary")
	if err := os.Chmod(in.Path, 0o750); err != nil {
		t.Fatal(err)
	}

	if _, err := applyFixture(t, in, "new binary", nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fi, err := os.Stat(in.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o750 {
		t.Fatalf("mode = %o, want 750", got)
	}
}

// setuid on the replacement is dropped rather than carried across, so a mode that
// should never have been there does not survive an update.
func TestApplyDropsSetuidFromTheReplacedBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not meaningful on Windows")
	}
	in := standaloneInstall(t, "old binary")
	if err := os.Chmod(in.Path, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	if _, err := applyFixture(t, in, "new binary", nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fi, err := os.Stat(in.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid != 0 {
		t.Fatalf("setuid survived the update: %v", fi.Mode())
	}
}

// A directory that cannot be written to fails before anything is touched, rather
// than part way through.
func TestApplyFailsCleanlyWithoutWritePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write permission is not enforced this way on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	in := standaloneInstall(t, "old binary")
	if err := os.Chmod(in.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(in.Dir, 0o700) })

	if _, err := applyFixture(t, in, "new binary", nil); err == nil {
		t.Fatal("Apply succeeded in a read-only directory")
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("the installed binary changed: %q", got)
	}
}

// The archive is selected by platform, so one built for another OS never lands:
// its single entry is not named what this platform's executable is called.
func TestApplyRefusesAnArchiveForAnotherPlatform(t *testing.T) {
	in := standaloneInstall(t, "old binary")
	other := "aqt.exe"
	if runtime.GOOS == "windows" {
		other = "aqt"
	}
	data := tarGz(t, archiveEntry{name: other, body: "new binary"})
	if runtime.GOOS == "windows" {
		data = zipArchive(t, archiveEntry{name: other, body: "new binary"})
	}

	_, err := Apply(context.Background(), ApplyOptions{
		Install:    in,
		Version:    "v9.9.9",
		Artifact:   artifactFor("aqt_v9.9.9_other.tar.gz", data),
		Source:     fakeArtifactSource{data: data},
		Platform:   here(),
		VerifyExec: func(context.Context, string, string) error { return nil },
	})
	if !errors.Is(err, ErrUnexpectedEntry) {
		t.Fatalf("got %v, want ErrUnexpectedEntry", err)
	}
	if got := mustRead(t, in.Path); got != "old binary" {
		t.Fatalf("the installed binary changed: %q", got)
	}
}

func TestCleanStaleKeepsTheFileInUse(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, TempPrefix+"keep.part")
	drop := filepath.Join(dir, TempPrefix+"drop.part")
	other := filepath.Join(dir, "aqt")
	for _, p := range []string{keep, drop, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	CleanStale(dir, keep)

	if _, err := os.Stat(keep); err != nil {
		t.Fatal("the file in use was removed")
	}
	if _, err := os.Stat(drop); err == nil {
		t.Fatal("stale debris survived")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("an unrelated file was removed")
	}
}
