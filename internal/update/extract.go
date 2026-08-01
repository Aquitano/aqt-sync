package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// maxExecutableBytes bounds what comes out of the archive. The archive itself is
// already length- and hash-checked against the signed manifest, so this is the
// backstop for the one thing a checksum cannot bound: how much a few verified
// megabytes expand into. A real aqt binary is tens of megabytes.
const maxExecutableBytes = 256 << 20

var (
	// ErrUnexpectedEntry means the archive holds something other than the single
	// executable it is supposed to. Release archives are flat and contain exactly
	// one file, so anything else is either a different archive or a crafted one.
	ErrUnexpectedEntry = errors.New("release archive contains an unexpected entry")
	// ErrMissingExecutable means the archive did not contain the executable at all.
	ErrMissingExecutable = errors.New("release archive does not contain the aqt executable")
	// ErrArchiveTooLarge means extraction hit the output bound, which a genuine
	// release archive never does.
	ErrArchiveTooLarge = errors.New("release archive expands to more than the allowed size")
)

// ExecutableName is the file the release archive for a platform carries.
func ExecutableName(p Platform) string {
	if p.OS == "windows" {
		return "aqt.exe"
	}
	return "aqt"
}

// ExtractExecutable writes the single executable from the verified archive to
// dst, which must sit on the install filesystem. The archive is treated as
// hostile even though its bytes matched a signed checksum: the signature says
// these are the bytes that were published, not that the publishing pipeline
// packed only what it meant to.
//
// Exactly one regular file, named as the release names the executable for p, is
// accepted. Directories, symlinks, hard links, devices, a second copy of the
// executable, and any other member are all refused rather than skipped, because
// an archive holding them is not the archive the release process produces.
//
// The platform decides both the entry name and the packing; archivePath is a
// temporary file whose own name says nothing about its contents.
func ExtractExecutable(archivePath string, p Platform, dst string) error {
	src, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer src.Close()

	want := ExecutableName(p)
	if archiveExt(p) == ".zip" {
		info, err := src.Stat()
		if err != nil {
			return err
		}
		return extractZip(src, info.Size(), want, dst)
	}
	return extractTarGz(src, want, dst)
}

func extractTarGz(r io.Reader, want, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading the release archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading the release archive: %w", err)
		}
		if err := checkEntryName(h.Name, want); err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("%w: %q is not a regular file", ErrUnexpectedEntry, h.Name)
		}
		if found {
			return fmt.Errorf("%w: %q appears twice", ErrUnexpectedEntry, h.Name)
		}
		found = true
		if err := writeBounded(dst, tr); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%w: expected %q", ErrMissingExecutable, want)
	}
	return nil
}

func extractZip(r io.ReaderAt, size int64, want, dst string) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("reading the release archive: %w", err)
	}
	found := false
	for _, f := range zr.File {
		if err := checkEntryName(f.Name, want); err != nil {
			return err
		}
		// Mode carries the type bits for entries written by a Unix zip, which is how
		// the release archives are produced; a symlink or device smuggled in this way
		// is refused before it is opened.
		if !f.FileInfo().Mode().IsRegular() {
			return fmt.Errorf("%w: %q is not a regular file", ErrUnexpectedEntry, f.Name)
		}
		if found {
			return fmt.Errorf("%w: %q appears twice", ErrUnexpectedEntry, f.Name)
		}
		found = true

		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeBounded(dst, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%w: expected %q", ErrMissingExecutable, want)
	}
	return nil
}

// checkEntryName rejects anything that is not exactly the executable, at the root
// of the archive. Requiring an exact match subsumes path traversal: a name has to
// equal `aqt` to be accepted, so "../../etc/cron.d/x" and "bin/aqt" alike fail
// without any need to reason about what a cleaned path would resolve to.
func checkEntryName(name, want string) error {
	if strings.ContainsRune(name, '\\') {
		return fmt.Errorf("%w: %q", ErrUnexpectedEntry, name)
	}
	if name != want {
		return fmt.Errorf("%w: %q, expected only %q", ErrUnexpectedEntry, name, want)
	}
	return nil
}

// writeBounded copies at most maxExecutableBytes to dst, created private because
// a partially written executable must never be runnable by anyone. The caller
// sets the final mode once the contents are known good.
func writeBounded(dst string, r io.Reader) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := io.Copy(f, io.LimitReader(r, maxExecutableBytes+1))
	if err != nil {
		return err
	}
	if n > maxExecutableBytes {
		return fmt.Errorf("%w: over %d bytes", ErrArchiveTooLarge, maxExecutableBytes)
	}
	if n == 0 {
		return fmt.Errorf("%w: it is empty", ErrMissingExecutable)
	}
	return f.Sync()
}
