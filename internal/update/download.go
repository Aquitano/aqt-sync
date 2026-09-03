// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// TempPrefix marks the files an interrupted update leaves behind, in the install
// directory. Named so a user who finds one knows what it is, and so cleanup can
// recognize its own debris without guessing.
const TempPrefix = ".aqt-update-"

var (
	// ErrSizeMismatch means the archive is not the length the signed manifest
	// declares. Checked while downloading, so an endless body is cut off rather
	// than filling the disk first.
	ErrSizeMismatch = errors.New("downloaded archive is not the size the manifest declares")
	// ErrHashMismatch means the bytes hash to something other than the signed
	// SHA-256. The transport is untrusted, so this is the check that matters.
	ErrHashMismatch = errors.New("downloaded archive does not match the manifest checksum")
)

// ArtifactSource fetches one release archive. Kept apart from Source because
// metadata is small enough to hold in memory and an archive is not: this streams.
type ArtifactSource interface {
	FetchArtifact(ctx context.Context, version string, a Artifact, w io.Writer) error
}

// DownloadArtifact streams the archive into a temporary file in dir, verifying
// length and SHA-256 as the bytes arrive, and returns the path to the verified
// file. dir must be the directory the binary will be installed into, so the
// eventual rename is a same-filesystem operation rather than a copy across
// devices that could be interrupted halfway.
//
// The caller owns the returned file and must remove it unless it is renamed into
// place. On any error nothing is left behind.
func DownloadArtifact(ctx context.Context, src ArtifactSource, version string, a Artifact, dir string) (path string, err error) {
	if src == nil {
		return "", errors.New("no artifact source configured")
	}
	if a.Size <= 0 || a.Size > maxArtifactBytes {
		return "", fmt.Errorf("%w: %d bytes", ErrMalformedManifest, a.Size)
	}
	f, err := os.CreateTemp(dir, TempPrefix+"*.part")
	if err != nil {
		return "", fmt.Errorf("creating a temporary file next to the installed binary: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	h := sha256.New()
	// The limit is the manifest's own declared size: one byte more and this is not
	// the artifact that was signed, whatever it turns out to hash to.
	counter := &boundedWriter{w: io.MultiWriter(f, h), limit: a.Size}
	if err = src.FetchArtifact(ctx, version, a, counter); err != nil {
		return "", err
	}
	if counter.n != a.Size {
		return "", fmt.Errorf("%w: got %d bytes, want %d", ErrSizeMismatch, counter.n, a.Size)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != a.SHA256 {
		return "", fmt.Errorf("%w: got %s, want %s", ErrHashMismatch, sum, a.SHA256)
	}
	// Durability before the swap: a crash between here and the rename must not be
	// able to leave a file that passed verification but is not fully on disk.
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return tmp, nil
}

// boundedWriter refuses to pass on more than limit bytes, so a source that keeps
// sending is stopped at the size the manifest declared instead of being written
// to disk in full and rejected afterwards.
type boundedWriter struct {
	w     io.Writer
	limit int64
	n     int64
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if b.n+int64(len(p)) > b.limit {
		return 0, fmt.Errorf("%w: more than %d bytes", ErrSizeMismatch, b.limit)
	}
	n, err := b.w.Write(p)
	b.n += int64(n)
	return n, err
}

// FetchArtifact streams a release asset over HTTPS. The URL comes from the signed
// manifest, which CheckURLs has already pinned to the one location it may name.
func (h HTTPSource) FetchArtifact(ctx context.Context, _ string, a Artifact, w io.Writer) error {
	return streamURL(ctx, h.Client, a.URL, w)
}

// streamURL copies one URL's body to w without buffering it whole. Callers bound
// the size: DownloadArtifact stops at the manifest's declared length.
func streamURL(ctx context.Context, client *http.Client, rawURL string, w io.Writer) error {
	if client == nil {
		client = defaultHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// CleanStale removes update debris older than nothing in particular: every
// temporary file this package creates in dir that is not the one in use. An
// interrupted update leaves a .part file and possibly a rollback copy; neither is
// load-bearing once a later update starts, and leaving them accumulating in the
// user's bin directory is its own bug.
func CleanStale(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, TempPrefix) || e.IsDir() {
			continue
		}
		path := filepath.Join(dir, name)
		if path == keep {
			continue
		}
		_ = os.Remove(path) // best effort: a locked or vanished file is not worth reporting
	}
}
