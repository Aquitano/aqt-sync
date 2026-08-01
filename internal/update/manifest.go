// Package update reports whether a newer aqt release has been published. It
// fetches a signed, canonical release manifest, verifies it against public keys
// compiled into this build, and answers "is this binary current?". Nothing here
// writes to the installation: the transport is untrusted by design, and the
// signature is what makes the answer trustworthy.
package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const (
	// ManifestSchema is the only manifest layout this build understands. A newer
	// schema is refused rather than parsed on a best-effort basis.
	ManifestSchema = 1

	// MaxManifestBytes and MaxSignatureBytes bound how much is read from the
	// network before anything is parsed.
	MaxManifestBytes  = 64 << 10
	MaxSignatureBytes = 8 << 10

	// ManifestAssetName and SignatureAssetName are the release asset names the
	// manifest and its detached signature are published under.
	ManifestAssetName  = "aqt-update.json"
	SignatureAssetName = "aqt-update.json.sig"

	maxArtifacts     = 32
	maxArtifactBytes = 512 << 20
)

var (
	// ErrUnsupportedSchema means the manifest was published by a newer release
	// process than this build knows how to read.
	ErrUnsupportedSchema = errors.New("update manifest schema is newer than this build understands")
	// ErrMalformedManifest covers every structural defect in the manifest.
	ErrMalformedManifest = errors.New("malformed update manifest")
	// ErrNotCanonical means the bytes that were signed are not the canonical
	// encoding of what they decode to, so two readers could disagree about them.
	ErrNotCanonical = errors.New("update manifest is not in canonical form")
	// ErrTooLarge means the metadata exceeded its size cap.
	ErrTooLarge = errors.New("update metadata is too large")
	// ErrAmbiguousAsset means one platform is listed more than once, so there is
	// no single answer to "which archive is mine".
	ErrAmbiguousAsset = errors.New("update manifest lists a platform more than once")
	// ErrNoPlatformAsset means the release carries no build for this OS/arch.
	ErrNoPlatformAsset = errors.New("the release has no build for this platform")
)

// Channel names a release track. Stable is the default; beta additionally carries
// prereleases and must be asked for explicitly.
type Channel string

const (
	ChannelStable Channel = "stable"
	ChannelBeta   Channel = "beta"
)

func (c Channel) valid() bool { return c == ChannelStable || c == ChannelBeta }

// accepts reports whether a manifest published on got answers a check for c.
// Beta is a superset of stable rather than a separate track: it carries
// prereleases in addition to stable releases, and most of the time the newest
// release is a stable one. The reverse never holds, which is what keeps a
// prerelease off a stable check even when its manifest is authentic.
func (c Channel) accepts(got Channel) bool {
	return got == c || (c == ChannelBeta && got == ChannelStable)
}

// Platform is an OS/architecture pair, matching runtime.GOOS/runtime.GOARCH.
type Platform struct {
	OS   string
	Arch string
}

func (p Platform) String() string { return p.OS + "/" + p.Arch }

// Platforms is the exact set of client builds a release publishes. Manifest
// generation fails when an archive for one of these is missing, so the manifest
// can never advertise a platform the release does not actually carry.
var Platforms = []Platform{
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "darwin", Arch: "amd64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "windows", Arch: "amd64"},
}

// Manifest is the signed description of one published release.
type Manifest struct {
	Schema      int        `json:"schema"`
	Channel     Channel    `json:"channel"`
	Version     string     `json:"version"`
	PublishedAt string     `json:"publishedAt"`
	ReleaseURL  string     `json:"releaseUrl"`
	Artifacts   []Artifact `json:"artifacts"`
}

// Artifact is one client archive: the exact bytes a downloader must end up with.
type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// Platform returns the artifact's OS/arch pair.
func (a Artifact) Platform() Platform { return Platform{OS: a.OS, Arch: a.Arch} }

// ArchiveName is the only archive name a manifest may use for a platform. It is
// what keeps the `aqt` client apart from the `aqt-server` archive published beside
// it: an `aqt-server_...` name can never equal this, whatever slot it claims.
func ArchiveName(version string, p Platform) string {
	return fmt.Sprintf("aqt_%s_%s_%s%s", version, p.OS, p.Arch, archiveExt(p))
}

// archiveExt is how the release packs a platform's archive. Extraction reads it
// too, so the two never disagree about what the downloaded bytes are.
func archiveExt(p Platform) string {
	if p.OS == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

// ReleaseTagURL and AssetURL derive the only URLs a manifest may carry for a
// repository, so a signed manifest cannot redirect a downloader elsewhere.
func ReleaseTagURL(repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, version)
}

func AssetURL(repo, version, name string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, version, name)
}

// CanonicalBytes renders the manifest in its one signable encoding: artifacts
// sorted by platform, struct field order, two-space indent, no HTML escaping, one
// trailing newline. Signing covers exactly these bytes.
func (m Manifest) CanonicalBytes() ([]byte, error) {
	c := m
	c.Artifacts = append([]Artifact(nil), m.Artifacts...)
	sort.Slice(c.Artifacts, func(i, j int) bool {
		if c.Artifacts[i].OS != c.Artifacts[j].OS {
			return c.Artifacts[i].OS < c.Artifacts[j].OS
		}
		return c.Artifacts[i].Arch < c.Artifacts[j].Arch
	})
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseManifest decodes and fully validates manifest bytes. It is the only way to
// turn bytes into a Manifest, so no caller can skip a check: unknown fields,
// non-canonical encodings, and trailing data are all rejected, because a verified
// signature only means "these bytes are authentic", not "these bytes are sane".
func ParseManifest(b []byte) (Manifest, error) {
	if len(b) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest is %d bytes", ErrTooLarge, len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrMalformedManifest, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Manifest{}, fmt.Errorf("%w: trailing data after the manifest", ErrMalformedManifest)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	canon, err := m.CanonicalBytes()
	if err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(canon, b) {
		return Manifest{}, ErrNotCanonical
	}
	return m, nil
}

// Validate enforces every rule that does not depend on who is asking: schema,
// channel, version shape, timestamps, URL shape, and the per-artifact tuple.
func (m Manifest) Validate() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("%w (schema %d)", ErrUnsupportedSchema, m.Schema)
	}
	if !m.Channel.valid() {
		return fmt.Errorf("%w: unknown channel %q", ErrMalformedManifest, m.Channel)
	}
	v, err := ParseVersion(m.Version)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedManifest, err)
	}
	if m.Channel == ChannelStable && v.IsPrerelease() {
		return fmt.Errorf("%w: stable channel carries prerelease %s", ErrMalformedManifest, m.Version)
	}
	if !strings.HasSuffix(m.PublishedAt, "Z") {
		return fmt.Errorf("%w: publishedAt must be UTC", ErrMalformedManifest)
	}
	if _, err := time.Parse(time.RFC3339, m.PublishedAt); err != nil {
		return fmt.Errorf("%w: publishedAt: %v", ErrMalformedManifest, err)
	}
	if _, err := parseHTTPSURL(m.ReleaseURL); err != nil {
		return fmt.Errorf("%w: releaseUrl: %v", ErrMalformedManifest, err)
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > maxArtifacts {
		return fmt.Errorf("%w: %d artifacts", ErrMalformedManifest, len(m.Artifacts))
	}
	seen := make(map[Platform]bool, len(m.Artifacts))
	for _, a := range m.Artifacts {
		p := a.Platform()
		if !isLowerAlnum(a.OS) || !isLowerAlnum(a.Arch) {
			return fmt.Errorf("%w: bad platform %q/%q", ErrMalformedManifest, a.OS, a.Arch)
		}
		if seen[p] {
			return fmt.Errorf("%w: %s", ErrAmbiguousAsset, p)
		}
		seen[p] = true
		if want := ArchiveName(m.Version, p); a.Name != want {
			return fmt.Errorf("%w: %s names %q, want %q", ErrMalformedManifest, p, a.Name, want)
		}
		if a.Size <= 0 || a.Size > maxArtifactBytes {
			return fmt.Errorf("%w: %s has size %d", ErrMalformedManifest, p, a.Size)
		}
		if !isSHA256Hex(a.SHA256) {
			return fmt.Errorf("%w: %s has a malformed sha256", ErrMalformedManifest, p)
		}
		u, err := parseHTTPSURL(a.URL)
		if err != nil {
			return fmt.Errorf("%w: %s url: %v", ErrMalformedManifest, p, err)
		}
		if path.Base(u.Path) != a.Name {
			return fmt.Errorf("%w: %s url does not end in %q", ErrMalformedManifest, p, a.Name)
		}
	}
	return nil
}

// CheckURLs pins every URL in the manifest to the one location it may point at.
// A signed manifest is authentic, not benign: without this, anyone who could sign
// one could aim a downloader at an arbitrary host. Kept separate from Validate
// because it is the one rule that depends on which repository is publishing.
func (m Manifest) CheckURLs(repo string) error {
	if want := ReleaseTagURL(repo, m.Version); m.ReleaseURL != want {
		return fmt.Errorf("%w: releaseUrl is %q, want %q", ErrMalformedManifest, m.ReleaseURL, want)
	}
	for _, a := range m.Artifacts {
		if want := AssetURL(repo, m.Version, a.Name); a.URL != want {
			return fmt.Errorf("%w: %s url is %q, want %q", ErrMalformedManifest, a.Platform(), a.URL, want)
		}
	}
	return nil
}

// Artifact returns the archive for exactly one platform. Selection is by OS/arch,
// never by matching a name prefix, so the `aqt-server` archive published in the
// same release is not reachable from here.
func (m Manifest) Artifact(p Platform) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.Platform() == p {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %s", ErrNoPlatformAsset, p)
}

func parseHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("no host")
	}
	return u, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isLowerAlnum(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
