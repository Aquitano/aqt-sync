package update

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

// DefaultRepo is the repository releases are published from.
const DefaultRepo = "Aquitano/aqt-sync"

// Build kinds. Only a build produced by the release workflow can be updated: a
// source build is owned by whoever built it, and its version string says nothing
// about which release it corresponds to.
const (
	KindRelease = "release"
	KindDev     = "dev"
)

// Check statuses, as reported by `aqt update --check --json`.
const (
	StatusUpToDate        = "upToDate"
	StatusUpdateAvailable = "updateAvailable"
	StatusUnsupported     = "unsupported"
)

// ErrRollback means the published release is older than the running build. It is
// refused rather than reported, because the only ways to see it are a replayed
// manifest and a mistaken republish, and neither should move anyone backwards.
var ErrRollback = errors.New("the published release is older than the running build")

// ErrChannelMismatch means the fetched manifest is authentic but belongs to a
// different channel than the one asked for.
var ErrChannelMismatch = errors.New("update manifest is for a different channel")

// Build describes the running binary's provenance, stamped in at link time.
type Build struct {
	Version string
	Kind    string
}

// Options configures one check.
type Options struct {
	Build    Build
	Channel  Channel
	Source   Source
	Roots    []TrustRoot
	Repo     string
	Platform Platform
}

// Result is the answer to "is this binary current?". Its JSON encoding is the
// stable machine-readable contract of `aqt update --check --json`; fields may be
// added but not removed or repurposed.
type Result struct {
	CurrentVersion   string    `json:"currentVersion"`
	AvailableVersion string    `json:"availableVersion,omitempty"`
	Channel          string    `json:"channel"`
	Status           string    `json:"status"`
	ReleaseURL       string    `json:"releaseUrl,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	PublishedAt      string    `json:"publishedAt,omitempty"`
	Artifact         *Artifact `json:"-"`
}

// Check reports whether a newer release exists on the requested channel. It never
// touches the installed binary. Every failure mode — an unknown signing key, a bad
// signature, oversized or malformed metadata, a duplicated platform, a missing
// build for this platform, a rollback — returns an error instead of a partial
// answer, so a caller can never act on a manifest that was not fully authenticated.
func Check(ctx context.Context, opts Options) (Result, error) {
	ch := opts.Channel
	if ch == "" {
		ch = ChannelStable
	}
	if !ch.valid() {
		return Result{}, fmt.Errorf("unknown channel %q", ch)
	}
	res := Result{CurrentVersion: opts.Build.Version, Channel: string(ch)}

	if opts.Build.Kind != KindRelease {
		res.Status = StatusUnsupported
		res.Reason = "this is a development build, not a published release"
		return res, nil
	}
	current, err := ParseVersion(opts.Build.Version)
	if err != nil {
		res.Status = StatusUnsupported
		res.Reason = "the running build does not report a release version"
		return res, nil
	}

	roots := opts.Roots
	if roots == nil {
		roots = TrustRoots()
	}
	if len(roots) == 0 {
		return res, ErrNoTrustRoots
	}
	if opts.Source == nil {
		return res, errors.New("no update source configured")
	}
	repo := opts.Repo
	if repo == "" {
		repo = DefaultRepo
	}
	platform := opts.Platform
	if platform == (Platform{}) {
		platform = Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}
	}

	rel, err := opts.Source.Fetch(ctx, ch)
	if err != nil {
		return res, err
	}
	if _, err := Verify(rel.Manifest, rel.Signature, roots); err != nil {
		return res, err
	}
	m, err := ParseManifest(rel.Manifest)
	if err != nil {
		return res, err
	}
	if !ch.accepts(m.Channel) {
		return res, fmt.Errorf("%w: asked for %s, got %s", ErrChannelMismatch, ch, m.Channel)
	}
	if err := m.CheckURLs(repo); err != nil {
		return res, err
	}
	// Report the track the answer actually came from, so a beta check that lands on
	// a stable release does not describe it as a prerelease.
	res.Channel = string(m.Channel)

	available, err := ParseVersion(m.Version)
	if err != nil {
		return res, fmt.Errorf("%w: %v", ErrMalformedManifest, err)
	}
	res.AvailableVersion = m.Version
	res.ReleaseURL = m.ReleaseURL
	res.PublishedAt = m.PublishedAt

	switch Compare(available, current) {
	case -1:
		return res, fmt.Errorf("%w: %s is older than %s", ErrRollback, m.Version, opts.Build.Version)
	case 0:
		res.Status = StatusUpToDate
		return res, nil
	}

	a, err := m.Artifact(platform)
	if err != nil {
		return res, err
	}
	res.Status = StatusUpdateAvailable
	res.Artifact = &a
	return res, nil
}
