// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNoRelease means the channel has no published release yet.
var ErrNoRelease = errors.New("no published release found for this channel")

// Release is the signed metadata pair for one published release, exactly as
// fetched. Both halves are untrusted bytes until Verify accepts them.
type Release struct {
	Manifest  []byte
	Signature []byte
}

// Source fetches release metadata for a channel. Implementations do not
// authenticate anything: the signature is what makes the bytes trustworthy, so a
// hostile transport cannot do worse than fail the check.
type Source interface {
	Fetch(ctx context.Context, ch Channel) (Release, error)
}

// ReleaseSource is one transport that can supply both halves of an update: the
// channel metadata and the archive it names.
type ReleaseSource interface {
	Source
	ArtifactSource
}

// GHWebSource reads release metadata from GitHub's public release endpoints with
// no external tool. The manifest and its signature are published as fixed-name
// assets on every release, so a download needs no API token and no credentials.
type GHWebSource struct {
	Repo string
	// WebBase and APIBase default to GitHub's own hosts. Tests point them at a local
	// server so no network is involved.
	WebBase string
	APIBase string
	Client  *http.Client
}

const (
	githubWebBase = "https://github.com"
	githubAPIBase = "https://api.github.com"
)

func (g GHWebSource) Fetch(ctx context.Context, ch Channel) (Release, error) {
	base, err := g.assetBase(ctx, ch)
	if err != nil {
		return Release{}, err
	}
	manifest, err := getURL(ctx, g.Client, base+"/"+ManifestAssetName, MaxManifestBytes)
	if err != nil {
		return Release{}, err
	}
	signature, err := getURL(ctx, g.Client, base+"/"+SignatureAssetName, MaxSignatureBytes)
	if err != nil {
		return Release{}, err
	}
	return Release{Manifest: manifest, Signature: signature}, nil
}

// FetchArtifact streams a release archive from the URL the signed manifest names.
func (g GHWebSource) FetchArtifact(ctx context.Context, _ string, a Artifact, w io.Writer) error {
	return streamURL(ctx, g.Client, a.URL, w)
}

// assetBase resolves the directory the channel's assets live under.
func (g GHWebSource) assetBase(ctx context.Context, ch Channel) (string, error) {
	web := strings.TrimRight(orDefault(g.WebBase, githubWebBase), "/")
	if ch == ChannelStable {
		// GitHub's "latest" release is by definition the newest non-prerelease, which
		// is exactly the stable channel's rule. Resolving it is a plain redirect, so
		// the common check costs no API call and cannot be rate limited.
		return web + "/" + g.Repo + "/releases/latest/download", nil
	}
	tag, err := g.latestTag(ctx)
	if err != nil {
		return "", err
	}
	return web + "/" + g.Repo + "/releases/download/" + tag, nil
}

// latestTag finds the newest release including prereleases, which no static URL
// exposes. Only the opt-in beta channel needs it, so the unauthenticated API's
// per-IP rate limit is not on the path of a routine stable check.
func (g GHWebSource) latestTag(ctx context.Context) (string, error) {
	api := strings.TrimRight(orDefault(g.APIBase, githubAPIBase), "/")
	body, err := getURL(ctx, g.Client, api+"/repos/"+g.Repo+"/releases?per_page=1", MaxManifestBytes)
	if err != nil {
		return "", err
	}
	// The REST API spells this tag_name, unlike the gh CLI's tagName.
	var releases []struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", fmt.Errorf("listing releases: %w", err)
	}
	if len(releases) == 0 {
		return "", ErrNoRelease
	}
	tag := releases[0].TagName
	if _, err := ParseVersion(tag); err != nil {
		return "", fmt.Errorf("release tag %q is not a version: %w", tag, err)
	}
	return tag, nil
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// HTTPSource reads per-channel metadata from a static origin serving
// <base>/stable.json and <base>/stable.json.sig. It is how the tests run and how a
// self-hoster or mirror points clients at their own origin (AQT_UPDATE_BASE_URL).
type HTTPSource struct {
	BaseURL string
	Client  *http.Client
}

func (h HTTPSource) Fetch(ctx context.Context, ch Channel) (Release, error) {
	base := strings.TrimRight(h.BaseURL, "/")
	manifest, err := getURL(ctx, h.Client, base+"/"+string(ch)+".json", MaxManifestBytes)
	if err != nil {
		return Release{}, err
	}
	signature, err := getURL(ctx, h.Client, base+"/"+string(ch)+".json.sig", MaxSignatureBytes)
	if err != nil {
		return Release{}, err
	}
	return Release{Manifest: manifest, Signature: signature}, nil
}

func getURL(ctx context.Context, client *http.Client, rawURL string, max int64) ([]byte, error) {
	if client == nil {
		client = defaultHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	// One byte past the cap distinguishes "exactly at the limit" from "truncated".
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, rawURL, max)
	}
	return b, nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: checkRedirect,
	}
}

// checkRedirect keeps a fetch on the origin it started from, except for the one
// cross-host hop a GitHub release download always takes: github.com answers with a
// redirect to a signed, expiring *.githubusercontent.com asset URL. Following it is
// required for any download from a GitHub release, and is safe because the manifest
// is signature-checked and every archive is size- and hash-checked against it — the
// host rule is hygiene against misconfiguration, not the trust boundary.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 5 {
		return errors.New("too many redirects")
	}
	// A fetch that started over TLS stays over TLS. The bytes are verified either
	// way, but a downgrade would hand the plaintext of what this client is asking
	// for to anyone on the path.
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect from https to %s", req.URL.Scheme)
	}
	// Host, not Hostname: a different port on the same name is still a different
	// origin, and two local test servers differ only there.
	if strings.EqualFold(via[0].URL.Host, req.URL.Host) {
		return nil
	}
	if isGitHubHost(via[0].URL.Hostname()) && isGitHubAssetHost(req.URL.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing redirect to %s", req.URL.Host)
}

func isGitHubHost(host string) bool {
	return strings.EqualFold(host, "github.com") || strings.EqualFold(host, "api.github.com")
}

// isGitHubAssetHost matches githubusercontent.com and its subdomains only. The
// leading dot is what keeps a lookalike like evilgithubusercontent.com out.
func isGitHubAssetHost(host string) bool {
	host = strings.ToLower(host)
	return host == "githubusercontent.com" || strings.HasSuffix(host, ".githubusercontent.com")
}
