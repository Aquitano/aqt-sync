package update

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// ErrGHUnavailable means the GitHub CLI is not installed or not usable. It is no
// longer a prerequisite for the public repository — GHWebSource reads the same
// assets over plain HTTPS — but a private fork still needs an authenticated client.
var ErrGHUnavailable = errors.New("the GitHub CLI (gh) is required to check for updates")

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
// channel metadata and the archive it names. Every implementation here satisfies
// both, so FallbackSource can carry a single ordered list.
type ReleaseSource interface {
	Source
	ArtifactSource
}

// GHSource reads release metadata through the GitHub CLI, which carries the user's
// own credentials. That is what lets a *private* repository publish updates at all.
// This repository is public, so GHWebSource is the default and this is the fallback
// that keeps a private fork or mirror working.
type GHSource struct {
	Repo string
	// Run executes gh and returns its stdout, bounded to max bytes. Tests
	// substitute it so no gh binary or network is involved.
	Run func(ctx context.Context, max int64, args ...string) ([]byte, error)
	// RunStream executes gh and pipes its stdout to w, for payloads too large to
	// hold in memory. Tests substitute it for the same reason as Run.
	RunStream func(ctx context.Context, w io.Writer, args ...string) error
}

func (g GHSource) Fetch(ctx context.Context, ch Channel) (Release, error) {
	run := g.Run
	if run == nil {
		run = runGH
	}
	list := []string{"release", "list", "--repo", g.Repo, "--limit", "1", "--exclude-drafts", "--json", "tagName"}
	if ch == ChannelStable {
		// The newest release overall may be a prerelease; the stable channel must not
		// see it. gh filters server-side, and the signed channel field is re-checked
		// afterwards so this flag is a convenience, not the security boundary.
		list = append(list, "--exclude-pre-releases")
	}
	out, err := run(ctx, 64<<10, list...)
	if err != nil {
		return Release{}, err
	}
	var releases []struct {
		TagName string `json:"tagName"`
	}
	if err := json.Unmarshal(out, &releases); err != nil {
		return Release{}, fmt.Errorf("gh release list: %w", err)
	}
	if len(releases) == 0 {
		return Release{}, ErrNoRelease
	}
	tag := releases[0].TagName
	if _, err := ParseVersion(tag); err != nil {
		return Release{}, fmt.Errorf("release tag %q is not a version: %w", tag, err)
	}

	manifest, err := g.download(ctx, run, tag, ManifestAssetName, MaxManifestBytes)
	if err != nil {
		return Release{}, err
	}
	signature, err := g.download(ctx, run, tag, SignatureAssetName, MaxSignatureBytes)
	if err != nil {
		return Release{}, err
	}
	return Release{Manifest: manifest, Signature: signature}, nil
}

func (g GHSource) download(ctx context.Context, run func(context.Context, int64, ...string) ([]byte, error), tag, asset string, max int64) ([]byte, error) {
	out, err := run(ctx, max, "release", "download", tag, "--repo", g.Repo, "--pattern", asset, "--output", "-")
	if err != nil {
		return nil, fmt.Errorf("downloading %s from %s: %w", asset, tag, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("release %s publishes no %s", tag, asset)
	}
	return out, nil
}

// runGH invokes gh with a fixed argument vector (never a shell), a bounded stdout,
// and no inherited stdin, so a hung or chatty child cannot stall or flood the CLI.
func runGH(ctx context.Context, max int64, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "gh", args...)
	stdout := &capWriter{max: max}
	stderr := &capWriter{max: 4 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%w: install it from https://cli.github.com and run `gh auth login`", ErrGHUnavailable)
		}
		if stdout.over {
			return nil, fmt.Errorf("%w: gh returned more than %d bytes", ErrTooLarge, max)
		}
		if msg := strings.TrimSpace(stderr.buf.String()); msg != "" {
			return nil, fmt.Errorf("gh %s: %v: %s", args[0], err, msg)
		}
		return nil, fmt.Errorf("gh %s: %w", args[0], err)
	}
	return stdout.buf.Bytes(), nil
}

// capWriter refuses to buffer more than max bytes, which stops a hostile or broken
// child process from being read into memory without limit.
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

// FallbackSource tries its sources in order and returns the first that succeeds.
// Every source is checked against the same signature and the same pinned URLs, so
// the order decides reachability, never trust.
type FallbackSource struct {
	Sources []ReleaseSource
}

func (f FallbackSource) Fetch(ctx context.Context, ch Channel) (Release, error) {
	var errs []error
	for _, s := range f.Sources {
		rel, err := s.Fetch(ctx, ch)
		if err == nil {
			return rel, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return Release{}, errors.New("no update source configured")
	}
	return Release{}, errors.Join(errs...)
}

func (f FallbackSource) FetchArtifact(ctx context.Context, version string, a Artifact, w io.Writer) error {
	var errs []error
	for _, s := range f.Sources {
		probe := &wroteAny{w: w}
		err := s.FetchArtifact(ctx, version, a, probe)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		// A source that failed mid-stream has already put bytes in the destination.
		// Another attempt would append to them rather than replace them, so the only
		// safe fallback is one that got nowhere. The size and hash checks would catch
		// the damage regardless; stopping here reports the real error instead.
		if probe.wrote {
			break
		}
	}
	if len(errs) == 0 {
		return errors.New("no update source configured")
	}
	return errors.Join(errs...)
}

// wroteAny records whether anything reached the underlying writer.
type wroteAny struct {
	w     io.Writer
	wrote bool
}

func (p *wroteAny) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 {
		p.wrote = true
	}
	return n, err
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
	defer resp.Body.Close()
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
