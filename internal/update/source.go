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

// ErrGHUnavailable means the GitHub CLI is not installed or not usable. While the
// repository is private, release assets are only reachable through an
// authenticated client, so `gh` is a prerequisite for checking for updates.
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

// GHSource reads release metadata through the GitHub CLI, which carries the
// user's own credentials. That is what lets a private repository publish updates
// at all; when the repository is public, HTTPSource fetches the same bytes with no
// external tool.
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

// HTTPSource reads per-channel metadata from a static origin, e.g.
// https://aqt.sh/updates/stable.json. Used by tests today, and by clients once the
// archives are served from a public origin.
type HTTPSource struct {
	BaseURL string
	Client  *http.Client
}

func (h HTTPSource) Fetch(ctx context.Context, ch Channel) (Release, error) {
	base := strings.TrimRight(h.BaseURL, "/")
	manifest, err := h.get(ctx, base+"/"+string(ch)+".json", MaxManifestBytes)
	if err != nil {
		return Release{}, err
	}
	signature, err := h.get(ctx, base+"/"+string(ch)+".json.sig", MaxSignatureBytes)
	if err != nil {
		return Release{}, err
	}
	return Release{Manifest: manifest, Signature: signature}, nil
}

func (h HTTPSource) get(ctx context.Context, rawURL string, max int64) ([]byte, error) {
	client := h.Client
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
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Metadata is tiny and lives on one origin; a redirect to another host is
			// either a misconfiguration or a downgrade attempt, and the check is not
			// important enough to follow one.
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("refusing redirect to %s", req.URL.Host)
			}
			if len(via) > 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}
