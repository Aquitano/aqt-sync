// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestHTTPSourceFetchesBothHalves(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable.json":
			w.Write(manifest)
		case "/stable.json.sig":
			w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rel, err := HTTPSource{BaseURL: srv.URL + "/"}.Fetch(context.Background(), ChannelStable)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := Verify(rel.Manifest, rel.Signature, rootsOf(key)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestHTTPSourceFailsClosedOnBadResponses(t *testing.T) {
	oversized := strings.Repeat("x", MaxManifestBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/oversized"):
			w.Write([]byte(oversized))
		case strings.HasPrefix(r.URL.Path, "/broken"):
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	if _, err := (HTTPSource{BaseURL: srv.URL + "/missing"}).Fetch(context.Background(), ChannelStable); err == nil {
		t.Fatal("a 404 was accepted")
	}
	if _, err := (HTTPSource{BaseURL: srv.URL + "/broken"}).Fetch(context.Background(), ChannelStable); err == nil {
		t.Fatal("a 500 was accepted")
	}
	if _, err := (HTTPSource{BaseURL: srv.URL + "/oversized"}).Fetch(context.Background(), ChannelStable); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized body: got %v, want ErrTooLarge", err)
	}
}

// Metadata lives on one origin; a redirect to another host is either a
// misconfiguration or a downgrade attempt, and the check is not worth following one.
func TestHTTPSourceRefusesCrossHostRedirects(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	if _, err := (HTTPSource{BaseURL: srv.URL}).Fetch(context.Background(), ChannelStable); err == nil {
		t.Fatal("followed a redirect to another host")
	}
}

func TestGHSourceAsksForTheRightRelease(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)

	for _, tc := range []struct {
		channel         Channel
		wantPrereleases bool
	}{
		{ChannelStable, false},
		{ChannelBeta, true},
	} {
		t.Run(string(tc.channel), func(t *testing.T) {
			var seen [][]string
			src := GHSource{
				Repo: DefaultRepo,
				Run: func(_ context.Context, _ int64, args ...string) ([]byte, error) {
					seen = append(seen, args)
					switch {
					case args[1] == "list":
						return []byte(`[{"tagName":"v0.4.0"}]`), nil
					case slices.Contains(args, ManifestAssetName):
						return manifest, nil
					case slices.Contains(args, SignatureAssetName):
						return signature, nil
					}
					t.Fatalf("unexpected gh call %v", args)
					return nil, nil
				},
			}
			rel, err := src.Fetch(context.Background(), tc.channel)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if _, err := Verify(rel.Manifest, rel.Signature, rootsOf(key)); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if len(seen) != 3 {
				t.Fatalf("made %d gh calls, want 3", len(seen))
			}
			excluded := slices.Contains(seen[0], "--exclude-pre-releases")
			if excluded == tc.wantPrereleases {
				t.Fatalf("%s asked gh for %v", tc.channel, seen[0])
			}
			for _, args := range seen[1:] {
				if !slices.Contains(args, "v0.4.0") {
					t.Fatalf("downloaded from the wrong release: %v", args)
				}
			}
		})
	}
}

func TestGHSourceFailsClosedOnUnusableReleases(t *testing.T) {
	cases := []struct {
		name string
		run  func(context.Context, int64, ...string) ([]byte, error)
		want error
	}{
		{
			name: "no releases",
			run:  func(context.Context, int64, ...string) ([]byte, error) { return []byte(`[]`), nil },
			want: ErrNoRelease,
		},
		{
			name: "tag is not a version",
			run: func(_ context.Context, _ int64, args ...string) ([]byte, error) {
				return []byte(`[{"tagName":"nightly"}]`), nil
			},
			want: ErrBadVersion,
		},
		{
			name: "gh is missing",
			run: func(context.Context, int64, ...string) ([]byte, error) {
				return nil, ErrGHUnavailable
			},
			want: ErrGHUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GHSource{Repo: DefaultRepo, Run: tc.run}.Fetch(context.Background(), ChannelStable)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGHSourceRejectsAnEmptyAsset(t *testing.T) {
	_, err := GHSource{
		Repo: DefaultRepo,
		Run: func(_ context.Context, _ int64, args ...string) ([]byte, error) {
			if args[1] == "list" {
				return []byte(`[{"tagName":"v0.4.0"}]`), nil
			}
			return nil, nil
		},
	}.Fetch(context.Background(), ChannelStable)
	if err == nil || !strings.Contains(err.Error(), ManifestAssetName) {
		t.Fatalf("got %v, want a complaint about the missing manifest asset", err)
	}
}

// The real runner is what users hit; check that a missing gh produces the
// actionable error rather than an exec failure nobody can act on.
func TestRunGHReportsAMissingBinary(t *testing.T) {
	if _, err := exec.LookPath("gh"); err == nil {
		t.Skip("gh is installed; the missing-binary path cannot be exercised here")
	}
	if _, err := runGH(context.Background(), 1<<10, "release", "list"); !errors.Is(err, ErrGHUnavailable) {
		t.Fatalf("got %v, want ErrGHUnavailable", err)
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

// The stable channel must resolve through GitHub's "latest" redirect, which is
// defined as the newest non-prerelease. Going through the API instead would spend
// the unauthenticated rate limit on the one check every client makes routinely.
func TestGHWebSourceStableUsesLatestWithoutTheAPI(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	var apiCalls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		http.NotFound(w, r)
	}))
	defer api.Close()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/latest/download/" + ManifestAssetName:
			w.Write(manifest)
		case "/owner/repo/releases/latest/download/" + SignatureAssetName:
			w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
	defer web.Close()

	src := GHWebSource{Repo: "owner/repo", WebBase: web.URL, APIBase: api.URL}
	rel, err := src.Fetch(context.Background(), ChannelStable)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := Verify(rel.Manifest, rel.Signature, rootsOf(key)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if apiCalls != 0 {
		t.Fatalf("a stable check made %d API calls; it must need none", apiCalls)
	}
}

// Beta is a superset that must see prereleases, which no static URL exposes, so it
// resolves the newest tag through the API and then reads that tag's assets.
func TestGHWebSourceBetaResolvesThroughTheAPI(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.5.0-rc.1", ChannelBeta), key)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"tag_name":"v0.5.0-rc.1"}]`))
	}))
	defer api.Close()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v0.5.0-rc.1/" + ManifestAssetName:
			w.Write(manifest)
		case "/owner/repo/releases/download/v0.5.0-rc.1/" + SignatureAssetName:
			w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
	defer web.Close()

	src := GHWebSource{Repo: "owner/repo", WebBase: web.URL, APIBase: api.URL}
	rel, err := src.Fetch(context.Background(), ChannelBeta)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := Verify(rel.Manifest, rel.Signature, rootsOf(key)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestGHWebSourceFailsClosedOnUnusableReleaseLists(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{
		{"empty", `[]`, ErrNoRelease},
		{"not a version", `[{"tag_name":"nightly"}]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer api.Close()
			src := GHWebSource{Repo: "owner/repo", WebBase: "https://example.invalid", APIBase: api.URL}
			_, err := src.Fetch(context.Background(), ChannelBeta)
			if err == nil {
				t.Fatal("an unusable release list was accepted")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A GitHub release download always leaves github.com for a signed, expiring asset
// host. Refusing that hop would make every real download fail, so the one pair is
// allowed and everything else still is not.
func TestCheckRedirectAllowsOnlyGitHubsAssetHop(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		allow    bool
	}{
		{"https://github.com/o/r/releases/latest/download/a", "https://release-assets.githubusercontent.com/x", true},
		{"https://github.com/o/r/releases/latest/download/a", "https://objects.githubusercontent.com/x", true},
		{"https://api.github.com/repos/o/r/releases", "https://githubusercontent.com/x", true},
		{"https://github.com/o/r/releases/latest/download/a", "https://evilgithubusercontent.com/x", false},
		{"https://github.com/o/r/releases/latest/download/a", "https://example.com/x", false},
		{"https://updates.example.com/stable.json", "https://cdn.example.net/stable.json", false},
		{"https://updates.example.com/stable.json", "https://updates.example.com/other.json", true},
		{"https://updates.example.com/stable.json", "http://updates.example.com/stable.json", false},
		{"https://github.com/o/r/releases/latest/download/a", "http://objects.githubusercontent.com/x", false},
	} {
		from := httptest.NewRequest(http.MethodGet, tc.from, nil)
		to := httptest.NewRequest(http.MethodGet, tc.to, nil)
		err := checkRedirect(to, []*http.Request{from})
		if tc.allow && err != nil {
			t.Errorf("%s -> %s: refused (%v), want allowed", tc.from, tc.to, err)
		}
		if !tc.allow && err == nil {
			t.Errorf("%s -> %s: allowed, want refused", tc.from, tc.to)
		}
	}
}

func TestFallbackSourceUsesTheFirstSourceThatWorks(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(signature)
			return
		}
		w.Write(manifest)
	}))
	defer good.Close()

	src := FallbackSource{Sources: []ReleaseSource{
		HTTPSource{BaseURL: "https://example.invalid"},
		HTTPSource{BaseURL: good.URL},
	}}
	rel, err := src.Fetch(context.Background(), ChannelStable)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := Verify(rel.Manifest, rel.Signature, rootsOf(key)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Every source reports why it failed. Collapsing them to the last error would hide
// the one the user can act on, which is usually the first.
func TestFallbackSourceReportsEveryFailure(t *testing.T) {
	src := FallbackSource{Sources: []ReleaseSource{
		HTTPSource{BaseURL: "https://first.invalid"},
		HTTPSource{BaseURL: "https://second.invalid"},
	}}
	_, err := src.Fetch(context.Background(), ChannelStable)
	if err == nil {
		t.Fatal("all sources failed but Fetch succeeded")
	}
	for _, want := range []string{"first.invalid", "second.invalid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q omits %s", err, want)
		}
	}
}

// A source that dies mid-stream has already written bytes the next one would append
// to. Falling back there produces a corrupt archive, so it must stop instead.
func TestFallbackSourceDoesNotRetryAfterAPartialWrite(t *testing.T) {
	partial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "64")
		w.Write([]byte("half"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // cut the connection mid-body
	}))
	defer partial.Close()

	var secondTried bool
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondTried = true
		w.Write([]byte("whole"))
	}))
	defer second.Close()

	var got strings.Builder
	src := FallbackSource{Sources: []ReleaseSource{
		HTTPSource{BaseURL: partial.URL},
		HTTPSource{BaseURL: second.URL},
	}}
	err := src.FetchArtifact(context.Background(), "v0.4.0", Artifact{URL: partial.URL + "/a.tar.gz"}, &got)
	if err == nil {
		t.Fatal("a truncated download was reported as success")
	}
	if secondTried {
		t.Fatal("fell back after a partial write; the archive would be the two responses concatenated")
	}
}

// The workflow publishes the assets these constants name. If either side is renamed
// alone, every client's update check 404s against a release that looks fine.
func TestReleaseWorkflowPublishesTheAssetNamesClientsFetch(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Skipf("release workflow not readable: %v", err)
	}
	for _, name := range []string{ManifestAssetName, SignatureAssetName} {
		if !strings.Contains(string(wf), name) {
			t.Errorf("release.yml never mentions %q, so no release publishes it", name)
		}
	}
}
