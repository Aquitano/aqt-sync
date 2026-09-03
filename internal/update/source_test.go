// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSourceFetchesBothHalves(t *testing.T) {
	key := fixtureKey(t, seedA)
	manifest, signature := signFixture(t, fixtureManifest("v0.4.0", ChannelStable), key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable.json":
			_, _ = w.Write(manifest)
		case "/stable.json.sig":
			_, _ = w.Write(signature)
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
			_, _ = w.Write([]byte(oversized))
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
		_, _ = w.Write([]byte("{}"))
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
			_, _ = w.Write(manifest)
		case "/owner/repo/releases/latest/download/" + SignatureAssetName:
			_, _ = w.Write(signature)
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
		_, _ = w.Write([]byte(`[{"tag_name":"v0.5.0-rc.1"}]`))
	}))
	defer api.Close()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/repo/releases/download/v0.5.0-rc.1/" + ManifestAssetName:
			_, _ = w.Write(manifest)
		case "/owner/repo/releases/download/v0.5.0-rc.1/" + SignatureAssetName:
			_, _ = w.Write(signature)
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
				_, _ = w.Write([]byte(tc.body))
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
