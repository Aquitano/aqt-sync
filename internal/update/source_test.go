package update

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
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
