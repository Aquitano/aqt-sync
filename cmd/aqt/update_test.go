// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/update"
)

// updateFixtureSeed is fixed so the CLI tests never depend on a real signing key
// and never reach GitHub.
const updateFixtureSeed = "aqt update cli fixture signing k" // exactly ed25519.SeedSize bytes

// serveUpdateFixture publishes a signed manifest for one version on a local origin
// and points the CLI at it, standing in for the release assets. It also gives the
// test its own update store, since runUpdate persists the freshness ceiling there.
func serveUpdateFixture(t *testing.T, released string) update.Store {
	t.Helper()
	store := withUpdateStore(t)
	serveUpdateManifest(t, released)
	return store
}

// serveUpdateManifest is serveUpdateFixture without the store isolation, so a
// test can change the served version while keeping the recorded state.
func serveUpdateManifest(t *testing.T, released string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(updateFixtureSeed))

	m := update.Manifest{
		Schema:      update.ManifestSchema,
		Channel:     update.ChannelStable,
		Version:     released,
		PublishedAt: "2026-07-26T11:00:00Z",
		ReleaseURL:  update.ReleaseTagURL(update.DefaultRepo, released),
	}
	for _, p := range update.Platforms {
		name := update.ArchiveName(released, p)
		m.Artifacts = append(m.Artifacts, update.Artifact{
			OS:     p.OS,
			Arch:   p.Arch,
			Name:   name,
			Size:   9_000_000,
			SHA256: strings.Repeat("ab12cd34", 8),
			URL:    update.AssetURL(update.DefaultRepo, released, name),
		})
	}
	manifest, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := update.SignManifest(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := signature.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		// The beta path serves the same stable-channel manifest: beta is a
		// superset of stable, so this mirrors the common state where no
		// prerelease is outstanding and a --prerelease check lands on stable.
		case "/stable.json", "/beta.json":
			w.Write(manifest)
		case "/stable.json.sig", "/beta.json.sig":
			w.Write(sigBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv(updateBaseURLEnv, srv.URL)

	pub := key.Public().(ed25519.PublicKey)
	roots := []update.TrustRoot{{KeyID: update.KeyID(pub), PublicKey: pub}}
	orig := updateTrustRoots
	updateTrustRoots = func() []update.TrustRoot { return roots }
	t.Cleanup(func() { updateTrustRoots = orig })
}

// requirePublishedPlatform skips a test that expects to resolve an archive when
// the machine running it is not one the release publishes for. Failing closed
// there is correct behavior, not a broken test.
func requirePublishedPlatform(t *testing.T) {
	t.Helper()
	here := update.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if !slices.Contains(update.Platforms, here) {
		t.Skipf("no release build for %s", here)
	}
}

// withBuild pretends this binary is a released build of the given version.
func withBuild(t *testing.T, v, kind string) {
	t.Helper()
	origVersion, origKind := version, buildKind
	version, buildKind = v, kind
	t.Cleanup(func() { version, buildKind = origVersion, origKind })
}

func TestUpdateCheckJSONContract(t *testing.T) {
	requirePublishedPlatform(t)
	serveUpdateFixture(t, "v9.9.9")
	withBuild(t, "v0.3.0", update.KindRelease)

	out := captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true, asJSON: true}); err != nil {
			t.Fatalf("update --check --json: %v", err)
		}
	})
	var got struct {
		CurrentVersion   string `json:"currentVersion"`
		AvailableVersion string `json:"availableVersion"`
		Channel          string `json:"channel"`
		Status           string `json:"status"`
		ReleaseURL       string `json:"releaseUrl"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if got.CurrentVersion != "v0.3.0" || got.AvailableVersion != "v9.9.9" {
		t.Fatalf("versions = %q -> %q", got.CurrentVersion, got.AvailableVersion)
	}
	if got.Status != update.StatusUpdateAvailable {
		t.Fatalf("status = %q", got.Status)
	}
	if got.Channel != string(update.ChannelStable) {
		t.Fatalf("channel = %q", got.Channel)
	}
	if !strings.HasSuffix(got.ReleaseURL, "/releases/tag/v9.9.9") {
		t.Fatalf("releaseUrl = %q", got.ReleaseURL)
	}
}

func TestUpdateCheckReportsTheAvailableAssetForThisPlatform(t *testing.T) {
	requirePublishedPlatform(t)
	serveUpdateFixture(t, "v9.9.9")
	withBuild(t, "v0.3.0", update.KindRelease)

	out := captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true}); err != nil {
			t.Fatalf("update --check: %v", err)
		}
	})
	if !strings.Contains(out, "v0.3.0 -> v9.9.9") {
		t.Fatalf("output does not show the transition:\n%s", out)
	}
	// The client archive, never the aqt-server archive published beside it.
	if !strings.Contains(out, "aqt_v9.9.9_") || strings.Contains(out, "aqt-server") {
		t.Fatalf("output names the wrong asset:\n%s", out)
	}
}

func TestUpdateCheckReportsUpToDate(t *testing.T) {
	serveUpdateFixture(t, "v0.3.0")
	withBuild(t, "v0.3.0", update.KindRelease)

	out := captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true}); err != nil {
			t.Fatalf("update --check: %v", err)
		}
	})
	if !strings.Contains(out, "latest stable release") {
		t.Fatalf("output does not report being current:\n%s", out)
	}
}

// A source build must say so and offer no way to overwrite itself, without
// contacting anything to find out.
func TestUpdateCheckRefusesToActOnADevelopmentBuild(t *testing.T) {
	withUpdateStore(t)
	t.Setenv(updateBaseURLEnv, "https://127.0.0.1:1/never-reached")
	withBuild(t, "0.3.0-dev", "dev")

	out := captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true}); err != nil {
			t.Fatalf("update --check: %v", err)
		}
	})
	if !strings.Contains(out, "development build") {
		t.Fatalf("output does not name the problem:\n%s", out)
	}
}

// A published release older than the running build is refused rather than offered.
func TestUpdateCheckRefusesARollback(t *testing.T) {
	serveUpdateFixture(t, "v0.2.0")
	withBuild(t, "v0.3.0", update.KindRelease)

	if err := runUpdate(updateOptions{checkOnly: true}); err == nil {
		t.Fatal("a downgrade was reported as an update")
	}
}

// A signed manifest can be replayed: one older than the newest release this
// machine ever authenticated — yet newer than the running build, so ErrRollback
// is blind to it — must be refused, and `--accept-rollback` is the deliberate
// way through after a real upstream retraction.
func TestUpdateRefusesAReplayedOlderManifest(t *testing.T) {
	requirePublishedPlatform(t)
	store := serveUpdateFixture(t, "v0.5.0")
	withBuild(t, "v0.3.0", update.KindRelease)

	captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true}); err != nil {
			t.Fatalf("first check: %v", err)
		}
	})
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Ceiling(update.ChannelStable); got != "v0.5.0" {
		t.Fatalf("ceiling after first check = %q, want v0.5.0", got)
	}

	// Upstream now serves v0.4.0 — newer than the running v0.3.0, older than the
	// authenticated v0.5.0. Before the ceiling this replay was offered as an update.
	serveUpdateManifest(t, "v0.4.0")
	err = runUpdate(updateOptions{checkOnly: true})
	if !errors.Is(err, update.ErrStaleManifest) {
		t.Fatalf("replayed manifest: got %v, want ErrStaleManifest", err)
	}
	if !strings.Contains(err.Error(), "--accept-rollback") {
		t.Fatalf("stale-manifest error does not name the recovery flag: %v", err)
	}

	// --check --accept-rollback bypasses the floor for the report but commits
	// nothing: acceptance means actually taking the older release, so a mere
	// report — or a run the user declines partway — must leave the old ceiling
	// standing (else a mistaken origin could lower it durably with no install).
	captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true, acceptRollback: true}); err != nil {
			t.Fatalf("--accept-rollback --check: %v", err)
		}
	})
	assertCeiling := func(want string) {
		t.Helper()
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Ceiling(update.ChannelStable); got != want {
			t.Fatalf("ceiling = %q, want %q", got, want)
		}
	}
	assertCeiling("v0.5.0")
	if err := runUpdate(updateOptions{checkOnly: true}); !errors.Is(err, update.ErrStaleManifest) {
		t.Fatalf("plain check after --accept-rollback --check: got %v, want the refusal to persist", err)
	}

	// An install run that aborts before completing (here: the test binary is not
	// a replaceable release install / no terminal to confirm) commits nothing.
	var insErr error
	captureStdout(t, func() { insErr = runUpdate(updateOptions{acceptRollback: true}) })
	if insErr == nil {
		t.Fatal("install run unexpectedly succeeded in a test environment")
	}
	assertCeiling("v0.5.0")

	// The machine already running the retracted-to version: accepting confirms
	// it, lowers the record, and later plain checks pass clean.
	withBuild(t, "v0.4.0", update.KindRelease)
	captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true, acceptRollback: true}); err != nil {
			t.Fatalf("--accept-rollback on the running version: %v", err)
		}
	})
	assertCeiling("v0.4.0")
	captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true}); err != nil {
			t.Fatalf("check after accepted rollback: %v", err)
		}
	})
}

// A --prerelease check that lands on a stable release (the common case: no
// prerelease outstanding) must raise the stable ceiling too — background checks
// are stable-only, and a prerelease-track user would otherwise never establish
// the floor they consult.
func TestBetaCheckRaisesTheStableCeiling(t *testing.T) {
	requirePublishedPlatform(t)
	store := serveUpdateFixture(t, "v0.5.0")
	withBuild(t, "v0.3.0", update.KindRelease)

	captureStdout(t, func() {
		if err := runUpdate(updateOptions{checkOnly: true, prerelease: true}); err != nil {
			t.Fatalf("beta check: %v", err)
		}
	})
	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Ceiling(update.ChannelBeta); got != "v0.5.0" {
		t.Fatalf("beta ceiling = %q, want v0.5.0", got)
	}
	if got := st.Ceiling(update.ChannelStable); got != "v0.5.0" {
		t.Fatalf("stable ceiling after a beta check on a stable release = %q, want v0.5.0", got)
	}
}

func TestUpdateCommandSurface(t *testing.T) {
	root := rootCmd()
	cmd := subcommand(t, root, "update")
	if cmd.Annotations[jsonAnnotation] == "" {
		t.Error("`aqt update` does not advertise --json support")
	}
	for _, name := range []string{"check", "prerelease", "yes", "accept-rollback"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("`aqt update` is missing --%s", name)
		}
	}
	if subcommand(t, cmd, "policy") == nil {
		t.Error("`aqt update policy` is missing")
	}
	// The default build is a source build, so nothing shipped from this tree can
	// present itself as an installable release.
	if buildKind == update.KindRelease {
		t.Error("buildKind defaults to release; a source build would offer to update itself")
	}
}
