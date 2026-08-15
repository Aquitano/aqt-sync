// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func checkFixture(t *testing.T, build Build, ch Channel, src Source, keys ...ed25519.PrivateKey) (Result, error) {
	t.Helper()
	return Check(context.Background(), Options{
		Build:    build,
		Channel:  ch,
		Source:   src,
		Roots:    rootsOf(keys...),
		Platform: linuxAMD64,
	})
}

func TestCheckReportsAnAvailableUpdate(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)

	res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, src, key)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Status != StatusUpdateAvailable {
		t.Fatalf("status = %q, want %q", res.Status, StatusUpdateAvailable)
	}
	if res.CurrentVersion != "v0.3.0" || res.AvailableVersion != "v0.4.0" {
		t.Fatalf("versions = %q -> %q", res.CurrentVersion, res.AvailableVersion)
	}
	if res.Channel != string(ChannelStable) {
		t.Fatalf("channel = %q", res.Channel)
	}
	if res.ReleaseURL != "https://github.com/"+DefaultRepo+"/releases/tag/v0.4.0" {
		t.Fatalf("releaseUrl = %q", res.ReleaseURL)
	}
	if res.Artifact == nil || res.Artifact.Name != "aqt_v0.4.0_linux_amd64.tar.gz" {
		t.Fatalf("artifact = %+v", res.Artifact)
	}
}

func TestCheckReportsUpToDate(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)

	res, err := checkFixture(t, releaseBuild("v0.4.0"), ChannelStable, src, key)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Status != StatusUpToDate {
		t.Fatalf("status = %q, want %q", res.Status, StatusUpToDate)
	}
}

// A manifest naming an older release is either a replay or a mistaken republish.
// Either way it must not move anyone backwards, so it is refused rather than
// reported as an "update".
func TestCheckRefusesARollback(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.3.0", ChannelStable), key)

	_, err := checkFixture(t, releaseBuild("v0.4.0"), ChannelStable, src, key)
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

func TestCheckRefusesTamperedMetadata(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)
	src.manifest = bytes.Replace(src.manifest, []byte("v0.4.0"), []byte("v9.9.9"), 1)

	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, src, key); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestCheckRefusesAnUnknownSigningKey(t *testing.T) {
	attacker := fixtureKey(t, seedC)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), attacker)

	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, src, fixtureKey(t, seedA)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
}

// The rotation story end to end: during the overlap a release is signed by both
// keys and every supported client accepts it.
func TestCheckAcceptsAReleaseSignedDuringAKeyRotation(t *testing.T) {
	outgoing, incoming := fixtureKey(t, seedA), fixtureKey(t, seedB)
	m := fixtureManifest("v0.4.0", ChannelStable)

	for _, tc := range []struct {
		name  string
		roots []ed25519.PrivateKey
	}{
		{"client from before the rotation", []ed25519.PrivateKey{outgoing}},
		{"client from after the rotation", []ed25519.PrivateKey{incoming}},
		{"client that carries both", []ed25519.PrivateKey{outgoing, incoming}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := sourceFor(t, m, outgoing, incoming)
			res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, src, tc.roots...)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if res.Status != StatusUpdateAvailable {
				t.Fatalf("status = %q", res.Status)
			}
		})
	}
}

func TestCheckKeepsPrereleasesOffTheStableChannel(t *testing.T) {
	key := fixtureKey(t, seedA)

	// The default channel is stable, and the source is asked for stable.
	stable := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), "", stable, key); err != nil {
		t.Fatalf("default channel: %v", err)
	}
	if stable.channel != ChannelStable {
		t.Fatalf("default channel asked the source for %q", stable.channel)
	}

	// A prerelease is only reachable by asking for it.
	beta := sourceFor(t, fixtureManifest("v0.4.0-rc.1", ChannelBeta), key)
	res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelBeta, beta, key)
	if err != nil {
		t.Fatalf("beta channel: %v", err)
	}
	if res.AvailableVersion != "v0.4.0-rc.1" || res.Channel != string(ChannelBeta) {
		t.Fatalf("beta result = %+v", res)
	}

	// A beta manifest served to a stable check is refused even though it is
	// authentic: the channel is part of what was signed.
	crossed := sourceFor(t, fixtureManifest("v0.4.0-rc.1", ChannelBeta), key)
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, crossed, key); !errors.Is(err, ErrChannelMismatch) {
		t.Fatalf("got %v, want ErrChannelMismatch", err)
	}

	// And a stable manifest cannot smuggle a prerelease in through its version.
	smuggled := sourceFor(t, fixtureManifest("v0.4.0-rc.1", ChannelStable), key)
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, smuggled, key); !errors.Is(err, ErrMalformedManifest) {
		t.Fatalf("got %v, want ErrMalformedManifest", err)
	}
}

// Beta carries stable releases as well as prereleases, and the newest release is
// a stable one most of the time. Refusing it would make `--prerelease` fail for
// everyone whenever no prerelease is outstanding.
func TestCheckOnBetaAcceptsAStableRelease(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)

	res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelBeta, src, key)
	if err != nil {
		t.Fatalf("beta check against a stable release: %v", err)
	}
	if res.Status != StatusUpdateAvailable || res.AvailableVersion != "v0.4.0" {
		t.Fatalf("result = %+v", res)
	}
	// The reported channel is where the release came from, not what was asked for.
	if res.Channel != string(ChannelStable) {
		t.Fatalf("channel = %q, want %q", res.Channel, ChannelStable)
	}
}

// Every release publishes an aqt-server archive whose name differs from the client
// archive by five characters. Nothing in the check may select it.
func TestCheckNeverSelectsTheServerArchive(t *testing.T) {
	key := fixtureKey(t, seedA)

	m := fixtureManifest("v0.4.0", ChannelStable)
	for i := range m.Artifacts {
		if m.Artifacts[i].Platform() == linuxAMD64 {
			m.Artifacts[i].Name = strings.Replace(m.Artifacts[i].Name, "aqt_", "aqt-server_", 1)
			m.Artifacts[i].URL = strings.Replace(m.Artifacts[i].URL, "aqt_", "aqt-server_", 1)
		}
	}
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, m, key), key); !errors.Is(err, ErrMalformedManifest) {
		t.Fatalf("got %v, want ErrMalformedManifest", err)
	}

	// The archive name is derived per platform, so a well-formed manifest resolves
	// to the client build and there is no slot an aqt-server archive could occupy.
	ok := fixtureManifest("v0.4.0", ChannelStable)
	res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, ok, key), key)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !strings.HasPrefix(res.Artifact.Name, "aqt_") {
		t.Fatalf("selected %q", res.Artifact.Name)
	}
}

func TestCheckRefusesAnAmbiguousOrMissingPlatform(t *testing.T) {
	key := fixtureKey(t, seedA)

	dup := fixtureManifest("v0.4.0", ChannelStable)
	dup.Artifacts = append(dup.Artifacts, dup.Artifacts[0])
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, dup, key), key); !errors.Is(err, ErrAmbiguousAsset) {
		t.Fatalf("duplicate platform: got %v, want ErrAmbiguousAsset", err)
	}

	missing := fixtureManifest("v0.4.0", ChannelStable)
	kept := missing.Artifacts[:0]
	for _, a := range missing.Artifacts {
		if a.Platform() != linuxAMD64 {
			kept = append(kept, a)
		}
	}
	missing.Artifacts = kept
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, missing, key), key); !errors.Is(err, ErrNoPlatformAsset) {
		t.Fatalf("missing platform: got %v, want ErrNoPlatformAsset", err)
	}
}

// A signed manifest is authentic, not benign. Pinning every URL keeps a signer who
// is compromised or mistaken from aiming a downloader at another host.
func TestCheckRefusesAssetURLsThatLeaveTheRelease(t *testing.T) {
	key := fixtureKey(t, seedA)
	for _, tc := range []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"foreign asset host", func(m *Manifest) {
			m.Artifacts[0].URL = strings.Replace(m.Artifacts[0].URL, "github.com", "githuh.com", 1)
		}},
		{"another repository", func(m *Manifest) {
			m.Artifacts[0].URL = AssetURL("attacker/aqt-sync", m.Version, m.Artifacts[0].Name)
		}},
		{"foreign release page", func(m *Manifest) {
			m.ReleaseURL = "https://example.test/releases/tag/v0.4.0"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureManifest("v0.4.0", ChannelStable)
			tc.mutate(&m)
			if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, m, key), key); !errors.Is(err, ErrMalformedManifest) {
				t.Fatalf("got %v, want ErrMalformedManifest", err)
			}
		})
	}
}

func TestCheckRefusesOversizedMetadata(t *testing.T) {
	key := fixtureKey(t, seedA)

	bigManifest := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)
	bigManifest.manifest = append(bigManifest.manifest, bytes.Repeat([]byte(" "), MaxManifestBytes)...)
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, bigManifest, key); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("manifest: got %v, want ErrTooLarge", err)
	}

	bigSig := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)
	bigSig.signature = append(bigSig.signature, bytes.Repeat([]byte(" "), MaxSignatureBytes)...)
	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, bigSig, key); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("signature: got %v, want ErrTooLarge", err)
	}
}

// Signing a non-canonical encoding must not make it acceptable: the signature says
// who published the bytes, not that the bytes mean one thing.
func TestCheckRefusesASignedNonCanonicalManifest(t *testing.T) {
	key := fixtureKey(t, seedA)
	compact, err := json.Marshal(fixtureManifest("v0.4.0", ChannelStable))
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSource{manifest: compact, signature: signBytes(t, compact, key)}

	if _, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, src, key); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("got %v, want ErrNotCanonical", err)
	}
}

// A source build has no relationship to any published release, so the check says
// so instead of guessing — and does not touch the network to find out.
func TestCheckTreatsSourceBuildsAsUnsupported(t *testing.T) {
	key := fixtureKey(t, seedA)
	for _, build := range []Build{
		{Version: "0.3.0-dev", Kind: KindDev},
		{Version: "v0.3.0-5-gdeadbee", Kind: KindDev},
		{Version: "unknown", Kind: KindRelease},
		{Version: "v0.3", Kind: KindRelease},
	} {
		src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)
		res, err := checkFixture(t, build, ChannelStable, src, key)
		if err != nil {
			t.Fatalf("%+v: %v", build, err)
		}
		if res.Status != StatusUnsupported {
			t.Fatalf("%+v: status = %q, want %q", build, res.Status, StatusUnsupported)
		}
		if res.Reason == "" {
			t.Fatalf("%+v: unsupported without a reason", build)
		}
		if src.calls != 0 {
			t.Fatalf("%+v: contacted the update source %d times", build, src.calls)
		}
	}
}

func TestCheckWithoutTrustRootsFailsClosed(t *testing.T) {
	key := fixtureKey(t, seedA)
	src := sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key)

	_, err := Check(context.Background(), Options{
		Build:    releaseBuild("v0.3.0"),
		Source:   src,
		Roots:    []TrustRoot{},
		Platform: linuxAMD64,
	})
	if !errors.Is(err, ErrNoTrustRoots) {
		t.Fatalf("got %v, want ErrNoTrustRoots", err)
	}
	if src.calls != 0 {
		t.Fatal("fetched metadata it could never authenticate")
	}
}

func TestCheckPropagatesFetchFailures(t *testing.T) {
	sentinel := errors.New("network is down")
	_, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, &fakeSource{err: sentinel}, fixtureKey(t, seedA))
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want the fetch error", err)
	}
}

// The JSON field set is the contract scripts depend on.
func TestResultJSONFieldsAreStable(t *testing.T) {
	key := fixtureKey(t, seedA)
	res, err := checkFixture(t, releaseBuild("v0.3.0"), ChannelStable, sourceFor(t, fixtureManifest("v0.4.0", ChannelStable), key), key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"currentVersion", "availableVersion", "channel", "status", "releaseUrl"} {
		if _, ok := got[field]; !ok {
			t.Errorf("missing field %q in %s", field, b)
		}
	}
	if _, ok := got["Artifact"]; ok {
		t.Error("the selected artifact leaked into the JSON contract")
	}
}
