package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCanonicalBytesRoundTripThroughTheParser(t *testing.T) {
	m := fixtureManifest("v0.4.0", ChannelStable)
	b, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseManifest(b)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	again, err := got.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, again) {
		t.Fatal("canonical encoding is not stable across a decode/encode cycle")
	}
}

// The signature covers bytes, so any encoding that decodes to the same manifest
// but is not the canonical one has to be refused: otherwise two readers could
// disagree about what was signed.
func TestParseManifestRefusesNonCanonicalEncodings(t *testing.T) {
	m := fixtureManifest("v0.4.0", ChannelStable)
	compact, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(compact); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("compact encoding: got %v, want ErrNotCanonical", err)
	}

	// Artifacts out of canonical order.
	shuffled := m
	shuffled.Artifacts = append([]Artifact(nil), m.Artifacts...)
	shuffled.Artifacts[0], shuffled.Artifacts[len(shuffled.Artifacts)-1] = shuffled.Artifacts[len(shuffled.Artifacts)-1], shuffled.Artifacts[0]
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(shuffled); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(buf.Bytes()); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("shuffled artifacts: got %v, want ErrNotCanonical", err)
	}
}

func TestParseManifestRefusesUnknownFieldsAndTrailingData(t *testing.T) {
	b, err := fixtureManifest("v0.4.0", ChannelStable).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	withExtra := bytes.Replace(b, []byte(`"schema": 1,`), []byte(`"schema": 1,`+"\n  "+`"installer": "curl | sh",`), 1)
	if _, err := ParseManifest(withExtra); !errors.Is(err, ErrMalformedManifest) {
		t.Fatalf("unknown field: got %v, want ErrMalformedManifest", err)
	}
	if _, err := ParseManifest(append(bytes.Clone(b), []byte("{}\n")...)); !errors.Is(err, ErrMalformedManifest) {
		t.Fatalf("trailing data: got %v, want ErrMalformedManifest", err)
	}
}

func TestParseManifestRefusesOversizedMetadata(t *testing.T) {
	b := append(bytes.Repeat([]byte(" "), MaxManifestBytes), '{')
	if _, err := ParseManifest(b); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
}

func TestValidateRejectsMalformedManifests(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
		want   error
	}{
		{"future schema", func(m *Manifest) { m.Schema = ManifestSchema + 1 }, ErrUnsupportedSchema},
		{"unknown channel", func(m *Manifest) { m.Channel = "nightly" }, ErrMalformedManifest},
		{"malformed version", func(m *Manifest) { m.Version = "0.4" }, ErrMalformedManifest},
		{"prerelease on stable", func(m *Manifest) {
			*m = fixtureManifest("v0.4.0-rc.1", ChannelStable)
		}, ErrMalformedManifest},
		{"local publication time", func(m *Manifest) { m.PublishedAt = "2026-07-26T11:00:00+02:00" }, ErrMalformedManifest},
		{"malformed publication time", func(m *Manifest) { m.PublishedAt = "yesterdayZ" }, ErrMalformedManifest},
		{"plaintext release url", func(m *Manifest) {
			m.ReleaseURL = strings.Replace(m.ReleaseURL, "https://", "http://", 1)
		}, ErrMalformedManifest},
		{"no artifacts", func(m *Manifest) { m.Artifacts = nil }, ErrMalformedManifest},
		{"duplicate platform", func(m *Manifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[0]) }, ErrAmbiguousAsset},
		{"server archive in a client slot", func(m *Manifest) {
			m.Artifacts[0].Name = strings.Replace(m.Artifacts[0].Name, "aqt_", "aqt-server_", 1)
			m.Artifacts[0].URL = strings.Replace(m.Artifacts[0].URL, "aqt_", "aqt-server_", 1)
		}, ErrMalformedManifest},
		{"archive named for another platform", func(m *Manifest) {
			m.Artifacts[0].Name = ArchiveName(m.Version, Platform{OS: "darwin", Arch: "arm64"})
		}, ErrMalformedManifest},
		{"zero size", func(m *Manifest) { m.Artifacts[0].Size = 0 }, ErrMalformedManifest},
		{"absurd size", func(m *Manifest) { m.Artifacts[0].Size = 1 << 40 }, ErrMalformedManifest},
		{"short hash", func(m *Manifest) { m.Artifacts[0].SHA256 = "abcd" }, ErrMalformedManifest},
		{"uppercase hash", func(m *Manifest) { m.Artifacts[0].SHA256 = strings.ToUpper(m.Artifacts[0].SHA256) }, ErrMalformedManifest},
		{"plaintext asset url", func(m *Manifest) {
			m.Artifacts[0].URL = strings.Replace(m.Artifacts[0].URL, "https://", "http://", 1)
		}, ErrMalformedManifest},
		{"url pointing at another file", func(m *Manifest) {
			m.Artifacts[0].URL = AssetURL(DefaultRepo, m.Version, "checksums.txt")
		}, ErrMalformedManifest},
		{"empty platform", func(m *Manifest) { m.Artifacts[0].Arch = "" }, ErrMalformedManifest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := fixtureManifest("v0.4.0", ChannelStable)
			tc.mutate(&m)
			if err := m.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsAPrereleaseOnTheBetaChannel(t *testing.T) {
	if err := fixtureManifest("v0.4.0-rc.1", ChannelBeta).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// Selection is by platform, never by name prefix, which is what keeps the
// aqt-server archive published in the same release out of reach.
func TestArtifactSelectsTheClientArchive(t *testing.T) {
	m := fixtureManifest("v0.4.0", ChannelStable)
	a, err := m.Artifact(linuxAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "aqt_v0.4.0_linux_amd64.tar.gz" {
		t.Fatalf("selected %q", a.Name)
	}
	if _, err := m.Artifact(Platform{OS: "windows", Arch: "arm64"}); !errors.Is(err, ErrNoPlatformAsset) {
		t.Fatalf("got %v, want ErrNoPlatformAsset", err)
	}
}

func TestArchiveNameMatchesTheReleaseWorkflow(t *testing.T) {
	for _, tc := range []struct {
		p    Platform
		want string
	}{
		{Platform{OS: "linux", Arch: "amd64"}, "aqt_v0.4.0_linux_amd64.tar.gz"},
		{Platform{OS: "darwin", Arch: "arm64"}, "aqt_v0.4.0_darwin_arm64.tar.gz"},
		{Platform{OS: "windows", Arch: "amd64"}, "aqt_v0.4.0_windows_amd64.zip"},
	} {
		if got := ArchiveName("v0.4.0", tc.p); got != tc.want {
			t.Errorf("ArchiveName(%s) = %q, want %q", tc.p, got, tc.want)
		}
	}
}
