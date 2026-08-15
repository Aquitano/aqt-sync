// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

// Deterministic fixture keys. Every test that needs a signature uses one of these
// seeds, so a failure is always reproducible and no test depends on a real key.
const (
	seedA = "aqt update fixture signing key A"
	seedB = "aqt update fixture signing key B"
	seedC = "aqt update fixture signing key C"
)

func fixtureKey(t *testing.T, seed string) ed25519.PrivateKey {
	t.Helper()
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("fixture seed %q is %d bytes, want %d", seed, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed([]byte(seed))
}

func rootsOf(keys ...ed25519.PrivateKey) []TrustRoot {
	roots := make([]TrustRoot, 0, len(keys))
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		roots = append(roots, TrustRoot{KeyID: KeyID(pub), PublicKey: pub})
	}
	return roots
}

// fixtureManifest is a complete, valid manifest for every published platform.
// Tests mutate one field of a copy to isolate the rule they are exercising.
func fixtureManifest(version string, ch Channel) Manifest {
	m := Manifest{
		Schema:      ManifestSchema,
		Channel:     ch,
		Version:     version,
		PublishedAt: "2026-07-26T11:00:00Z",
		ReleaseURL:  ReleaseTagURL(DefaultRepo, version),
	}
	for i, p := range Platforms {
		name := ArchiveName(version, p)
		m.Artifacts = append(m.Artifacts, Artifact{
			OS:     p.OS,
			Arch:   p.Arch,
			Name:   name,
			Size:   int64(8_000_000 + i),
			SHA256: strings.Repeat(fmt.Sprintf("%dbeef%dab", i, i), 8),
			URL:    AssetURL(DefaultRepo, version, name),
		})
	}
	return m
}

func signFixture(t *testing.T, m Manifest, keys ...ed25519.PrivateKey) (manifest, signature []byte) {
	t.Helper()
	b, err := m.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	return b, signBytes(t, b, keys...)
}

func signBytes(t *testing.T, manifest []byte, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	sig, err := SignManifest(manifest, keys...)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b, err := sig.Bytes()
	if err != nil {
		t.Fatalf("encode signature: %v", err)
	}
	return b
}

// fakeSource serves fixed bytes and records what it was asked for, so a test can
// assert both the answer and that a check which should never reach the network
// did not.
type fakeSource struct {
	manifest  []byte
	signature []byte
	err       error

	calls   int
	channel Channel
}

func (f *fakeSource) Fetch(_ context.Context, ch Channel) (Release, error) {
	f.calls++
	f.channel = ch
	if f.err != nil {
		return Release{}, f.err
	}
	return Release{Manifest: f.manifest, Signature: f.signature}, nil
}

func sourceFor(t *testing.T, m Manifest, keys ...ed25519.PrivateKey) *fakeSource {
	t.Helper()
	manifest, signature := signFixture(t, m, keys...)
	return &fakeSource{manifest: manifest, signature: signature}
}

// linuxAMD64 keeps checks independent of the machine running the tests.
var linuxAMD64 = Platform{OS: "linux", Arch: "amd64"}

func releaseBuild(v string) Build { return Build{Version: v, Kind: KindRelease} }
