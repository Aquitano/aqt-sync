package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/update"
)

// stageRelease writes archives with the names the release workflow produces.
func stageRelease(t *testing.T, version string) string {
	t.Helper()
	dist := t.TempDir()
	for i, p := range update.Platforms {
		body := strings.Repeat("archive bytes ", i+1)
		if err := os.WriteFile(filepath.Join(dist, update.ArchiveName(version, p)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The server archives published in the same release must not confuse anything.
	for _, p := range update.Platforms {
		name := strings.Replace(update.ArchiveName(version, p), "aqt_", "aqt-server_", 1)
		if err := os.WriteFile(filepath.Join(dist, name), []byte("server"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dist
}

// The release pipeline's whole job is to produce something a client accepts, so
// the round trip is the test: generate from real archives, sign, and verify with
// the same code the CLI runs.
func TestGenSignVerifyRoundTrip(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	manifestPath := filepath.Join(dist, update.ManifestAssetName)
	sigPath := filepath.Join(dist, update.SignatureAssetName)

	if err := gen([]string{"--dist", dist, "--version", version, "--out", manifestPath, "--published-at", "2026-07-26T11:00:00Z"}); err != nil {
		t.Fatalf("gen: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AQT_UPDATE_SIGNING_KEYS", base64.StdEncoding.EncodeToString(priv.Seed()))
	if err := sign([]string{"--in", manifestPath, "--out", sigPath}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verify([]string{"--in", manifestPath, "--sig", sigPath, "--pubkey", base64.StdEncoding.EncodeToString(pub)}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := []update.TrustRoot{{KeyID: update.KeyID(pub), PublicKey: pub}}
	if _, err := update.Verify(manifest, sigBytes, roots); err != nil {
		t.Fatalf("the client would reject this signature: %v", err)
	}
	m, err := update.ParseManifest(manifest)
	if err != nil {
		t.Fatalf("the client would reject this manifest: %v", err)
	}
	if m.Channel != update.ChannelStable || m.Version != version {
		t.Fatalf("manifest describes %s %s", m.Channel, m.Version)
	}
	if len(m.Artifacts) != len(update.Platforms) {
		t.Fatalf("manifest carries %d artifacts, want %d", len(m.Artifacts), len(update.Platforms))
	}

	// Sizes and hashes must describe the bytes that were actually built, not
	// whatever the manifest happens to claim.
	for _, a := range m.Artifacts {
		body, err := os.ReadFile(filepath.Join(dist, a.Name))
		if err != nil {
			t.Fatalf("%s: %v", a.Platform(), err)
		}
		sum := sha256.Sum256(body)
		if a.Size != int64(len(body)) || a.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: manifest does not describe the archive on disk", a.Platform())
		}
		if strings.Contains(a.Name, "aqt-server") {
			t.Fatalf("%s: the server archive was published as a client build", a.Platform())
		}
	}
}

// A signature is only good for the bytes it covers; re-signing must be part of
// republishing, never optional.
func TestVerifyRejectsAManifestEditedAfterSigning(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	manifestPath := filepath.Join(dist, update.ManifestAssetName)
	sigPath := filepath.Join(dist, update.SignatureAssetName)

	if err := gen([]string{"--dist", dist, "--version", version, "--out", manifestPath}); err != nil {
		t.Fatalf("gen: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AQT_UPDATE_SIGNING_KEYS", base64.StdEncoding.EncodeToString(priv.Seed()))
	if err := sign([]string{"--in", manifestPath, "--out", sigPath}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.ReplaceAll(string(manifest), version, "v9.9.9")
	if err := os.WriteFile(manifestPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify([]string{"--in", manifestPath, "--sig", sigPath, "--pubkey", base64.StdEncoding.EncodeToString(pub)}); err == nil {
		t.Fatal("an edited manifest verified")
	}
}

// A manifest whose URLs point somewhere the client does not pin would be refused
// by every installed binary. Catching it at release time is the whole point of the
// workflow's verify step.
func TestVerifyRejectsAManifestForAnotherRepository(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	manifestPath := filepath.Join(dist, update.ManifestAssetName)
	sigPath := filepath.Join(dist, update.SignatureAssetName)

	if err := gen([]string{"--dist", dist, "--version", version, "--repo", "someone-else/aqt-sync", "--out", manifestPath}); err != nil {
		t.Fatalf("gen: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AQT_UPDATE_SIGNING_KEYS", base64.StdEncoding.EncodeToString(priv.Seed()))
	if err := sign([]string{"--in", manifestPath, "--out", sigPath}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verify([]string{"--in", manifestPath, "--sig", sigPath, "--pubkey", base64.StdEncoding.EncodeToString(pub)}); err == nil {
		t.Fatal("verify accepted a manifest pointing at another repository")
	}
}

// Every platform in the published set must have an archive: a release that
// silently drops one would tell those users they are up to date forever.
func TestGenRefusesAnIncompleteRelease(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	if err := os.Remove(filepath.Join(dist, update.ArchiveName(version, update.Platforms[0]))); err != nil {
		t.Fatal(err)
	}
	err := gen([]string{"--dist", dist, "--version", version, "--out", filepath.Join(dist, update.ManifestAssetName)})
	if err == nil {
		t.Fatal("gen accepted a release missing a platform")
	}
	if !strings.Contains(err.Error(), update.Platforms[0].String()) {
		t.Fatalf("error does not name the missing platform: %v", err)
	}
}

func TestGenPutsPrereleasesOnTheBetaChannel(t *testing.T) {
	const version = "v0.4.0-rc.1"
	dist := stageRelease(t, version)
	out := filepath.Join(dist, update.ManifestAssetName)
	if err := gen([]string{"--dist", dist, "--version", version, "--out", out}); err != nil {
		t.Fatalf("gen: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	m, err := update.ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Channel != update.ChannelBeta {
		t.Fatalf("channel = %q, want %q", m.Channel, update.ChannelBeta)
	}
}

func TestSignRequiresAKey(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	manifestPath := filepath.Join(dist, update.ManifestAssetName)
	if err := gen([]string{"--dist", dist, "--version", version, "--out", manifestPath}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AQT_UPDATE_SIGNING_KEYS", "")
	if err := sign([]string{"--in", manifestPath, "--out", filepath.Join(dist, update.SignatureAssetName)}); err == nil {
		t.Fatal("signing succeeded without a key")
	}
}

// Rotation is only survivable if one release can carry both signatures.
func TestSignSupportsMultipleKeys(t *testing.T) {
	const version = "v0.4.0"
	dist := stageRelease(t, version)
	manifestPath := filepath.Join(dist, update.ManifestAssetName)
	sigPath := filepath.Join(dist, update.SignatureAssetName)
	if err := gen([]string{"--dist", dist, "--version", version, "--out", manifestPath}); err != nil {
		t.Fatal(err)
	}

	outgoingPub, outgoing, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	incomingPub, incoming, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AQT_UPDATE_SIGNING_KEYS", base64.StdEncoding.EncodeToString(outgoing.Seed())+","+base64.StdEncoding.EncodeToString(incoming.Seed()))
	if err := sign([]string{"--in", manifestPath, "--out", sigPath}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, pub := range []ed25519.PublicKey{outgoingPub, incomingPub} {
		roots := []update.TrustRoot{{KeyID: update.KeyID(pub), PublicKey: pub}}
		if _, err := update.Verify(manifest, sigBytes, roots); err != nil {
			t.Fatalf("client trusting %s: %v", update.KeyID(pub), err)
		}
	}
}
