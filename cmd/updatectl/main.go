// Command updatectl generates, signs, and verifies the release update manifest.
// It is a build-time tool run by the release workflow and by whoever provisions
// the signing key; it is never shipped to users.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "gen":
		err = gen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `updatectl <command> [flags]

  keygen   generate a release-signing keypair
  gen      build the canonical update manifest from a dist directory
  sign     sign a manifest with one or more keys
  verify   verify a manifest against the compiled trust roots or explicit keys
`)
}

// keygen mints a release-signing keypair. The private half is printed once and
// never stored: it belongs in the protected release environment's secret, not on
// disk or in the repository.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	comment := fs.String("comment", "", "human label for the trust-root entry (e.g. \"release signing key 1\")")
	addedIn := fs.String("added-in", "", "version this key first shipped in (e.g. v0.4.0)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	fmt.Printf("key id:      %s\n", update.KeyID(pub))
	fmt.Printf("public key:  %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("private key: %s\n\n", base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Printf("Store the private key as the AQT_UPDATE_SIGNING_KEYS secret in the\n")
	fmt.Printf("release-signing environment, then add this entry to internal/update/trustroots.go:\n\n")
	fmt.Printf("\t{\n\t\tPublicKey: %q,\n\t\tComment:   %q,\n\t\tAddedIn:   %q,\n\t},\n", base64.StdEncoding.EncodeToString(pub), *comment, *addedIn)
	return nil
}

// gen builds the manifest from the archives that were actually produced, so the
// published sizes and hashes cannot drift from the published bytes.
func gen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	dist := fs.String("dist", "dist", "directory holding the release archives")
	version := fs.String("version", "", "release version, e.g. v0.4.0")
	channel := fs.String("channel", "", "stable or beta (default: derived from the version)")
	repo := fs.String("repo", update.DefaultRepo, "owner/repo the release is published under")
	publishedAt := fs.String("published-at", "", "RFC3339 UTC publication time (default: now)")
	out := fs.String("out", "", "output path for the manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || *out == "" {
		return errors.New("gen requires --version and --out")
	}
	v, err := update.ParseVersion(*version)
	if err != nil {
		return err
	}
	ch := update.Channel(*channel)
	if *channel == "" {
		ch = update.ChannelStable
		if v.IsPrerelease() {
			ch = update.ChannelBeta
		}
	}
	published := *publishedAt
	if published == "" {
		published = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}

	m := update.Manifest{
		Schema:      update.ManifestSchema,
		Channel:     ch,
		Version:     *version,
		PublishedAt: published,
		ReleaseURL:  update.ReleaseTagURL(*repo, *version),
	}
	for _, p := range update.Platforms {
		name := update.ArchiveName(*version, p)
		path := filepath.Join(*dist, name)
		size, sum, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		m.Artifacts = append(m.Artifacts, update.Artifact{
			OS:     p.OS,
			Arch:   p.Arch,
			Name:   name,
			Size:   size,
			SHA256: sum,
			URL:    update.AssetURL(*repo, *version, name),
		})
	}
	b, err := m.CanonicalBytes()
	if err != nil {
		return err
	}
	// Round-trip through the client's own parser: whatever ships must be something
	// a client will accept, and finding out at release time beats finding out from
	// a user whose check started failing.
	if _, err := update.ParseManifest(b); err != nil {
		return fmt.Errorf("generated manifest is not acceptable to the client: %w", err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%s, %d artifacts)\n", *out, ch, len(m.Artifacts))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	in := fs.String("in", "", "manifest to sign")
	out := fs.String("out", "", "output path for the detached signature")
	keyEnv := fs.String("key-env", "AQT_UPDATE_SIGNING_KEYS", "environment variable holding comma-separated base64 private keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return errors.New("sign requires --in and --out")
	}
	keys, err := loadKeys(os.Getenv(*keyEnv))
	if err != nil {
		return fmt.Errorf("%s: %w", *keyEnv, err)
	}
	manifest, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	if _, err := update.ParseManifest(manifest); err != nil {
		return fmt.Errorf("refusing to sign: %w", err)
	}
	sig, err := update.SignManifest(manifest, keys...)
	if err != nil {
		return err
	}
	b, err := sig.Bytes()
	if err != nil {
		return err
	}
	// Verify against the keys just used before publishing anything: a signature that
	// does not check out here would only be discovered by every client at once.
	if _, err := update.Verify(manifest, b, rootsFor(keys)); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d signature(s))\n", *out, len(keys))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "", "manifest to verify")
	sigPath := fs.String("sig", "", "detached signature")
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "base64 public key to trust instead of the compiled trust roots (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *sigPath == "" {
		return errors.New("verify requires --in and --sig")
	}
	manifest, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sigBytes, err := os.ReadFile(*sigPath)
	if err != nil {
		return err
	}
	roots := update.TrustRoots()
	if len(pubkeys) > 0 {
		roots, err = rootsFromPublicKeys(pubkeys)
		if err != nil {
			return err
		}
	}
	keyID, err := update.Verify(manifest, sigBytes, roots)
	if err != nil {
		return err
	}
	m, err := update.ParseManifest(manifest)
	if err != nil {
		return err
	}
	// The same URL pinning a client applies. Without it a manifest could pass here
	// and be refused by every installed binary, which is the worst place to find out.
	if err := m.CheckURLs(update.DefaultRepo); err != nil {
		return err
	}
	fmt.Printf("ok: %s %s signed by %s\n", m.Channel, m.Version, keyID)
	return nil
}

func loadKeys(env string) ([]ed25519.PrivateKey, error) {
	var keys []ed25519.PrivateKey
	for _, field := range strings.Split(env, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(field)
		if err != nil {
			return nil, fmt.Errorf("key is not base64: %w", err)
		}
		switch len(raw) {
		case ed25519.SeedSize:
			keys = append(keys, ed25519.NewKeyFromSeed(raw))
		case ed25519.PrivateKeySize:
			keys = append(keys, ed25519.PrivateKey(raw))
		default:
			return nil, fmt.Errorf("key is %d bytes, want %d", len(raw), ed25519.SeedSize)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no signing key set")
	}
	return keys, nil
}

func rootsFor(keys []ed25519.PrivateKey) []update.TrustRoot {
	roots := make([]update.TrustRoot, 0, len(keys))
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		roots = append(roots, update.TrustRoot{KeyID: update.KeyID(pub), PublicKey: pub})
	}
	return roots
}

func rootsFromPublicKeys(encoded []string) ([]update.TrustRoot, error) {
	roots := make([]update.TrustRoot, 0, len(encoded))
	for _, s := range encoded {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("malformed public key %q", s)
		}
		roots = append(roots, update.TrustRoot{KeyID: update.KeyID(pub), PublicKey: pub})
	}
	return roots, nil
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }
