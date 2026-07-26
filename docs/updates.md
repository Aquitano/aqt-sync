# Update metadata and `aqt update --check`

Every tagged release publishes a signed description of itself. `aqt update --check`
fetches that description, verifies it against signing keys compiled into the binary,
and reports whether the running build is current. The check is read-only: nothing in
this path writes to the installation.

The transport is not trusted. Whoever serves the metadata — the GitHub CLI today, a
static origin later — can only make the check fail, never make it lie: the signature
is what makes an answer usable, and every field is refused until it verifies.

## Using it

```
aqt update --check              # stable channel
aqt update --check --prerelease # beta channel, which includes prereleases
aqt update --check --json       # machine-readable
```

`aqt update` with no flags does the same check. Installing updates is not
implemented yet; the command prints the release and asset to download.

**Prerequisite:** the repository is private, so release assets are only reachable
with credentials. The check shells out to the [GitHub CLI](https://cli.github.com)
(`gh auth login` once). Set `AQT_UPDATE_BASE_URL` to fetch `<base>/stable.json` and
`<base>/stable.json.sig` over plain HTTPS instead — that is how the tests run, and
it is the switch for serving metadata from a public origin.

### JSON output

```json
{
  "currentVersion": "v0.3.0",
  "availableVersion": "v0.4.0",
  "channel": "stable",
  "status": "updateAvailable",
  "releaseUrl": "https://github.com/Aquitano/aqt-sync/releases/tag/v0.4.0",
  "publishedAt": "2026-07-26T11:00:00Z"
}
```

`status` is one of:

| status            | meaning                                                             |
| ----------------- | ------------------------------------------------------------------- |
| `upToDate`        | the published release matches the running build                      |
| `updateAvailable` | a newer release exists; `availableVersion` and `releaseUrl` are set  |
| `unsupported`     | a source build, which corresponds to no release; `reason` explains it |

Fields may be added, never removed or repurposed. All three statuses exit `0`; a
failed check exits `1`, or `5` for a network error.

### Channels

`stable` is the default and never carries a prerelease. `beta` is opt-in via
`--prerelease` and additionally carries tags with a prerelease suffix (`v0.4.0-rc.1`),
which the release workflow already marks as GitHub prereleases. The channel is part
of what is signed, so a beta manifest served to a stable check is refused even though
it is authentic.

## Manifest

Published as the release asset `aqt-update.json`:

```json
{
  "schema": 1,
  "channel": "stable",
  "version": "v0.4.0",
  "publishedAt": "2026-07-26T11:00:00Z",
  "releaseUrl": "https://github.com/Aquitano/aqt-sync/releases/tag/v0.4.0",
  "artifacts": [
    {
      "os": "linux",
      "arch": "amd64",
      "name": "aqt_v0.4.0_linux_amd64.tar.gz",
      "size": 8123456,
      "sha256": "3b1f…",
      "url": "https://github.com/Aquitano/aqt-sync/releases/download/v0.4.0/aqt_v0.4.0_linux_amd64.tar.gz"
    }
  ]
}
```

One artifact per published platform: `linux/amd64`, `linux/arm64`, `darwin/amd64`,
`darwin/arm64`, `windows/amd64`. A release missing any of them fails to generate a
manifest at all, so the metadata can never advertise a platform the release does not
carry. A platform with no build is reported as such, not silently reported as current.

**Canonical encoding.** The signature covers bytes, so exactly one encoding is
acceptable: struct field order as above, artifacts sorted by `(os, arch)`, two-space
indent, no HTML escaping, one trailing newline. A client re-encodes what it parsed and
requires byte equality, so an alternative encoding of the same content is refused even
when correctly signed.

**Rules a client enforces before trusting anything** (all fail closed):

- schema is exactly `1`; a newer schema is refused rather than partially read
- the channel matches what was asked for, and `stable` carries no prerelease version
- the version is an exact `vMAJOR.MINOR.PATCH[-prerelease]`; `v1.2` is a packaging bug
- `publishedAt` is RFC3339 UTC
- 1–32 artifacts, each platform appearing at most once
- each `name` equals `aqt_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) — this is
  what keeps the `aqt-server` archive published in the same release unreachable
- each `size` is 1 byte to 512 MiB, each `sha256` is 64 lowercase hex
- every URL is exactly the GitHub release URL derived from the repository, version,
  and asset name; a signed manifest cannot point a downloader at another host
- the whole manifest is at most 64 KiB and the signature at most 8 KiB, enforced while
  reading rather than after
- the published version is not older than the running build

Selection is by `(GOOS, GOARCH)`, never by matching a name prefix.

## Signature

Published as `aqt-update.json.sig` beside the manifest:

```json
{
  "schema": 1,
  "alg": "ed25519",
  "signatures": [
    { "keyid": "9f2c1ab34d5e6f70", "sig": "base64…" }
  ]
}
```

The signed message is `"aqt-update-manifest-v1\0" || <canonical manifest bytes>`. The
domain prefix keeps a release signature from being interchangeable with any other
Ed25519 signature this project produces (account auth, key self-signatures), even if
a key were ever reused by mistake.

`keyid` is the first 8 bytes of SHA-256 of the public key, hex encoded. It is a lookup
handle, never a substitute for verifying: a signature naming a trusted key id but made
by a different key is rejected. A client accepts the manifest if **any** listed key it
trusts verifies, which is what makes rotation survivable. The envelope is validated in
full — key id shape, duplicates, signature length — before any signature is checked,
so a malformed file cannot pass because its first entry happened to be well formed.

## Signing keys

The public halves are compiled into the client in `internal/update/trustroots.go`. The
private half exists only as the `AQT_UPDATE_SIGNING_KEYS` secret in the
`release-signing` GitHub environment.

### Provisioning (one-time)

1. `go run ./cmd/updatectl keygen --comment "release signing key 1" --added-in v0.4.0`
   on a trusted machine. It prints the key id, the public key, the private key, and
   the `trustroots.go` entry to paste.
2. Store the private key as the `AQT_UPDATE_SIGNING_KEYS` secret in the
   `release-signing` environment. Nowhere else — not a repository secret, not a file,
   not a password manager shared with anyone who does not cut releases.
3. Commit the `trustroots.go` entry.
4. Cut a release. The workflow signs, then verifies the signature against the
   committed trust roots — that step is what proves shipped clients will accept it.

Until step 3 lands, `aqt update --check` refuses to trust anything
(`this build has no release-signing keys compiled in`), and the release workflow's
verify step fails. That is the intended behavior for a build that cannot authenticate
a manifest; it is not a state to work around.

### Least privilege

- The key is readable only by the `publish` job, which runs only for `v*` tags and
  only after the environment's protection rules are satisfied.
- The `build` job holds no key. Manifest generation needs none: it reads the archives
  and computes their hashes, and the asset URLs are deterministic.
- `aqt` itself never sees a private key. Verification is public-key only.

### Rotation

Rotation is planned, overlapping, and slow on purpose:

1. `updatectl keygen` a new key; add it to `trustroots.go` **alongside** the current
   one; ship a release. Clients from now on trust both.
2. Set `AQT_UPDATE_SIGNING_KEYS` to `<old>,<new>` (comma-separated). Releases are now
   signed by both keys, so clients on either side of the change accept them.
3. When enough time has passed that clients predating step 1 are not worth supporting,
   drop the old key from the secret and from `trustroots.go`.

Clients that never upgrade past step 1 stop being able to verify releases at step 3.
They fail closed with "signed by an unknown key" — they are left out, not fooled.

### Compromise

Removing a key from `trustroots.go` only affects builds shipped *after* the removal.
An already-installed client keeps trusting whatever it was compiled with; there is no
revocation channel that reaches it, and adding one would be another thing to
compromise. Recovery is therefore an upgrade campaign, not a revocation:

1. Rotate the signing key immediately (steps 1–2 above), and remove the compromised
   key from `trustroots.go` in the same release rather than overlapping with it.
2. Cut and publish that release, then announce the compromise: state which versions
   trust the compromised key and that they must be replaced by hand.
3. Assume anything the compromised key signed may be forged. Re-verify the published
   archives against their Sigstore attestations (`gh attestation verify`), which are
   independent of this key.
4. Investigate how the environment secret leaked before issuing a replacement key
   into the same environment.

The blast radius is bounded by what a manifest can say: it names archives on this
repository's release pages only, and `aqt update --check` never writes to the
installation. A forged manifest can misreport a version, not install anything.

## Verifying a release by hand

```
gh release download v0.4.0 --pattern 'aqt-update.json*' --dir /tmp/aqt
go run ./cmd/updatectl verify --in /tmp/aqt/aqt-update.json --sig /tmp/aqt/aqt-update.json.sig
```

`verify` uses the trust roots compiled into the checkout. Pass `--pubkey <base64>` to
check against a specific key instead.

## Privacy

The check contacts GitHub (or `AQT_UPDATE_BASE_URL`) and nothing else, only when run.
It sends no account identifier, no profile, and no telemetry: it downloads two small
files. Nothing about it runs on its own — there are no background checks in this
version.
