# Updates: signed metadata, `aqt update`, and update policy

Every tagged release publishes a signed description of itself. `aqt update` fetches
that description, verifies it against signing keys compiled into the binary, and
either reports what is available or installs it. `--check` keeps the whole path
read-only.

The transport is not trusted. Whoever serves the metadata — GitHub's public release
assets or an explicitly configured static origin — can only make the check fail,
never make it lie: the signature is what makes an answer usable, and every field is
refused until it verifies.

## Using it

```
aqt update                      # check, show the transition, ask, then install
aqt update --yes                # install without asking (scripts, CI)
aqt update --check              # report only, change nothing
aqt update --check --prerelease # beta channel, which includes prereleases
aqt update --json               # machine-readable
```

`aqt update` shows the current and available versions and the release URL, then asks
before writing anything. Without a terminal it refuses rather than assuming consent;
`--yes` is the explicit non-interactive path.

**No prerequisites.** The repository is public, so the check reads the release's
`aqt-update.json` and `aqt-update.json.sig` assets over plain HTTPS — no tool to
install and no credentials. The stable channel resolves through GitHub's
`releases/latest/download/` redirect, which is by definition the newest
non-prerelease, so a routine check makes no API call and cannot be rate limited.
`--prerelease` additionally asks the public API for the newest release including
prereleases, since no static URL exposes that.

One explicit override exists for anyone not served by the default:

- `AQT_UPDATE_BASE_URL` fetches `<base>/stable.json` and `<base>/stable.json.sig`
  instead. That is how the tests run and how a mirror or self-hoster serves its own
  origin.

Transport is not a trust decision. The manifest signature is checked against keys
compiled into the binary whichever path supplied the bytes, and the artifact is
checked against the size and digest that signed manifest declares.

### JSON output

```json
{
  "currentVersion": "v0.5.0",
  "availableVersion": "v0.6.0",
  "channel": "stable",
  "status": "updateAvailable",
  "releaseUrl": "https://github.com/Aquitano/aqt-sync/releases/tag/v0.6.0",
  "publishedAt": "2026-08-09T21:47:59Z",
  "installed": false
}
```

`installed` says whether this run replaced the binary and is always present. `owner`
joins it once the running install has been classified — `standalone` for a release
archive the updater may replace, `source` for a build from the repository it will
not.

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
`--prerelease` and additionally carries tags with a prerelease suffix (`v0.7.0-rc.1`),
which the release workflow already marks as GitHub prereleases.

Beta is a superset, not a separate track: when no prerelease is outstanding — the
usual case — the newest release is a stable one, and a beta check reports it rather
than failing. The `channel` field in the output names the track the release was
published on, so a beta check that lands on a stable release says `stable`.

The containment is one-directional, and the channel is part of what is signed: a
beta manifest served to a stable check is refused even though it is authentic.

### Replayed manifests and the freshness ceiling

A signed manifest proves who published it, not that it is the newest one. Two guards
stand between a replayed old manifest and a downgrade:

- A release older than the **running build** is refused outright as a rollback.
- Every check also records, per channel in `update.json`, the highest version it has
  fully authenticated on this machine, and refuses a manifest below that ceiling —
  the case the first guard cannot see: a manifest newer than the running build but
  older than the newest release ever observed, which is exactly how a replay would
  pin a client at an intermediate release. Background checks raise the ceiling too,
  but never lower it.

If upstream genuinely retracted a release, `aqt update --accept-rollback` is the
explicit way through: it skips the ceiling for that one check and lowers the record
to what upstream now serves, so later plain checks stop tripping. The ceiling is
hardening on top of the signature checks, not a substitute — a state file that is
missing or unreadable degrades to "no ceiling", never to skipped verification.

## The first install

`aqt update` maintains an installation; it cannot create one. The first copy comes
from the install script the landing site serves:

```
curl -fsSL https://web.sync.aquitano.me/install.sh | sh      # macOS, Linux
iwr -useb https://web.sync.aquitano.me/install.ps1 | iex     # Windows
```

Both read the release's signed `aqt-update.json` to learn which archive belongs to
the platform, then refuse a download whose length or SHA-256 disagrees with what
that manifest declares — neither script guesses an asset name. `sh -s -- --server`
also installs `aqt-server`, which no signed manifest covers, so it is checked
against the release's `checksums.txt` instead; an unreadable or entry-less
checksums file is a refusal rather than a warning. `AQT_INSTALL_DIR` relocates the
install on both scripts — the default is `~/.local/bin` for `install.sh` and
`%LOCALAPPDATA%\Programs\aqt` for `install.ps1`. Pin a release with
`--version=vX.Y.Z` on the shell script or `-Version vX.Y.Z` on the PowerShell one.

The trust boundary differs from `aqt update` in exactly one place. Verifying an
Ed25519 signature in shell is not practical, so the first install trusts the origin
it downloads from; everything after it does not, because the updater checks the
manifest signature against keys compiled into the binary. To close that first gap
too, download from the releases page and check the build provenance with
`gh attestation verify` before running anything.

Installing a release archive is also what makes updating work at all: a `make build`
or `go install` copy reports its version as `dev`, which names no release, so the
updater reports it rather than replacing it.

## Installation kind

`aqt update` distinguishes only published release binaries from source builds.
The install script produces a release binary and the updater may replace it. A
`make build` or `go install` copy belongs to its source checkout, so the updater
refuses and explains how to rebuild or install a release.

| Owner | How it is recognized | What `aqt update` does |
| --- | --- | --- |
| standalone release | `buildKind` is `release` | replaces it |
| source | `buildKind` is not `release` | refuses; suggests `make build` or installing a release |

Release installs resolve symlinks before replacement so the updater writes the
actual binary rather than replacing only a link.

## Installing

The replacement is ordered so that there is no point at which the installed path
holds nothing usable:

1. Download the archive to a temporary file **in the install directory**, so the
   final rename is a same-filesystem operation rather than a copy across devices.
   Length and SHA-256 are checked as the bytes arrive, against the signed manifest;
   one byte over the declared size aborts the transfer rather than filling the disk.
2. Extract exactly one regular file named `aqt` (`aqt.exe` on Windows) from the root
   of the archive. Directories, symlinks, hard links, devices, a second copy, and any
   other member are refused rather than skipped — release archives are flat and hold
   one file, so anything else is not the archive the release process produces.
   Extraction output is bounded, so a crafted archive cannot expand without limit.
3. Run the extracted file and require it to report the version the manifest promised.
   This happens **before** the installed binary is touched, so a download that
   verified but does not run changes nothing.
4. Rename the current binary aside to `.aqt-update-previous.old`, then rename the new
   file into place.
5. Run the installed binary and check its version again. If that fails, the previous
   binary is renamed back.

Step 4 is the same on every platform. The operation Windows refuses is *overwriting*
a running image, not *renaming* one — so moving the old file aside first works there,
and on Unix the running process keeps its inode either way.

Permissions are carried over from the binary being replaced, so a deliberately
restricted install stays restricted. `setuid`, `setgid`, and the sticky bit are
dropped rather than preserved, and owner-execute is forced on.

### Rollback files and recovery

A file named `.aqt-update-*` in the install directory is update debris:

- `.aqt-update-*.part` — a download that did not finish.
- `.aqt-update-*.new` — an extracted binary that was never installed.
- `.aqt-update-previous.old` — the binary that was just replaced.

All three are safe to delete. Every `aqt update` that actually installs clears them
first, which is the only way the last one can go on Windows: the file is this
process's own running image, and the OS keeps it locked until the process exits. A
run that finds no newer release never reaches the install step, so it leaves the
debris where it is — an interrupted update's leftovers survive until the next real
install, or until you delete them by hand.

If an update is interrupted, the installed binary is whichever of the two the last
completed rename left in place — never a partial file, because the new binary is
written and flushed under a temporary name before any rename happens. To recover by
hand, move `.aqt-update-previous.old` back over the installed path.

## Update policy

By default nothing checks for updates unless asked. Installing aqt must not add
background network traffic to commands that were never pointed at the network.

```
aqt update policy            # show the current mode
aqt update policy notify     # check daily, print one line when a release exists
aqt update policy auto       # additionally install stable releases
aqt update policy off        # the default
```

Under `notify` and `auto`, a check runs **after** a command that succeeded, and only
when all of these hold:

- the policy is not `off`;
- at least 24 hours have passed since the last check (a failed check counts, so an
  unreachable network cannot turn "once a day" into "on every command");
- stdout and stdin are both a terminal;
- neither `--json` nor `--quiet` was passed;
- the command is not `watch`, `agent`, `update`, or `tui`.

The check is bounded to five seconds and its result never changes the exit status or
output of the command that triggered it. A notice is printed once per version rather
than on every check.

An automatic install is bounded separately, to two minutes: it moves tens of
megabytes rather than a few kilobytes of metadata, so the check's budget would leave
it failing on any ordinary connection. One that fails says so and points at `aqt
update`, and still does not change the exit status of the command that triggered it.

`auto` additionally installs, and only when every one of these holds — otherwise it
falls back to a notice:

- the installation is standalone (see above);
- the release is on the **stable** channel. A prerelease is something a user opts into
  per invocation with `--prerelease`, never something a policy decides for them;
- it is newer than the running build. A published version that is older is refused as
  a rollback, not offered — and one below the recorded freshness ceiling (see
  "Replayed manifests" above) is refused as a replay;
- there is a build for this OS and architecture;
- no registered watch agent is running.

### Watch agents

Replacing the binary under a running watch agent is safe on these filesystems, but
the agent would keep executing the old code with no way to know. So `auto` defers
instead, and says which agents are in the way.

Each agent records its root and pid in a global registry (`agents.json`, beside the
policy), because the per-folder `.aqt/agent.pid` is only visible from inside that
folder — and the point is for an update started anywhere to see agents everywhere.
Entries are removed on clean shutdown and reaped on read when the process is gone,
which is what keeps a killed agent from deferring updates forever. That matters most
on Windows, where stopping an agent terminates it rather than letting it clean up.

Stop the agents (`aqt agent stop` in each folder) and run `aqt update`, or wait: the
deferred install is retried at the next idle invocation rather than after another
full day. Retrying is free while the agents are still running — the registry answers
that locally, without fetching metadata again.

## Manifest

Published as the release asset `aqt-update.json`:

```json
{
  "schema": 1,
  "channel": "stable",
  "version": "v0.6.0",
  "publishedAt": "2026-08-09T21:47:59Z",
  "releaseUrl": "https://github.com/Aquitano/aqt-sync/releases/tag/v0.6.0",
  "artifacts": [
    {
      "os": "linux",
      "arch": "amd64",
      "name": "aqt_v0.6.0_linux_amd64.tar.gz",
      "size": 8123456,
      "sha256": "3b1f…",
      "url": "https://github.com/Aquitano/aqt-sync/releases/download/v0.6.0/aqt_v0.6.0_linux_amd64.tar.gz"
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
- the channel answers what was asked for (`stable` only for a stable check, `stable`
  or `beta` for a beta one), and `stable` carries no prerelease version
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
operational private half exists only as the `AQT_UPDATE_SIGNING_KEYS` secret in the
`release-signing` GitHub environment. Keep one recovery copy encrypted to an
access-controlled maintainer key and outside the repository; never store the seed as
plaintext, in agent memory, or in an ordinary shared password vault.

### Provisioning (one-time)

1. `go run ./cmd/updatectl keygen --comment "release signing key 2" --added-in v0.4.1`
   on a trusted machine. It prints the key id, the public key, the private key, and
   the `trustroots.go` entry to paste.
2. Store the private key as the `AQT_UPDATE_SIGNING_KEYS` secret in the
   `release-signing` environment. Never put it in a repository secret or a plaintext
   file.
3. Encrypt one recovery copy to a release maintainer's key, store it outside the
   repository, and test that it decrypts to the generated seed before deleting any
   plaintext or clearing the terminal.
4. Commit the `trustroots.go` entry.
5. Cut a release. The workflow signs, then verifies the signature against the
   committed trust roots — that step is what proves shipped clients will accept it.

Until step 4 lands, `aqt update --check` refuses to trust anything
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

### Loss

If a private key is lost before its first release publishes any artifacts, replace
the unshipped trust root and cut the next version. If it is lost after clients ship
and no recovery copy exists, those clients cannot authenticate a rotation release;
they require a manual reinstall from independently verified artifacts. This is why a
tested encrypted recovery copy is part of provisioning rather than an optional
backup.

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
gh release download v0.6.0 --pattern 'aqt-update.json*' --dir /tmp/aqt
go run ./cmd/updatectl verify --in /tmp/aqt/aqt-update.json --sig /tmp/aqt/aqt-update.json.sig
```

`verify` uses the trust roots compiled into the checkout. Pass `--pubkey <base64>` to
check against a specific key instead.

## Privacy

A check contacts GitHub (or `AQT_UPDATE_BASE_URL`) and nothing else. It sends no
account identifier, no profile, and no telemetry: it downloads two small files, and
an install downloads one archive.

Under the default `off` policy nothing runs on its own — the only network traffic is
from an explicit `aqt update`. Turning on `notify` or `auto` adds at most one check
per 24 hours, under the conditions listed above. Nothing is reported back: the
request is an ordinary asset download, and what the client decides afterwards stays
local.

The persisted state (`update.json`, beside the profiles) records the policy, the time
of the last check, the last version seen (so a notice is not repeated), and the
per-channel freshness ceiling. It holds nothing about the account.
