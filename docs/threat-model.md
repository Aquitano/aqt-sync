# Threat model

What the server can see, what it cannot, and where the boundary is deliberately
imperfect. The protocol documents describe *how* the formats work
([folder sync](protocol/folder-sync.md), [Git remotes](protocol/git-remote.md),
[HTTP API](protocol/api.md)); this one describes what they protect.

The short version: the client encrypts everything before it leaves the machine. The
server stores ciphertext and opaque metadata and never sees a key, a filename, or a
plaintext byte. It still sees sizes, timing, and the operational metadata it needs to
enforce a policy it cannot read — those are enumerated below, and the residual limits
are collected under [Still open](#still-open).

## Key hierarchy

```text
passphrase ──Argon2id(salt)──▶ unlockKey (UK)       (never leaves the device)
                                  │
                                  └─ unwraps ─▶ rootKey (RK), the master key
                                                  │    (random, minted at signup;
                                                  │     the server stores only
                                                  │     wrappedRoot = seal(RK, UK))
                                                  ├─ wraps ─▶ contentKey (one per resource)
                                                  ├─ HKDF ─▶ convergence key (chunk dedup)
                                                  └─ HKDF ─▶ Ed25519 signing key
                                                               (public half registered with the
                                                                server; logins sign a server
                                                                challenge — no secret is sent)
file ──encrypt(contentKey)──▶ ciphertext + nonce + AEAD tag  ──▶ server (opaque blob)
metadata (real name, size…) ──encrypt(contentKey)──▶ sealed metadata ──▶ server
```

The passphrase never derives the master key directly. It derives `UK`, whose only job
is to wrap `RK` — which is what makes a passphrase change cheap; see
[the wrapped-root model](#the-wrapped-root-model).

### The wrapped-root model

The account's *master key* is a random root key (`RK`), minted at signup and rotated
only during compromise recovery; it wraps content keys and derives the signing and
convergence keys. The passphrase derives an *unlock key*
(`UK = Argon2id(passphrase, salt)`) whose only job is to wrap `RK` —
`wrappedRoot = seal(RK, UK)`, stored server-side (opaque, zero-knowledge) and cached
locally.

A passphrase change is therefore cheap: re-derive `UK`, re-wrap `RK`, upload one
record. **No resource is re-encrypted**, because the master key is unchanged. It also
bumps an **auth epoch**, which invalidates every other device's token (the server
rejects a token whose epoch is behind), and rotates a passphrase **verifier** the
server stores hashed. A device re-attaches by presenting both an Ed25519 challenge
signature (proves `RK`) *and* the verifier (proves the *current* passphrase), so a
stale passphrase or a cached root key alone cannot re-attach after a change.

`aqt passphrase rotate-root` is the compromise-recovery operation: it mints a fresh
`RK`, re-wraps every recoverable resource and snapshot content key plus incoming
grant, migrates the derived signing and encryption identities, and atomically
switches the account record. The server issues a fresh token only to the initiating
device and removes every other device; they recover by logging in again with the
passphrase. Existing convergent objects stay readable because their per-object keys
are sealed in their roots; future writes derive convergence from the new `RK`.

A typo'd first passphrase is **unrecoverable** — there is nothing server-side to
reset against — so `signup` on a terminal confirms it and says so explicitly. Without
a terminal the passphrase is read once and the confirmation is skipped.

### KDF calibration

`crypto.CalibrateKdf` benchmarks the creating machine at signup (and on `passphrase
change`) and scales the Argon2id iteration count to a preset's target unlock time:
`interactive` ~0.5s at 64 MiB, `moderate` ~1s at 256 MiB (the default), `sensitive`
~2.5s at 1 GiB. On a machine too slow to fit one pass it steps memory down toward a
64 MiB floor rather than blowing the target.

Parameters are public and travel with the account, so every device re-derives the
same key. `--kdf-preset`, or manual `--kdf-time`/`--kdf-memory`/`--kdf-threads`,
override the calibration, and `aqt passphrase calibrate` re-tunes an existing account
in place through the cheap wrapped-root re-wrap (no resource is re-encrypted; other
devices re-login).

## What the server stores

Per resource: `id`, opaque `ownerHandle`, ciphertext blob(s), encrypted-metadata
blob, a `visibility` flag, a wrapped-key record *only for private resources owned by
an account*, version counter, timestamps, and — for a public link with a lifecycle
policy — an `expires_at` timestamp, a `max_reads` cap, a `reads` counter, an
`exhausted_at` stamp, and a `reclaimed` tombstone flag.

No user content is ever stored in plaintext: the file, its name, its size, and every
other attribute a user set live inside the sealed blob and sealed metadata. What is
plaintext is the operational metadata in that list — visibility, version, timestamps,
and the lifecycle counters — which the server must read to route and enforce. Those
are the [deliberate side channels](#deliberate-side-channels) below; nothing in them
identifies content.

## Reference forms

Three forms a user can hold. A share link is served by the server that stores the
resource, so `aqt.example.com` below stands in for wherever you host it.

| Form | Looks like | Who can decrypt | Used for |
| --- | --- | --- | --- |
| Private ref | `aqt://<id>` | only the owning account (master key unwraps the stored wrapped key) | `.env`-to-your-other-machine |
| Public link | `https://aqt.example.com/x/<id>#k.<key>` | anyone with the link (key in fragment) | sharing |
| Gated link | `https://aqt.example.com/x/<id>#p.<wrappedKey>` | anyone with the link **and** the password | sharing a secret semi-publicly |

The `k.` / `p.` prefix in the fragment tells the client whether to use the key
directly or prompt for a password to unwrap it. The fragment never reaches the
server; it sees only `<id>`.

## What revocation actually guarantees

`aqt unshare <id>` rotates the content key, re-encrypts, and prints the new
`aqt://` ref. Every link ever issued for that resource is dead.

For a **streamed file or a chunked folder**, rotation is root-only: the
`FileRoot`/`TreeRoot` and the sealed metadata re-seal under a fresh content key while
the convergent chunk ciphertext and per-chunk keys stay as they are. Re-sealing them
would break dedup and re-upload the whole resource, and it would buy nothing a link
holder could not already have taken: the per-object keys derive from the account
convergence key, which a link never carried.

The consequence is worth stating plainly. Revocation of the *content bytes* is
enforced by the server's visibility check, not by re-encryption. An old link holder
who saved the root's chunk keys could still decrypt that ciphertext if they somehow
obtained it later — but they could equally have saved the plaintext. Either way the
old **link** is dead: the root no longer opens under the old key, and the server
stops serving the objects.

An expiring link is a different operation from revoking one. Expiry can either
`reclaim` (destroy the content) or `retire` (take only the link down); a retired
link's fragment is dormant, not dead, because no key was rotated. See
[`compatibility.md`](compatibility.md#what-expiry-does-to-the-resource-onexpiry).

## Incoming shares are attacker-appendable

Registration is open by default and the handle lookup behind `aqt share --with` is
authenticated but unrestricted, so any account on a server can put a row into any
other account's `aqt shares` list. Three properties keep that from being worse than
noise:

- **The name is another account's plaintext.** A grantor picks the metadata a
  recipient's terminal renders, so control bytes in it could erase the line and forge
  output that looks like aqt's own — a fake `aqt://` ref, a fake fingerprint MATCH.
  Every foreign name and kind is stripped of control bytes and bounded before display
  (`aqt shares`, `aqt info`, and the pull paths), so the worst case is an odd-looking
  string on one line.
- **The recipient can remove it.** `aqt shares rm <ref>` deletes the row under a
  `grantee_handle = caller` predicate — it touches nobody else's access — and
  `--block` additionally refuses that account's future grants and drops the shares it
  has already sent. Blocks are listed by `aqt shares blocked` and lifted by
  `aqt shares unblock`.
- **The sender is named where it can be.** A grant carries an opaque handle. `aqt
  shares` reverse-resolves it against the local contact pins and prints the pinned
  email and key fingerprint on a match, `unknown sender` otherwise; the fingerprint is
  the one to compare out-of-band before acting on a share.

A block is the one place a grant write distinguishes a real account from a decoy, and
only to the account the recipient deliberately blocked.

## Deliberate side channels

**Lifecycle metadata.** Expiry timestamps and read counters are plaintext
operational metadata the server necessarily sees to enforce a policy it cannot read
the content of. It still never sees the file, its name, or any key; it only knows
*when* a link dies and *how many times* it has been fetched.

**Chunk size sequence (chunked folders).** FastCDC boundaries are content-derived
and the pack index stores each object's ciphertext length, so the *sequence of chunk
sizes* of a file is observable to the server, and to anyone who reads the object
store. The keyed convergence key stops an attacker *matching chunk hashes* against a
candidate file, but not matching that size sequence — the classic
content-defined-chunking leak. For a known target file an attacker can confirm its
presence from the shapes alone.

Pack-and-seal (`pack: true` in `.aqtconfig`) exists precisely to avoid this: it tars
the whole tree and seals it into fixed-size, per-sync-unique segments with no
per-file boundary, so it leaks only the total size. The trade is that any change
re-ships the whole folder and there is no per-file conflict resolution. See
[folder sync](protocol/folder-sync.md#pack-and-seal).

**Timing and volume.** The server sees when a push happens, how many segments it
carries, and how large they are. Nothing in the design hides that.

## Domain separation and record binding

AEAD additional-data domain separation across blob, wrap, and gated-wrap has been in
since v1. The resource id is bound into the AAD as well (`SealBound`/`OpenBound`, tag
form `aqt-<role>-v2:<id>`) over the metadata, the inline body, the
`FileRoot`/`TreeRoot`/`PackRoot` resource blobs, and snapshot labels — so a server
swapping whole records between ids fails the tag check, even though a record's blob,
meta, and wrapped key are mutually consistent under the per-resource key.

The id the check verifies against is the client's own: `GetResource` rejects a
response whose echoed id differs from the requested one, and a filtered snapshot
listing rejects rows claiming another resource, so the server cannot satisfy the
binding by echoing the id of whatever record it chose to serve.

Chunk objects, directory nodes, and pack segments stay id-free. They are
content-addressed, client-verified against their address, and reachable only through
an id-bound root; binding them would kill cross-resource dedup.

Four bounded caveats:

1. A create seals before the server assigns the id, so a resource is unbound until
   its first re-seal. Folder syncs upgrade the root — and, once, the metadata — on
   the next update; a one-shot `push` stays unbound.
2. The v1 fallback that keeps old blobs readable means a server can serve a stale
   unbound blob. It still cannot forge or cross-open one. Full strictness would need
   client-generated ids and a fallback cut-off.
3. A snapshot browsed without naming a resource has no client-side expectation to pin
   its claimed resource id to. An in-place restore checks the tracked folder's id;
   `--out` restores trust the claim.
4. Once a folder has synced with an id-binding client, its root no longer opens on
   clients from before that change — upgrade every device together.

Capability negotiation gates every declared format boundary: a client below a
resource's `min_client`, including a header-less client treated as baseline
capability 1, is refused before any ciphertext is served. See
[`compatibility.md`](compatibility.md) for the policy and
[`protocol/api.md`](protocol/api.md#request-contract) for the mechanism.

**Key wiping.** `ContentKey.Wipe` exists and every acquisition site scrubs on scope
exit, including the longest-lived by-value copies in the sync and pack apply
contexts. Transient by-value copies on intermediate stack frames remain out of
reach — the inherent Go caveat `Wipe` documents.

## Account enumeration

Unauthenticated auth routes are rate-limited, and `GET /v1/account/salt` returns an
indistinguishable decoy `{kdf, wrappedRoot}` for an unknown email instead of a 404.
The decoy's Argon2id costs are drawn per-email (HKDF over the server secret) from the
same value set a moderate calibration produces — memory ∈ {64, 128, 256 MiB},
iterations clustered where a ~1s unlock lands on common hardware — rather than the
fixed package default, so a decoy's parameters do not stand out.

`POST /v1/account` does not answer `409` on a duplicate email in the default *open*
registration mode. It returns the same success shape with a decoy token that grants
nothing, so signup is not an existence oracle either: the caller's next authenticated
call fails, matching the wrong-passphrase ambiguity.

Open registration is nonetheless enumerable by design. Signing up for an unused
address must succeed, so "the signup worked" always reveals that the address was
free. A prober cannot confirm a *specific* address without also taking it, but only
`AQT_REGISTRATION=invite` (with `AQT_INVITE_TOKENS`) actually closes enumeration, and
it is what closes the email-squatting hole for a hosted deployment.

`GET /v1/account/keys` returns the same kind of decoy — deterministic and correctly
self-signed — for an unknown grant target. That removes the oracle at a cost recorded
under [Still open](#still-open).

## Client data at rest

**Session cache.** The cached master key is sealed under a random per-profile key
kept in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret
Service, via pure-Go `zalando/go-keyring`); the on-disk 0600 file holds only
ciphertext and `expiresAt`, and is useless without the keychain entry. The device
token lives in the keychain too. A host with no keychain backend (a headless server),
or one that sets `AQT_NO_KEYCHAIN=1`, falls back to a machine-bound key and file, so
non-interactive operation is unchanged there. Exposure stays bounded by `--ttl` and
is cleared by `aqt logout`.

**Last-synced base.** `.aqt/base.json` carries per-chunk decryption keys and inline
small-file plaintext, so it is sealed at rest under the **same** per-profile sealing
key, with a distinct `aqt-base-at-rest-v1` AAD. A backed-up, cloud-synced, or
stolen-disk copy is therefore useless off-machine. The seal is read offline by
`status` and before the master key is unlocked, so it uses the sealing key, not the
master key. Old plaintext bases are read transparently and upgraded on the next sync
(disjoint top-level keys make the two forms unambiguous).

Both inherit the same residual: a process running as the same user can reach the
keychain, or re-derive the machine-bound key.

## Still open

Everything above ships. These four do not, and each is a deliberate limit rather than
an unfinished task — they are the honest answer to "what does aqt still not protect
you from":

- **Chunk size-sequence fingerprint.** Chunked mode leaks the sequence of ciphertext
  chunk lengths, so an attacker holding a candidate file can confirm its presence
  without breaking anything. The mitigation that exists today is choosing
  `pack: true`. Length-bucket padding would blunt it but changes the sealed
  ciphertext length and therefore the content address, breaking dedup identity
  against every existing chunk; deferred rather than folded into the seal path.
- **Same-user process reach.** The session cache and `.aqt/base.json` are sealed
  under a keychain-held per-profile key, which stops an off-machine copy but not a
  process running as the same user on the same machine. Closing it needs a
  passphrase- or biometric-gated agent, or a hardware enclave.
- **Grant to an address that has never been pinned.** `GET /v1/account/keys` returns
  an indistinguishable decoy for an unknown email — that is what removes the
  existence oracle, but it also means a hostile server can answer a first-time
  `share --with` for an unregistered address with a key it controls. The client pins
  on first use, warns on stderr, and offers `aqt contacts verify <email>` for an
  out-of-band fingerprint comparison, so the exposure is trust-on-first-use, not a
  standing hole — but a first grant to a never-seen address is only as trustworthy as
  that verification. `aqt contacts pin <email> --fingerprint <fp>` closes it for a
  contact who can read their fingerprint out over a separate channel: the pin lands
  only if the server presents that key, which is a check no decoy passes. Without a
  fingerprint to check against, the pin is still trust-on-first-use.
- **Pre-migration plaintext residue.** Upgrading an old plaintext `.aqt/base.json`
  writes the sealed form through an atomic rename; the freed disk blocks holding the
  old plaintext are not scrubbed. Forensic-only, and local to that disk.

Nothing here changes an interface, which is why they are recorded as limits rather
than blocking work.
