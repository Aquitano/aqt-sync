// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crypto implements aqt's zero-knowledge key hierarchy and blob sealing.
//
// The hierarchy is: passphrase --Argon2id--> master key --wraps--> content key,
// where each resource gets its own random content key and the content key seals
// the resource bytes with XChaCha20-Poly1305. The server never sees a passphrase,
// a master key, or an unwrapped content key.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeySize is the symmetric key length for every key in the hierarchy.
	KeySize = chacha20poly1305.KeySize // 32
	// NonceSize is the XChaCha20-Poly1305 nonce length. It is large enough that
	// random nonces will not collide in practice, so every Seal draws a fresh one.
	NonceSize = chacha20poly1305.NonceSizeX // 24
	saltSize  = 16
)

// Key is a 32-byte symmetric key. The distinct types stop the compiler from
// passing one where another is meant.
//
//   - MasterKey is the account's random root key: it wraps content keys and derives
//     the signing and convergence keys. It is minted once at signup and never
//     changes for the account's life (changing a passphrase does not change it).
//   - ContentKey seals a single resource's bytes.
//   - UnlockKey is the passphrase-derived key (Argon2id) whose only job is to wrap
//     the master key. Changing the passphrase re-derives it and re-wraps the master
//     key — no resource is re-encrypted.
type (
	MasterKey  [KeySize]byte
	ContentKey [KeySize]byte
	UnlockKey  [KeySize]byte
)

// Wipe best-effort zeroes the key material. Go gives no guarantee the value was
// not copied elsewhere, so this reduces exposure rather than eliminating it.
func (k *MasterKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// Wipe best-effort zeroes the content key (see MasterKey.Wipe for the caveats).
func (k *ContentKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// Wipe best-effort zeroes the unlock key (see MasterKey.Wipe for the caveats).
func (k *UnlockKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
}

// GenerateMasterKey returns a fresh random root key. It is wrapped under the
// passphrase-derived unlock key (WrapRoot) and stored as ciphertext; the passphrase
// guards the wrap, not the key itself, so a passphrase change re-wraps it cheaply.
func GenerateMasterKey() (MasterKey, error) {
	var mk MasterKey
	if _, err := rand.Read(mk[:]); err != nil {
		return mk, fmt.Errorf("generate master key: %w", err)
	}
	return mk, nil
}

// KdfParams are the Argon2id inputs. They are public: the salt and cost
// parameters are stored server-side (per account) and embedded in gated share
// links so the same key can be re-derived on any machine from the passphrase.
type KdfParams struct {
	Algo    string `json:"algo"`
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`    // iterations
	Memory  uint32 `json:"memory"`  // KiB
	Threads uint8  `json:"threads"` // lanes
}

// Argon2id defaults. Tuned for an interactive unlock on a developer laptop; see
// docs/threat-model.md ("KDF calibration") for per-machine tuning.
const (
	defaultTime    = 3
	defaultMemory  = 64 * 1024 // 64 MiB
	defaultThreads = 4
)

// Gated-link Argon2id profile. A gated link is semi-public — anyone holding it
// has the salt, costs, and wrapped key and can brute-force offline — and link
// passwords are typically weaker than account passphrases, so the gate is tuned
// deliberately higher than the interactive account-unlock profile.
//
// Vars, not consts, only so crypto_test.go can shrink them for the gated
// round-trip test, which would otherwise pay three 256 MiB derivations;
// nothing outside a test assigns to them.
var (
	gatedTime    uint32 = 4
	gatedMemory  uint32 = 256 * 1024 // 256 MiB
	gatedThreads uint8  = 4
)

// Upper bounds on KDF parameters accepted by DeriveMasterKey. They cap the work
// (and memory) a fragment- or server-supplied set of params can force on a
// client, so a crafted link or a hostile server cannot OOM/hang it on password
// entry. The bounds sit comfortably above every profile this package mints.
const (
	maxKdfMemory  = 1 << 20 // 1 GiB, in KiB
	maxKdfTime    = 16
	maxKdfThreads = 16
	maxKdfSalt    = 1024
)

// NewKdfParams returns fresh parameters with a random salt and default costs.
func NewKdfParams() (KdfParams, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return KdfParams{}, fmt.Errorf("generate salt: %w", err)
	}
	return KdfParams{
		Algo:    "argon2id",
		Salt:    salt,
		Time:    defaultTime,
		Memory:  defaultMemory,
		Threads: defaultThreads,
	}, nil
}

// NewGatedKdfParams returns fresh parameters at the higher gated-link cost.
func NewGatedKdfParams() (KdfParams, error) {
	p, err := NewKdfParams()
	if err != nil {
		return KdfParams{}, err
	}
	p.Time = gatedTime
	p.Memory = gatedMemory
	p.Threads = gatedThreads
	return p, nil
}

// validate rejects unsupported or out-of-range KDF params before they reach the
// (expensive, attacker-influenced) derivation.
func (p KdfParams) validate() error {
	switch {
	case p.Algo != "argon2id":
		return fmt.Errorf("unsupported kdf algo %q", p.Algo)
	case len(p.Salt) == 0:
		return errors.New("kdf params missing salt")
	case len(p.Salt) > maxKdfSalt:
		return fmt.Errorf("kdf salt too long: %d bytes", len(p.Salt))
	case p.Memory == 0 || p.Memory > maxKdfMemory:
		return fmt.Errorf("kdf memory out of range: %d KiB", p.Memory)
	case p.Time == 0 || p.Time > maxKdfTime:
		return fmt.Errorf("kdf time out of range: %d", p.Time)
	case p.Threads == 0 || p.Threads > maxKdfThreads:
		return fmt.Errorf("kdf threads out of range: %d", p.Threads)
	}
	return nil
}

// DeriveMasterKey derives the master key from a passphrase and KDF parameters.
// Given the same passphrase and params it is deterministic, which is what lets a
// new machine reconstruct the key after fetching the account's stored params.
// The params are clamped first: they may come from a hostile server (account
// salt) or a crafted share link (gated fragment).
func DeriveMasterKey(passphrase string, p KdfParams) (MasterKey, error) {
	var mk MasterKey
	if err := p.validate(); err != nil {
		return mk, err
	}
	out := argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, KeySize)
	copy(mk[:], out)
	return mk, nil
}

// DeriveUnlockKey derives the passphrase-based unlock key (Argon2id over the
// account's KDF params). It is deterministic, so the same passphrase and params
// reproduce it on any machine — which is what lets a new device fetch the account's
// params + wrapped root and recover the master key. The params are clamped first
// (they may come from a hostile server).
func DeriveUnlockKey(passphrase string, p KdfParams) (UnlockKey, error) {
	var uk UnlockKey
	if err := p.validate(); err != nil {
		return uk, err
	}
	out := argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, KeySize)
	copy(uk[:], out)
	return uk, nil
}

// WrapRoot wraps the master (root) key under the passphrase-derived unlock key.
// The result is the account's wrappedRoot: stored as opaque ciphertext server-side
// (so the server stays zero-knowledge) and cached locally so a working device
// re-derives the master key from its passphrase with no server round-trip.
func WrapRoot(rk MasterKey, uk UnlockKey) (SealedBlob, error) {
	return Seal(rk[:], ContentKey(uk), aadRootWrap)
}

// UnwrapRoot reverses WrapRoot. A wrong passphrase derives a wrong unlock key and
// fails the AEAD tag here, so an incorrect passphrase is caught at unlock rather
// than producing a silently-wrong key.
func UnwrapRoot(w SealedBlob, uk UnlockKey) (MasterKey, error) {
	var rk MasterKey
	plain, err := Open(w, ContentKey(uk), aadRootWrap)
	if err != nil {
		return rk, err
	}
	if len(plain) != KeySize {
		return rk, errors.New("unwrapped root key has wrong length")
	}
	copy(rk[:], plain)
	return rk, nil
}

// DeriveAuthVerifier derives a credential that proves possession of the current
// passphrase (via its unlock key), independent of the master key. A device presents
// it when attaching; the server stores only its hash and checks it alongside the
// Ed25519 signature, so re-attaching needs the current passphrase — a cached root
// key or an old passphrase alone cannot attach a new device after a passphrase
// change. It is one-way (HKDF), so it leaks nothing about the passphrase.
func DeriveAuthVerifier(uk UnlockKey) []byte {
	r := hkdf.New(sha256.New, uk[:], nil, []byte("aqt-auth-verifier-v1"))
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf auth verifier: " + err.Error()) // unreachable for an in-memory reader
	}
	return out
}

// DeriveSigningKey derives the account's Ed25519 signing key from the master key
// via HKDF. The public half is registered with the server at signup; a device
// then proves ownership by signing a server-issued challenge. No secret is ever
// sent to the server, and a server breach leaks only public keys — it can never
// yield the master key (one-way HKDF) nor impersonate the account.
func DeriveSigningKey(mk MasterKey) ed25519.PrivateKey {
	r := hkdf.New(sha256.New, mk[:], nil, []byte("aqt-auth-ed25519-v1"))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		panic("hkdf expand failed: " + err.Error()) // unreachable for an in-memory reader
	}
	return ed25519.NewKeyFromSeed(seed)
}

// KeyFingerprint returns a stable, human-comparable fingerprint of a public key
// in the SSH SHA256 format, so two devices can confirm they hold the same key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// GenerateContentKey returns a fresh random content key.
func GenerateContentKey() (ContentKey, error) {
	var ck ContentKey
	if _, err := rand.Read(ck[:]); err != nil {
		return ck, fmt.Errorf("generate content key: %w", err)
	}
	return ck, nil
}

// SealedBlob is a self-contained AEAD ciphertext: the nonce plus the encrypted
// bytes with the authentication tag appended.
type SealedBlob struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// WrappedKey is a content key encrypted ("wrapped") under another key, e.g. the
// master key for private resources or a password-derived key for gated links.
type WrappedKey struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// AEAD additional-authenticated-data tags bind a ciphertext to its role. They are
// authenticated but not encrypted; passing a different tag to Open fails the tag
// check. This domain-separates the structurally-identical SealedBlob/WrappedKey so
// a hostile server cannot reinterpret one field as another — e.g. move a resource
// blob into the wrappedKey slot, or swap a body blob for its metadata blob (both
// sealed under the same content key). SealBound/OpenBound additionally bind the
// resource id, so a whole record (blob + meta + wrapped key) served under a
// different id fails the tag check too.
var (
	AADBlob          = []byte("aqt-blob-v1")      // resource body (file bytes or chunked-folder manifest root)
	AADMeta          = []byte("aqt-meta-v1")      // resource metadata
	AADSnapshotLabel = []byte("aqt-snaplabel-v1") // a snapshot's optional user label, sealed under the resource content key
	// Tombstone: "aqt-pack-v1" and "aqt-packroot-v1" were the removed pack-and-seal
	// folder format's tags. The constants are gone, but the strings stay retired
	// forever — reassigning either to a new role would let any surviving packed
	// ciphertext open under the new meaning.
	AADTreeRoot    = []byte("aqt-treeroot-v1")  // a Merkle-DAG folder's sealed root blob (distinct from AADBlob, so a root cannot be swapped for a body)
	AADGitRefsRoot = []byte("aqt-gitrefs-v1")   // a git-remote resource's sealed refs and bundle-chain root
	AADGitBundle   = []byte("aqt-gitbundle-v1") // one opaque, per-push-unique git bundle segment
	aadKeyWrap     = []byte("aqt-keywrap-v1")   // content key wrapped under the master key
	aadGated       = []byte("aqt-gated-v1")     // content key wrapped under a link password
	aadRootWrap    = []byte("aqt-rootwrap-v1")  // master (root) key wrapped under the unlock key
)

// Seal encrypts plaintext under a content key, binding aad as additional
// authenticated data (the ciphertext's role; see the AAD tags above). It seals the
// whole payload in one shot, so it is used for bounded payloads (small files,
// metadata, the manifest/file roots); large content streams through SealChunk.
func Seal(plaintext []byte, ck ContentKey, aad []byte) (SealedBlob, error) {
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return SealedBlob{}, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return SealedBlob{}, err
	}
	return SealedBlob{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}, nil
}

// Open decrypts a sealed blob, verifying the authentication tag over the
// ciphertext and aad. It returns an error if the key is wrong, the aad does not
// match the one used to seal, or the ciphertext was tampered with.
func Open(blob SealedBlob, ck ContentKey, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return nil, err
	}
	if len(blob.Nonce) != NonceSize {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Open(nil, blob.Nonce, blob.Ciphertext, aad)
}

// BoundAAD is the id-bound (v2) form of a v1 role tag: "aqt-blob-v1" plus id
// "abc" becomes "aqt-blob-v2:abc". The version bump keeps it disjoint from every
// v1 tag; the id makes the ciphertext openable only under the id it was stored
// for. Exposed so a caller can name the exact tag a stored blob must carry (a test
// asserting the stored form); sealing and opening go through SealBound/OpenBound.
func BoundAAD(role []byte, resourceID string) []byte {
	base, ok := strings.CutSuffix(string(role), "-v1")
	if !ok {
		panic("crypto: AAD role tag without -v1 suffix: " + string(role))
	}
	return []byte(base + "-v2:" + resourceID)
}

// SealBound is Seal with the resource id bound into the additional data, so the
// ciphertext only opens under the id it is stored under and a server swapping
// whole records between ids is detected. An empty id seals with the plain role
// tag, which is only ever the first half of a create: the id is server-assigned
// and does not exist yet, so the create path re-seals the resource bound to the
// id the moment the server returns it (nothing reads the unbound form).
func SealBound(plaintext []byte, ck ContentKey, role []byte, resourceID string) (SealedBlob, error) {
	if resourceID == "" {
		return Seal(plaintext, ck, role)
	}
	return Seal(plaintext, ck, BoundAAD(role, resourceID))
}

// OpenBound reverses SealBound: a blob fetched under an id opens only under that
// id's v2 tag. There is no unbound fallback, so a server cannot strip the binding
// by serving the v1 form of a record it moved between ids.
func OpenBound(blob SealedBlob, ck ContentKey, role []byte, resourceID string) ([]byte, error) {
	if resourceID == "" {
		return Open(blob, ck, role)
	}
	return Open(blob, ck, BoundAAD(role, resourceID))
}

// WrapKey encrypts a content key under a 32-byte wrapping key (the master key),
// bound to the key-wrap role.
func WrapKey(ck ContentKey, wrappingKey [KeySize]byte) (WrappedKey, error) {
	return wrapKeyAAD(ck, wrappingKey, aadKeyWrap)
}

// UnwrapKey reverses WrapKey, returning the original content key.
func UnwrapKey(w WrappedKey, wrappingKey [KeySize]byte) (ContentKey, error) {
	return unwrapKeyAAD(w, wrappingKey, aadKeyWrap)
}

func wrapKeyAAD(ck ContentKey, wrappingKey [KeySize]byte, aad []byte) (WrappedKey, error) {
	blob, err := Seal(ck[:], ContentKey(wrappingKey), aad)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey(blob), nil
}

func unwrapKeyAAD(w WrappedKey, wrappingKey [KeySize]byte, aad []byte) (ContentKey, error) {
	var ck ContentKey
	plain, err := Open(SealedBlob(w), ContentKey(wrappingKey), aad)
	if err != nil {
		return ck, err
	}
	if len(plain) != KeySize {
		return ck, errors.New("unwrapped key has wrong length")
	}
	copy(ck[:], plain)
	return ck, nil
}

// Share-link fragment encoding. The fragment (the part after '#') never reaches
// the server. Two modes, distinguished by a prefix so the receiver knows how to
// read them:
//
//	k.<base64url(contentKey)>      public: the key itself
//	p.<base64url(json(gatedKey))>  gated: the key wrapped under a password
const (
	fragPublic = "k."
	fragGated  = "p."
)

// gatedKey carries everything a recipient needs to turn a password into the
// content key: the Argon2id params (salt + costs) and the wrapped key.
type gatedKey struct {
	Kdf     KdfParams  `json:"kdf"`
	Wrapped WrappedKey `json:"wrapped"`
}

var b64 = base64.RawURLEncoding

// EncodeFragment builds the URL fragment for a content key. An empty password
// produces a public fragment; a non-empty password produces a gated fragment in
// which the key is wrapped under a password-derived key, so the link alone does
// not decrypt anything.
func EncodeFragment(ck ContentKey, password string) (string, error) {
	if password == "" {
		return fragPublic + b64.EncodeToString(ck[:]), nil
	}
	params, err := NewGatedKdfParams()
	if err != nil {
		return "", err
	}
	pwKey, err := DeriveMasterKey(password, params)
	if err != nil {
		return "", err
	}
	wrapped, err := wrapKeyAAD(ck, [KeySize]byte(pwKey), aadGated)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(gatedKey{Kdf: params, Wrapped: wrapped})
	if err != nil {
		return "", err
	}
	return fragGated + b64.EncodeToString(payload), nil
}

// DecodeFragment recovers the content key from a fragment. A gated fragment
// requires the matching password; the wrong password fails the AEAD tag check
// and returns an error rather than garbage.
func DecodeFragment(fragment, password string) (ContentKey, error) {
	var ck ContentKey
	switch {
	case strings.HasPrefix(fragment, fragPublic):
		raw, err := b64.DecodeString(fragment[len(fragPublic):])
		if err != nil {
			return ck, fmt.Errorf("decode fragment: %w", err)
		}
		if len(raw) != KeySize {
			return ck, errors.New("public fragment has wrong key length")
		}
		copy(ck[:], raw)
		return ck, nil
	case strings.HasPrefix(fragment, fragGated):
		if password == "" {
			return ck, errors.New("link is password-protected: password required")
		}
		raw, err := b64.DecodeString(fragment[len(fragGated):])
		if err != nil {
			return ck, fmt.Errorf("decode fragment: %w", err)
		}
		var gk gatedKey
		if err := json.Unmarshal(raw, &gk); err != nil {
			return ck, fmt.Errorf("parse gated fragment: %w", err)
		}
		pwKey, err := DeriveMasterKey(password, gk.Kdf)
		if err != nil {
			return ck, err
		}
		return unwrapKeyAAD(gk.Wrapped, [KeySize]byte(pwKey), aadGated)
	default:
		return ck, errors.New("unrecognized fragment format")
	}
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}
