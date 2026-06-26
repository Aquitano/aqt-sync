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
	"crypto/subtle"
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

// Key is a 32-byte symmetric key. MasterKey and ContentKey are distinct types so
// the compiler stops us from passing one where the other is meant.
type (
	MasterKey  [KeySize]byte
	ContentKey [KeySize]byte
)

// Wipe best-effort zeroes the key material. Go gives no guarantee the value was
// not copied elsewhere, so this reduces exposure rather than eliminating it.
func (k *MasterKey) Wipe() {
	for i := range k {
		k[i] = 0
	}
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
// DESIGN.md section 5 for the open question of per-machine tuning.
const (
	defaultTime    = 3
	defaultMemory  = 64 * 1024 // 64 MiB
	defaultThreads = 4
)

// Gated-link Argon2id profile. A gated link is semi-public — anyone holding it
// has the salt, costs, and wrapped key and can brute-force offline — and link
// passwords are typically weaker than account passphrases, so the gate is tuned
// deliberately higher than the interactive account-unlock profile.
const (
	gatedTime    = 4
	gatedMemory  = 256 * 1024 // 256 MiB
	gatedThreads = 4
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
// sealed under the same content key). Binding the resource id as well is a future
// step: the id is server-assigned and unknown when the client seals on create.
var (
	AADBlob     = []byte("aqt-blob-v1")     // resource body (file bytes or chunked-folder manifest root)
	AADMeta     = []byte("aqt-meta-v1")     // resource metadata
	AADPack     = []byte("aqt-pack-v1")     // a pack-and-seal tarball segment (sealed under the folder content key)
	AADPackRoot = []byte("aqt-packroot-v1") // a pack-and-seal folder's sealed root blob
	aadKeyWrap  = []byte("aqt-keywrap-v1")  // content key wrapped under the master key
	aadGated    = []byte("aqt-gated-v1")    // content key wrapped under a link password
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

// ConstantTimeEqual reports whether two keys are equal without leaking timing.
func ConstantTimeEqual(a, b ContentKey) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}
