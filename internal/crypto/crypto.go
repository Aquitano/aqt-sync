// Package crypto implements aqt's zero-knowledge key hierarchy and blob sealing.
//
// The hierarchy is: passphrase --Argon2id--> master key --wraps--> content key,
// where each resource gets its own random content key and the content key seals
// the resource bytes with XChaCha20-Poly1305. The server never sees a passphrase,
// a master key, or an unwrapped content key.
package crypto

import (
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

// DeriveMasterKey derives the master key from a passphrase and KDF parameters.
// Given the same passphrase and params it is deterministic, which is what lets a
// new machine reconstruct the key after fetching the account's stored params.
func DeriveMasterKey(passphrase string, p KdfParams) (MasterKey, error) {
	var mk MasterKey
	if p.Algo != "argon2id" {
		return mk, fmt.Errorf("unsupported kdf algo %q", p.Algo)
	}
	if len(p.Salt) == 0 {
		return mk, errors.New("kdf params missing salt")
	}
	out := argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Threads, KeySize)
	copy(mk[:], out)
	return mk, nil
}

// DeriveAuthKey derives a server-facing authentication key from the master key.
// It is what a device sends to prove account ownership: the server stores only a
// hash of it. Because it is a one-way HKDF of the master key, possession of the
// auth key (or the server's stored hash) never yields the encryption master key,
// so a server compromise still cannot decrypt data — only mount the same offline
// passphrase-guessing attack that Argon2id already makes expensive.
func DeriveAuthKey(mk MasterKey) []byte {
	r := hkdf.New(sha256.New, mk[:], nil, []byte("aqt-auth-v1"))
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf expand failed: " + err.Error()) // only fails on impossible reader errors
	}
	return out
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

// Seal encrypts plaintext under a content key. v1 seals the whole payload in one
// shot; chunked streaming for large files is deferred (DESIGN.md section 5).
func Seal(plaintext []byte, ck ContentKey) (SealedBlob, error) {
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return SealedBlob{}, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return SealedBlob{}, err
	}
	return SealedBlob{Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, nil)}, nil
}

// Open decrypts a sealed blob, verifying the authentication tag. It returns an
// error if the key is wrong or the ciphertext was tampered with.
func Open(blob SealedBlob, ck ContentKey) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		return nil, err
	}
	if len(blob.Nonce) != NonceSize {
		return nil, errors.New("invalid nonce length")
	}
	return aead.Open(nil, blob.Nonce, blob.Ciphertext, nil)
}

// WrapKey encrypts a content key under a 32-byte wrapping key.
func WrapKey(ck ContentKey, wrappingKey [KeySize]byte) (WrappedKey, error) {
	blob, err := Seal(ck[:], ContentKey(wrappingKey))
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey(blob), nil
}

// UnwrapKey reverses WrapKey, returning the original content key.
func UnwrapKey(w WrappedKey, wrappingKey [KeySize]byte) (ContentKey, error) {
	var ck ContentKey
	plain, err := Open(SealedBlob(w), ContentKey(wrappingKey))
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
	params, err := NewKdfParams()
	if err != nil {
		return "", err
	}
	pwKey, err := DeriveMasterKey(password, params)
	if err != nil {
		return "", err
	}
	wrapped, err := WrapKey(ck, [KeySize]byte(pwKey))
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
		return UnwrapKey(gk.Wrapped, [KeySize]byte(pwKey))
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
