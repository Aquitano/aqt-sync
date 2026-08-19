// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity manages the local profile: server, account handle, device
// token, and the KDF params needed to re-derive the master key from a passphrase.
//
// The profile never holds the master key or passphrase; the master key is derived
// on demand and kept only in memory. The device token and the key that seals the
// cached session are kept in the OS keychain when one is available, so the on-disk
// files hold no usable credential; on a host with no keychain backend (e.g. a
// headless server) both fall back to the machine-bound 0600 file.
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
)

const DefaultProfile = "default"

// ErrNoProfile signals that no profile is stored yet.
var ErrNoProfile = errors.New("no aqt profile found; run `aqt login` first")

type Profile struct {
	Name        string            `json:"name"`
	Server      string            `json:"server"`
	Email       string            `json:"email"`
	OwnerHandle string            `json:"ownerHandle"`
	DeviceID    string            `json:"deviceId"`
	Token       string            `json:"token"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Kdf         crypto.KdfParams  `json:"kdf"`
	WrappedRoot crypto.SealedBlob `json:"wrappedRoot"`
	// AuthEpoch is the account auth epoch this device's token was issued under. A
	// passphrase change bumps it; the server rejects a token whose epoch is behind.
	AuthEpoch int `json:"authEpoch,omitempty"`
	// SessionTTLSeconds is the cache lifetime selected at signup/login; zero means
	// cache until lock or logout.
	SessionTTLSeconds int64 `json:"sessionTtlSeconds,omitempty"`
}

// Unlock recovers the account's master (root) key from the passphrase: it derives
// the unlock key from the stored KDF params and uses it to unwrap the locally-cached
// wrapped root, so no server round-trip is needed. A wrong passphrase fails the
// unwrap's AEAD tag rather than yielding a silently-wrong key.
func (p *Profile) Unlock(passphrase string) (crypto.MasterKey, error) {
	uk, err := crypto.DeriveUnlockKey(passphrase, p.Kdf)
	if err != nil {
		return crypto.MasterKey{}, err
	}
	defer uk.Wipe()
	return crypto.UnwrapRoot(p.WrappedRoot, uk)
}

func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "aqt"), nil
}

// Load reads a profile by name (empty means the default).
func Load(name string) (*Profile, error) {
	if name == "" {
		name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Token == "" {
		if tok, ok := keychainLoadToken(name); ok {
			p.Token = tok
		}
	}
	return &p, nil
}

// Save writes the profile with owner-only (0600) permissions. When a keychain is
// available the device token is moved into it and omitted from the file, so a
// readable profile carries no usable credential; without a keychain the token
// stays in the 0600 file.
func Save(p *Profile) error {
	if p.Name == "" {
		p.Name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	stored := *p
	if stored.Token != "" && keychainStoreToken(stored.Name, stored.Token) {
		stored.Token = ""
	}
	b, err := json.MarshalIndent(&stored, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(filepath.Join(dir, p.Name+".json"), b, 0o600)
}

// --- session cache ---
//
// The session cache holds the derived master key so a working session does not
// re-prompt for the passphrase on every command. The key is encrypted at rest
// before being written to a 0600 file. The sealing key is a random per-profile key
// kept in the OS keychain (saveSealingKey); on a host with no keychain backend it
// falls back to a machine-bound key (machineBoundKey). Either way a copied or
// backed-up session file is useless on another machine — closing the
// home-dir-backup / cloud-sync exposure.
//
// SECURITY TRADE-OFF: a process running as the same user can still reach the
// keychain (or re-derive the machine key) and open the cache. Fully closing that
// needs a passphrase/biometric-gated agent or hardware enclave; see
// docs/threat-model.md ("Still open"). Exposure is otherwise bounded by the TTL and cleared by `aqt logout`.

type session struct {
	Sealed    crypto.SealedBlob `json:"sealed"`
	ExpiresAt int64             `json:"expiresAt"` // unix seconds; 0 means no expiry
}

// sessionAAD domain-separates the at-rest session seal from other ciphertexts.
const sessionAAD = "aqt-session-at-rest-v1"

// machineSecretFn is overridable in tests to simulate a different machine.
var machineSecretFn = machineSecret

// machineBoundKey derives an at-rest encryption key from a stable per-machine
// secret, so a sealed session can only be opened on the machine that wrote it. It
// is the fallback when no OS keychain backend is available.
func machineBoundKey() crypto.ContentKey {
	sum := sha256.Sum256(append([]byte(sessionAAD+"\x00"), machineSecretFn()...))
	return crypto.ContentKey(sum)
}

// machineSecret returns a stable identifier for this machine that does not travel
// in a home-directory backup, so a restored/synced session file cannot be
// decrypted elsewhere. It falls back to the hostname (weaker, but still binds the
// cache to this host rather than leaving the key in cleartext).
func machineSecret() []byte {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return []byte("aqt-machine-id:" + s)
			}
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			if id := parsePlatformUUID(out); id != "" {
				return []byte("aqt-platform-uuid:" + id)
			}
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return []byte("aqt-host:" + h)
	}
	return []byte("aqt-no-machine-binding")
}

// parsePlatformUUID extracts the IOPlatformUUID value from `ioreg` output.
func parsePlatformUUID(out []byte) string {
	const marker = `"IOPlatformUUID" = "`
	s := string(out)
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func sessionPath(name string) (string, error) {
	if name == "" {
		name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".session"), nil
}

// SaveSession caches the master key for ttl. Zero means no expiry (until lock or
// logout); negative values are invalid rather than silently becoming unbounded.
func SaveSession(name string, mk crypto.MasterKey, ttl time.Duration) error {
	if ttl < 0 {
		return errors.New("session TTL must be zero or positive")
	}
	if name == "" {
		name = DefaultProfile
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sealed, err := crypto.Seal(mk[:], saveSealingKey(name), []byte(sessionAAD))
	if err != nil {
		return err
	}
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	b, err := json.Marshal(session{Sealed: sealed, ExpiresAt: exp})
	if err != nil {
		return err
	}
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(path, b, 0o600)
}

// LoadSession returns the cached master key if present and unexpired. An expired
// or malformed cache is removed and reported as a miss.
func LoadSession(name string) (crypto.MasterKey, bool) {
	if name == "" {
		name = DefaultProfile
	}
	var mk crypto.MasterKey
	path, err := sessionPath(name)
	if err != nil {
		return mk, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return mk, false
	}
	var s session
	if err := json.Unmarshal(b, &s); err != nil {
		os.Remove(path)
		return mk, false
	}
	if s.ExpiresAt != 0 && time.Now().Unix() > s.ExpiresAt {
		os.Remove(path)
		return mk, false
	}
	// Try the keychain sealing key, then the machine-bound fallback. A failure on
	// all candidates means the file was copied from another machine, the keychain
	// entry is gone, or it predates this format — treat any of them as a miss.
	for _, ck := range loadSealingKeys(name) {
		if plain, err := crypto.Open(s.Sealed, ck, []byte(sessionAAD)); err == nil && len(plain) == crypto.KeySize {
			copy(mk[:], plain)
			return mk, true
		}
	}
	os.Remove(path)
	return mk, false
}

// ClearSession removes any cached master key and its keychain sealing key. The
// device stays attached (the token is left in place), it is just locked again.
func ClearSession(name string) error {
	if name == "" {
		name = DefaultProfile
	}
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keychainDropSealingKey(name) // best-effort; the sealed file is already gone
	return nil
}

// Delete removes a local profile and every credential derived for it. Server-side
// device revocation is deliberately the caller's responsibility so a network
// failure cannot be mistaken for a completed logout.
func Delete(name string) error {
	if name == "" {
		name = DefaultProfile
	}
	if err := ClearSession(name); err != nil {
		return err
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, name+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	keychainDropToken(name)
	return nil
}

// baseAAD domain-separates the at-rest seal of a folder's local base manifest from
// the session-cache seal, so a session blob and a base blob can never be
// interchanged even where the two seals share a key (a host with no keychain, where
// both fall back to the machine-bound key).
const baseAAD = "aqt-base-at-rest-v1"

// ErrBaseSeal is returned by OpenBase when no candidate sealing key opens the base
// manifest — typically a base sealed under a different profile or copied from
// another machine.
var ErrBaseSeal = errors.New("aqt: could not open sealed base manifest (different profile or machine?)")

// SealBase encrypts a folder's local base manifest for storage at rest, under a
// per-profile key that survives lock and logout (see baseKeyID), falling back to the
// machine-bound key where no keychain exists. A backed-up or copied .aqt/base.json
// is therefore useless on another machine and exposes neither the chunk decryption
// keys nor the inline plaintext it holds.
func SealBase(name string, plaintext []byte) (crypto.SealedBlob, error) {
	if name == "" {
		name = DefaultProfile
	}
	return crypto.Seal(plaintext, saveBaseSealingKey(name), []byte(baseAAD))
}

// OpenBase decrypts a base manifest sealed by SealBase, trying each candidate key in
// turn so a base still opens if the keychain came or went between save and load, or
// if it was sealed by a build that used the session key.
func OpenBase(name string, blob crypto.SealedBlob) ([]byte, error) {
	if name == "" {
		name = DefaultProfile
	}
	for _, ck := range loadBaseSealingKeys(name) {
		if plain, err := crypto.Open(blob, ck, []byte(baseAAD)); err == nil {
			return plain, nil
		}
	}
	return nil, ErrBaseSeal
}
