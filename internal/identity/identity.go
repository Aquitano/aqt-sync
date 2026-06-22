// Package identity manages the local profile: server, account handle, device
// token, and the KDF params needed to re-derive the master key from a passphrase.
//
// The profile holds the device token (for API auth) but never the master key or
// passphrase. The master key is derived on demand and kept only in memory.
// Persisting the token in a 0600 file rather than the OS keychain is a v1
// simplification (DESIGN.md section 5).
package identity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

const DefaultProfile = "default"

// ErrNoProfile signals that no profile is stored yet.
var ErrNoProfile = errors.New("no aqt profile found; run `aqt login` first")

type Profile struct {
	Name        string           `json:"name"`
	Server      string           `json:"server"`
	Email       string           `json:"email"`
	OwnerHandle string           `json:"ownerHandle"`
	DeviceID    string           `json:"deviceId"`
	Token       string           `json:"token"`
	Kdf         crypto.KdfParams `json:"kdf"`
}

// Unlock derives the master key from the passphrase using the profile's stored
// KDF params.
func (p *Profile) Unlock(passphrase string) (crypto.MasterKey, error) {
	return crypto.DeriveMasterKey(passphrase, p.Kdf)
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
	return &p, nil
}

// Save writes the profile with owner-only (0600) permissions.
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
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, p.Name+".json"), b, 0o600)
}

// --- session cache ---
//
// The session cache holds the derived master key so a working session does not
// re-prompt for the passphrase on every command. SECURITY TRADE-OFF: the master
// key is written to a 0600 file, so anyone who can read that file can decrypt
// your data. Exposure is bounded by the TTL and cleared by `aqt logout`.

type session struct {
	MasterKey []byte `json:"masterKey"`
	ExpiresAt int64  `json:"expiresAt"` // unix seconds; 0 means no expiry
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

// SaveSession caches the master key for ttl. A non-positive ttl caches it with
// no expiry (until logout).
func SaveSession(name string, mk crypto.MasterKey, ttl time.Duration) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var exp int64
	if ttl > 0 {
		exp = time.Now().Add(ttl).Unix()
	}
	b, err := json.Marshal(session{MasterKey: mk[:], ExpiresAt: exp})
	if err != nil {
		return err
	}
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadSession returns the cached master key if present and unexpired. An expired
// or malformed cache is removed and reported as a miss.
func LoadSession(name string) (crypto.MasterKey, bool) {
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
	if err := json.Unmarshal(b, &s); err != nil || len(s.MasterKey) != crypto.KeySize {
		os.Remove(path)
		return mk, false
	}
	if s.ExpiresAt != 0 && time.Now().Unix() > s.ExpiresAt {
		os.Remove(path)
		return mk, false
	}
	copy(mk[:], s.MasterKey)
	return mk, true
}

// ClearSession removes any cached master key.
func ClearSession(name string) error {
	path, err := sessionPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
