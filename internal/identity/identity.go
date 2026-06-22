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
