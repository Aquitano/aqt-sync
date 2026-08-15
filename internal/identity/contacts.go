// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Contact is a trust-on-first-use pin of another account's published keys. The
// server can substitute keys at lookup time; pinning turns that into a one-shot
// attack window, and `aqt contacts verify` closes it via out-of-band comparison.
type Contact struct {
	Email        string `json:"email"`
	Handle       string `json:"handle"`
	PublicKey    []byte `json:"publicKey"`
	EncPublicKey []byte `json:"encPublicKey"`
	PinnedAt     int64  `json:"pinnedAt"`
}

func contactsPath(profile string) (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, profile+".contacts.json"), nil
}

// LoadContacts returns the profile's pinned contacts, keyed by email. A missing
// file is an empty set, not an error.
func LoadContacts(profile string) (map[string]Contact, error) {
	path, err := contactsPath(profile)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]Contact{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]Contact{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SaveContacts persists the profile's pinned contacts atomically, private to the
// user like the profile itself (emails and key material).
func SaveContacts(profile string, contacts map[string]Contact) error {
	path, err := contactsPath(profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(contacts, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}
