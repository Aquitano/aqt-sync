// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/fsatomic"
)

// Contact is a trust-on-first-use pin of another account's published keys. The
// server can substitute keys at lookup time; pinning turns that into a one-shot
// attack window, and `aqt contacts verify` closes it via out-of-band comparison.
//
// Verified records that the identity key matched a fingerprint the user supplied
// (`aqt contacts pin --fingerprint`). A first-use pin is unverified, and so is every
// pin written before the field existed: an unverified pin may be the decoy an
// unregistered email gets, so a confirmed lookup may replace it, while a verified one
// is never replaced that way.
type Contact struct {
	Email        string `json:"email"`
	Handle       string `json:"handle"`
	PublicKey    []byte `json:"publicKey"`
	EncPublicKey []byte `json:"encPublicKey"`
	PinnedAt     int64  `json:"pinnedAt"`
	Verified     bool   `json:"verified,omitempty"`
}

// LoadContacts returns the profile's pinned contacts, keyed by email in the form the
// server stores it (api.NormalizeEmail), so a pin made under another spelling of the
// same address is still found by it. A missing file is an empty set, not an error.
//
// Two stored pins for one address keep the verified one, then the older one: a later
// pin under another spelling is the kind of claim the first pin exists to refuse.
func LoadContacts(profile string) (map[string]Contact, error) {
	stored := map[string]Contact{}
	if err := loadJSON(profile, ".contacts.json", &stored); err != nil {
		return nil, err
	}
	out := make(map[string]Contact, len(stored))
	for _, c := range stored {
		c.Email = api.NormalizeEmail(c.Email)
		if kept, ok := out[c.Email]; ok && (kept.Verified && !c.Verified || kept.Verified == c.Verified && kept.PinnedAt <= c.PinnedAt) {
			continue
		}
		out[c.Email] = c
	}
	return out, nil
}

// SaveContacts persists the profile's pinned contacts atomically, private to the
// user like the profile itself (emails and key material).
func SaveContacts(profile string, contacts map[string]Contact) error {
	return saveJSON(profile, ".contacts.json", contacts)
}

// loadJSON decodes the profile's state file with the given suffix into v. A missing
// file leaves v as it is.
func loadJSON(profile, suffix string, v any) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, profile+suffix))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// saveJSON writes the profile's state file with the given suffix atomically, private
// to the user like the profile itself.
func saveJSON(profile, suffix string, v any) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(filepath.Join(dir, profile+suffix), data, 0o600)
}
