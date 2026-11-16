// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import "slices"

const revokedSuffix = ".revoked.json"

// RevokedGrant is a grant this device revoked: the resource and the grantee handle
// that lost it. A rotation follows a grant whose signature covers the key it replaces,
// and a server that serves a resource as it was before the revoke serves that key and
// the revoked grant's signature with it. This record keeps the revoking device's own
// rotations from following the grant whatever key the server serves; the owner's other
// devices do not hold it.
type RevokedGrant struct {
	ResourceID    string `json:"resourceId"`
	GranteeHandle string `json:"granteeHandle"`
}

// LoadRevokedGrants returns the grants this device revoked on the profile's account. A
// missing file is an empty set, not an error.
func LoadRevokedGrants(profile string) ([]RevokedGrant, error) {
	var grants []RevokedGrant
	if err := loadJSON(profile, revokedSuffix, &grants); err != nil {
		return nil, err
	}
	return grants, nil
}

// RecordRevokedGrant notes that this device revoked handle's grant on resource id.
func RecordRevokedGrant(profile, id, handle string) error {
	grants, err := LoadRevokedGrants(profile)
	if err != nil {
		return err
	}
	g := RevokedGrant{ResourceID: id, GranteeHandle: handle}
	if slices.Contains(grants, g) {
		return nil
	}
	return saveJSON(profile, revokedSuffix, append(grants, g))
}

// ClearRevokedGrant drops the record of a revoke once this device grants handle the
// resource again.
func ClearRevokedGrant(profile, id, handle string) error {
	grants, err := LoadRevokedGrants(profile)
	if err != nil {
		return err
	}
	g := RevokedGrant{ResourceID: id, GranteeHandle: handle}
	if !slices.Contains(grants, g) {
		return nil
	}
	return saveJSON(profile, revokedSuffix, slices.DeleteFunc(grants, func(r RevokedGrant) bool { return r == g }))
}
