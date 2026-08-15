// SPDX-License-Identifier: AGPL-3.0-or-later

package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
)

// TrustRoot is a release-signing public key this build accepts.
type TrustRoot struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Comment   string
	AddedIn   string
}

// trustedKeys are the release-signing public keys compiled into this build,
// base64 (standard encoding) of the raw 32-byte Ed25519 public key.
//
// Rotation: add the new key here and keep the old entry until every supported
// build carries both, signing releases with both keys for the overlap. Removing a
// key only affects builds shipped after the removal — an already-installed client
// keeps trusting whatever it was compiled with, which is why compromise recovery
// is an upgrade campaign and not a revocation. See docs/updates.md.
var trustedKeys = []struct {
	PublicKey string
	Comment   string
	AddedIn   string
}{
	{
		PublicKey: "BwNXo1smVKIpvC54/iSV+86pQQuTND8py60WPVjGLXE=",
		Comment:   "release signing key 2",
		AddedIn:   "v0.4.1",
	},
}

// TrustRoots returns the keys this build accepts on a release manifest.
var TrustRoots = sync.OnceValue(func() []TrustRoot {
	roots := make([]TrustRoot, 0, len(trustedKeys))
	for _, k := range trustedKeys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			// A malformed constant is a build-time mistake; failing loudly here beats
			// shipping a client that silently trusts one key fewer than intended.
			panic(fmt.Sprintf("update: malformed trust root %q", k.Comment))
		}
		roots = append(roots, TrustRoot{
			KeyID:     KeyID(pub),
			PublicKey: pub,
			Comment:   k.Comment,
			AddedIn:   k.AddedIn,
		})
	}
	return roots
})
