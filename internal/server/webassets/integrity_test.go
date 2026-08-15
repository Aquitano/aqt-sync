// SPDX-License-Identifier: AGPL-3.0-or-later

package webassets

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// vendoredDigests pins the SHA-256 of each vendored runtime AS SERVED. The README
// also lists the upstream npm tarball digests, but those verify the packages these
// files were built from, not the files themselves — a re-wrapped single-file build
// cannot be checked against a tarball hash, so nothing stopped a one-character edit
// from shipping. These handle the fragment key and the plaintext; treat any failure
// here as a supply-chain event until proven otherwise.
//
// To update deliberately: re-vendor, run this test, and copy the reported digest in
// along with the version bump in the README.
var vendoredDigests = map[string]string{
	"fzstd-0.1.1.js":               "51a9129225337a42de06ef1ae5ddf6ceaa822f7243f6b8c54f8b7c6f587ad5a5",
	"hash-wasm-argon2-4.9.0.js":    "541f1f7f56086b7c36d16b0a4f453815d4f1b9ee61bd390570ed3da6ced10817",
	"libsodium-0.7.10.js":          "3d878d341f873679db59ccecf2e9e8dda80d6f8b395eb5b3a3608dd55bb38a61",
	"libsodium-wrappers-0.7.10.js": "2d50c83ba3e92741e36626f0a07eb9a5f28713054e50ddeffaa45f37336d3038",
}

func TestVendoredAssetsMatchPinnedDigests(t *testing.T) {
	for name, want := range vendoredDigests {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s digest = %s, pinned %s — the vendored runtime changed; re-vendor deliberately or treat as tampering", name, got, want)
		}
	}
}
