// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"testing"

	"pgregory.net/rapid"
)

// TestGrantExactness is the issue #79 property: across random accounts, resources,
// and grants, a grant wrap opens for exactly the (grantee key, resource, owner,
// grantee handle) tuple it was sealed for, and for nothing and nobody else.
func TestGrantExactness(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		nAcc := rapid.IntRange(2, 4).Draw(rt, "accounts")
		mks := make([]MasterKey, nAcc)
		handles := make([]string, nAcc)
		for i := range mks {
			copy(mks[i][:], rapid.SliceOfN(rapid.Byte(), KeySize, KeySize).Draw(rt, "mk"))
			handles[i] = rapid.StringMatching(`h[0-9a-f]{6}`).Draw(rt, "handle")
		}

		type grant struct {
			resID   string
			owner   int
			grantee int
			ck      ContentKey
			wrap    []byte
		}
		nRes := rapid.IntRange(1, 3).Draw(rt, "resources")
		var grants []grant
		for r := 0; r < nRes; r++ {
			resID := rapid.StringMatching(`res[0-9a-f]{8}`).Draw(rt, "resID")
			owner := rapid.IntRange(0, nAcc-1).Draw(rt, "owner")
			var ck ContentKey
			copy(ck[:], rapid.SliceOfN(rapid.Byte(), KeySize, KeySize).Draw(rt, "ck"))
			grantee := rapid.IntRange(0, nAcc-1).Draw(rt, "grantee")
			if grantee == owner {
				grantee = (grantee + 1) % nAcc
			}
			wrap, err := WrapGrant(ck, DeriveEncKey(mks[grantee]).Public(), resID, handles[owner], handles[grantee])
			if err != nil {
				rt.Fatalf("wrap: %v", err)
			}
			grants = append(grants, grant{resID: resID, owner: owner, grantee: grantee, ck: ck, wrap: wrap})
		}

		for _, g := range grants {
			// Every account tries every wrap with the true binding: only the grantee opens it.
			for acc := range mks {
				got, err := UnwrapGrant(g.wrap, mks[acc], g.resID, handles[g.owner], handles[acc])
				if acc == g.grantee && handleUnique(handles, acc) {
					if err != nil {
						rt.Fatalf("grantee failed to open its own grant: %v", err)
					}
					if got != g.ck {
						rt.Fatal("grantee recovered the wrong content key")
					}
					continue
				}
				if acc != g.grantee && err == nil {
					rt.Fatal("a non-grantee opened a grant")
				}
			}
			// The binding is strict: any changed context field refuses to open.
			if _, err := UnwrapGrant(g.wrap, mks[g.grantee], g.resID+"x", handles[g.owner], handles[g.grantee]); err == nil {
				rt.Fatal("grant opened for a different resource id")
			}
			if _, err := UnwrapGrant(g.wrap, mks[g.grantee], g.resID, handles[g.owner]+"x", handles[g.grantee]); err == nil {
				rt.Fatal("grant opened for a different owner handle")
			}
			// A corrupted wrap never opens.
			bad := append([]byte(nil), g.wrap...)
			bad[rapid.IntRange(0, len(bad)-1).Draw(rt, "flip")] ^= 0x01
			if _, err := UnwrapGrant(bad, mks[g.grantee], g.resID, handles[g.owner], handles[g.grantee]); err == nil {
				rt.Fatal("a corrupted grant wrap opened")
			}
		}
	})
}

// handleUnique reports whether handles[i] appears exactly once: rapid can draw
// duplicate handles, and a duplicate makes "grantee opens its own grant" ambiguous
// (the info binding is by handle string, not by index).
func handleUnique(handles []string, i int) bool {
	n := 0
	for _, h := range handles {
		if h == handles[i] {
			n++
		}
	}
	return n == 1
}
