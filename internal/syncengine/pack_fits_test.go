// SPDX-License-Identifier: AGPL-3.0-or-later

package syncengine

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
)

// The client's pack arithmetic used to check the target only after appending, so a
// MaxNodeBytes directory node on top of a near-target buffer assembled a ~40 MiB
// pack against the server's 32 MiB cap — a non-retryable 413 (issue #183).
// FitsInPack is the dispatch-before-append rule both builders now share.
func TestFitsInPack(t *testing.T) {
	// The audit's exact shape: a full 16 MiB target region plus a 24 MiB node.
	if FitsInPack(DefaultPackTarget, 2048, MaxNodeBytes) {
		t.Fatal("target region + max node claimed to fit the wire cap")
	}
	// Small objects on a modest region fit.
	if !FitsInPack(1<<20, 100, 64<<10) {
		t.Fatal("small append rejected")
	}
	// A single max-size node in an empty pack must fit on its own.
	if !FitsInPack(0, 0, MaxNodeBytes) {
		t.Fatal("a lone MaxNodeBytes object must fit one pack")
	}
}

// A pack built under the FitsInPack rule serializes within api.MaxPackBytes even
// with the index trailer appended, across adversarial object sizes.
func TestPackBuilderStaysUnderWireCap(t *testing.T) {
	sizes := []int{1, 64 << 10, 8 << 20, MaxNodeBytes, 3, 12 << 20, 24 << 20, 5 << 20}
	pb := NewPackBuilder()
	var packs [][]byte
	for i, n := range sizes {
		obj := make([]byte, n)
		rand.Read(obj)
		if !pb.Empty() && !FitsInPack(pb.Size(), pb.Objects(), len(obj)) {
			_, pack := pb.Finish()
			packs = append(packs, pack)
			pb = NewPackBuilder()
		}
		pb.Add(fmt.Sprintf("%064d", i), obj)
	}
	if !pb.Empty() {
		_, pack := pb.Finish()
		packs = append(packs, pack)
	}
	for i, pack := range packs {
		if len(pack) > api.MaxPackBytes {
			t.Fatalf("pack %d serialized to %d bytes, over the %d wire cap", i, len(pack), api.MaxPackBytes)
		}
	}
}
