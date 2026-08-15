// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
)

// The tree-root drift check lives inside rotateTree's reseal callback, so its error
// reaches the command through rotateResource rather than being returned directly.
// runShareRevoke and runPrivate both branch on errors.Is(err, errTreeRootDrift) to
// revoke without rotating and warn that the content key is unchanged; if the wrapping
// stopped surviving the callback they would fail hard instead and silently lose that
// path. The rotate success paths are covered end-to-end elsewhere, but nothing
// exercises this branch, so pin it here.
func TestRotateResourcePreservesResealError(t *testing.T) {
	drift := fmt.Errorf("%w: recomputed tree root a does not match stored root b", errTreeRootDrift)

	var handed crypto.ContentKey
	got, err := rotateResource(
		nil, // reseal fails before the client is touched
		"res-id",
		api.GetResourceResponse{},
		crypto.ContentKey{},
		crypto.MasterKey{},
		"",
		func(newCK crypto.ContentKey) (resealed, error) {
			handed = newCK
			return resealed{}, drift
		},
	)
	if !errors.Is(err, errTreeRootDrift) {
		t.Fatalf("reseal error lost its errTreeRootDrift wrapping: %v", err)
	}
	if got != (crypto.ContentKey{}) {
		t.Error("a failed rotate handed the caller a content key")
	}
	if handed == (crypto.ContentKey{}) {
		t.Error("reseal was given a zero content key")
	}
}
