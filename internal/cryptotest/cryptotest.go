// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cryptotest supplies Argon2id parameters stripped to the cheapest cost
// the validator accepts, for tests that need a derived key rather than an
// expensive one.
//
// At the production cost a single derivation is ~55ms, and ~215ms under -race;
// a suite that signs up an account per test spends nearly all of its time there.
// The cheap params derive in ~0.2ms under -race and are otherwise identical:
// same algorithm, same random salt, same determinism. Tests that assert on cost
// itself (calibration, decoy cost distribution) must keep the real params.
//
// Nothing outside a test may import this package: every entry point takes a
// testing.TB.
package cryptotest

import (
	"testing"

	"github.com/aquitano/aqt-sync/internal/crypto"
)

// KdfParams returns fresh params (random salt) at the minimum Argon2id cost.
// Memory is 8 KiB because Argon2 requires at least 8 blocks per lane.
func KdfParams(tb testing.TB) crypto.KdfParams {
	tb.Helper()
	p, err := crypto.NewKdfParams()
	if err != nil {
		tb.Fatalf("cryptotest: new kdf params: %v", err)
	}
	p.Time = 1
	p.Memory = 8
	p.Threads = 1
	return p
}
