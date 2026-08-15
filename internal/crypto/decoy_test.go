// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import "testing"

// The bootstrap decoy must draw its Argon2id costs from the same value set a real
// moderate calibration lands on, deterministically per seed. If it drew from a single
// constant (the old package default), every decoy would carry an identical fingerprint
// and an attacker could classify unknown emails off GET /v1/account/salt.
func TestDecoyKdfCostsDeterministicAndInDistribution(t *testing.T) {
	seed := []byte{5, 200}
	t1, m1, th1 := DecoyKdfCosts(seed)
	t2, m2, th2 := DecoyKdfCosts(seed)
	if t1 != t2 || m1 != m2 || th1 != th2 {
		t.Fatalf("non-deterministic for a fixed seed: (%d,%d,%d) vs (%d,%d,%d)", t1, m1, th1, t2, m2, th2)
	}

	full := presetTargets[DefaultPreset].memory
	memCounts := map[uint32]int{}
	for i := 0; i < 256; i++ {
		tc, mem, threads := DecoyKdfCosts([]byte{byte(i), byte(i * 7)})
		if threads != defaultThreads {
			t.Fatalf("seed %d: threads %d, want %d", i, threads, defaultThreads)
		}
		// Memory must be one of the three values CalibrateKdf can produce for the
		// moderate preset: the full budget, the halved step, or the floor.
		if mem != calibrateMemoryFloor && mem != full/2 && mem != full {
			t.Fatalf("seed %d: memory %d KiB is off the calibration distribution", i, mem)
		}
		// Every drawn cost must pass the KDF validator, so a decoy never mints params a
		// real account could not carry.
		if _, err := ManualKdfParams(tc, mem, threads); err != nil {
			t.Fatalf("seed %d: costs (%d,%d,%d) do not validate: %v", i, tc, mem, threads, err)
		}
		memCounts[mem]++
	}
	// The whole point of the fix: the params vary across seeds rather than pinning one
	// constant an attacker could match.
	if len(memCounts) < 2 {
		t.Fatalf("decoy memory is constant across seeds (%v); still a fingerprint", memCounts)
	}
}
