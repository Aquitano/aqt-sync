package crypto

import (
	"fmt"
	"runtime"
	"time"

	"golang.org/x/crypto/argon2"
)

// KdfPreset names a calibration target: a memory budget plus a wall-clock unlock
// time that CalibrateKdf scales the iteration count to hit on the local machine.
// The chosen params are public and travel with the account, so every device
// re-derives the same key regardless of which machine calibrated them.
type KdfPreset string

const (
	PresetInteractive KdfPreset = "interactive"
	PresetModerate    KdfPreset = "moderate"
	PresetSensitive   KdfPreset = "sensitive"

	// DefaultPreset balances offline-cracking resistance against a one-time
	// per-session unlock pause; see DESIGN.md section 5.
	DefaultPreset = PresetModerate
)

type presetTarget struct {
	memory uint32        // KiB
	target time.Duration // wall-clock unlock goal
}

var presetTargets = map[KdfPreset]presetTarget{
	PresetInteractive: {memory: 64 * 1024, target: 500 * time.Millisecond},
	PresetModerate:    {memory: 256 * 1024, target: 1000 * time.Millisecond},
	PresetSensitive:   {memory: 1 << 20, target: 2500 * time.Millisecond},
}

// calibrateMemoryFloor is the lowest memory CalibrateKdf drops to on a machine
// too slow to fit even one pass inside the target. It stays at the interactive
// budget, so the calibrated cost is never weaker than the lightest preset.
const calibrateMemoryFloor = 64 * 1024 // KiB

// Fixed inputs for the timing probe; the cost of Argon2id is independent of the
// passphrase and salt contents, so any fixed values measure the same work.
var (
	calibratePass = []byte("aqt-calibrate")
	calibrateSalt = []byte("aqt-calibrate-salt-16")
)

// CalibrateKdf benchmarks Argon2id on this machine and returns fresh params (with
// a random salt) tuned to the preset's target unlock time. Memory is held at the
// preset budget and the iteration count is scaled to the target; on a machine too
// slow to finish one pass within the target, memory steps down toward the floor
// first, so a weak device stays usable without dropping below the floor's cost.
func CalibrateKdf(preset KdfPreset, threads uint8) (KdfParams, error) {
	pt, ok := presetTargets[preset]
	if !ok {
		return KdfParams{}, fmt.Errorf("unknown kdf preset %q (want interactive|moderate|sensitive)", preset)
	}
	if threads == 0 {
		threads = DefaultKdfThreads()
	}
	memory := pt.memory
	timeOnePass(memory, threads) // warm the allocator before the first measurement
	per := timeOnePass(memory, threads)
	for per > pt.target && memory > calibrateMemoryFloor {
		memory /= 2
		if memory < calibrateMemoryFloor {
			memory = calibrateMemoryFloor
		}
		per = timeOnePass(memory, threads)
	}

	iters := uint32(1)
	if per > 0 {
		if n := pt.target / per; n > 1 {
			iters = uint32(n)
		}
	}
	if iters > maxKdfTime {
		iters = maxKdfTime
	}

	p, err := NewKdfParams()
	if err != nil {
		return KdfParams{}, err
	}
	p.Time = iters
	p.Memory = memory
	p.Threads = threads
	if err := p.validate(); err != nil {
		return KdfParams{}, err
	}
	return p, nil
}

// ManualKdfParams builds params from explicit costs, filling any zero field from
// the package defaults (interactive-weight memory, three iterations, auto lanes).
// It skips benchmarking, for callers that want exact, reproducible costs.
func ManualKdfParams(timeCost, memoryKiB uint32, threads uint8) (KdfParams, error) {
	p, err := NewKdfParams()
	if err != nil {
		return KdfParams{}, err
	}
	if timeCost != 0 {
		p.Time = timeCost
	}
	if memoryKiB != 0 {
		p.Memory = memoryKiB
	}
	if threads != 0 {
		p.Threads = threads
	} else {
		p.Threads = DefaultKdfThreads()
	}
	if err := p.validate(); err != nil {
		return KdfParams{}, err
	}
	return p, nil
}

// DecoyKdfCosts maps a deterministic seed (at least two bytes, e.g. an HKDF of a
// server secret and a queried email) onto the cost distribution real calibrated
// accounts carry. The package-default costs never appear on a calibrated account,
// so a decoy bootstrap built from them would mark itself; drawing from the same
// value set CalibrateKdf produces keeps a synthesized response indistinguishable.
// It lives next to the presets so a preset change updates both.
func DecoyKdfCosts(seed []byte) (timeCost, memoryKiB uint32, threads uint8) {
	var m, t byte
	if len(seed) > 0 {
		m = seed[0]
	}
	if len(seed) > 1 {
		t = seed[1]
	}
	// Draw the memory budget from the values a moderate calibration actually lands
	// on: mostly the full preset budget, sometimes the halved or floored step-downs
	// a slower machine takes. Same three-value set CalibrateKdf can produce.
	full := presetTargets[DefaultPreset].memory
	memoryKiB = full
	switch {
	case m < 26: // ~10%
		memoryKiB = calibrateMemoryFloor
	case m < 77: // ~20%
		memoryKiB = full / 2
	}
	// Iterations cluster where the ~1s target divides one Argon2id pass on common
	// hardware: several passes at the full budget, fewer once memory has stepped
	// down (a slower machine fits less work). Mirrors CalibrateKdf's memory/time
	// coupling; both stay well inside validate()'s 1..maxKdfTime bound.
	if memoryKiB < full {
		timeCost = uint32(2 + t%3) // 2..4
	} else {
		timeCost = uint32(3 + t%6) // 3..8
	}
	return timeCost, memoryKiB, defaultThreads
}

// DefaultKdfThreads returns the lane count calibration uses by default: the core
// count capped at 4, since extra lanes past a handful add little and the params
// must derive identically on every device including smaller ones.
func DefaultKdfThreads() uint8 {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return uint8(n)
}

func timeOnePass(memoryKiB uint32, threads uint8) time.Duration {
	start := time.Now()
	key := argon2.IDKey(calibratePass, calibrateSalt, 1, memoryKiB, threads, KeySize)
	dur := time.Since(start)
	runtime.KeepAlive(key)
	return dur
}
