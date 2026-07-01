package crypto

import "testing"

func TestCalibrateKdfPresets(t *testing.T) {
	for _, preset := range []KdfPreset{PresetInteractive, PresetModerate, PresetSensitive} {
		p, err := CalibrateKdf(preset, 1)
		if err != nil {
			t.Fatalf("calibrate %s: %v", preset, err)
		}
		if err := p.validate(); err != nil {
			t.Fatalf("calibrated %s params invalid: %v", preset, err)
		}
		if p.Time < 1 {
			t.Errorf("%s: time must be at least 1, got %d", preset, p.Time)
		}
		if p.Memory < calibrateMemoryFloor {
			t.Errorf("%s: memory %d dropped below floor %d", preset, p.Memory, calibrateMemoryFloor)
		}
		if len(p.Salt) == 0 {
			t.Errorf("%s: expected a fresh salt", preset)
		}
	}
}

func TestCalibrateKdfUnknownPreset(t *testing.T) {
	if _, err := CalibrateKdf("bogus", 1); err == nil {
		t.Fatal("expected error for unknown preset")
	}
}

func TestCalibrateKdfFreshSalt(t *testing.T) {
	a, err := CalibrateKdf(PresetInteractive, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CalibrateKdf(PresetInteractive, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Salt) == string(b.Salt) {
		t.Fatal("expected distinct random salts across calibrations")
	}
}

func TestManualKdfParams(t *testing.T) {
	p, err := ManualKdfParams(5, 128*1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	if p.Time != 5 || p.Memory != 128*1024 || p.Threads != 2 {
		t.Fatalf("manual params not honored: %+v", p)
	}

	// Zero fields fall back to defaults rather than failing validation.
	def, err := ManualKdfParams(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := def.validate(); err != nil {
		t.Fatalf("defaulted manual params invalid: %v", err)
	}

	// Out-of-range costs are rejected, not clamped.
	if _, err := ManualKdfParams(0, (maxKdfMemory+1)*1, 0); err == nil {
		t.Fatal("expected rejection of over-large memory")
	}
}
