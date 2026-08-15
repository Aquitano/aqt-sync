// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/syncengine"
)

func TestSaveStateRoundTripAtomic(t *testing.T) {
	root := t.TempDir()
	ctl := filepath.Join(root, syncengine.ControlDir)
	if err := os.MkdirAll(ctl, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := saveState(root, folderState{ID: "res-1", Server: "https://one.example"}); err != nil {
		t.Fatal(err)
	}
	// Overwrite with new content; the file must end up holding the new state.
	if err := saveState(root, folderState{ID: "res-2", Server: "https://two.example"}); err != nil {
		t.Fatal(err)
	}

	st, err := loadState(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != "res-2" || st.Server != "https://two.example" {
		t.Fatalf("round-trip mismatch: %+v", st)
	}

	// File mode bits are a Unix concept; Windows reports 0666 for a writable file.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(controlPath(root, stateFile)); err != nil {
			t.Fatal(err)
		} else if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("state perms = %o, want 600", perm)
		}
	}

	ents, err := os.ReadDir(ctl)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".aqt-tmp-") {
			t.Fatalf("leftover temp file after saveState: %s", e.Name())
		}
	}
}
