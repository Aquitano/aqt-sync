package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/identity"
)

// TestStreamingSingleFilePushPull pushes a file above the threshold and checks it
// took the packed path and round-trips byte-for-byte through pull and cat.
func TestStreamingSingleFilePushPull(t *testing.T) {
	h := newE2E(t)

	src := filepath.Join(t.TempDir(), "big.bin")
	data := make([]byte, 9<<20) // above streamThreshold
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runPush(src, pushOptions{noClip: true, quiet: true}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if h.countPacks() == 0 {
		t.Fatal("streaming push uploaded no packs")
	}

	cl, prof, err := authedClient()
	if err != nil {
		t.Fatal(err)
	}
	mk, ok := identity.LoadSession(prof.Name)
	if !ok {
		t.Fatal("no cached session")
	}
	rows, err := collectResources(cl, mk)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, r := range rows {
		if r.Name == "big.bin" {
			id = r.ID
			if r.Kind != api.KindFile {
				t.Errorf("kind = %q, want file", r.Kind)
			}
			if r.Size != int64(len(data)) {
				t.Errorf("size = %d, want %d", r.Size, len(data))
			}
		}
	}
	if id == "" {
		t.Fatalf("pushed file not in listing; rows=%+v", rows)
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if err := runPull(id, out, "", false, false); err != nil {
		t.Fatalf("pull: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("pull content mismatch")
	}

	captured := captureStdout(t, func() {
		if err := runPull(id, "", "", true, false); err != nil {
			t.Fatalf("cat: %v", err)
		}
	})
	if !bytes.Equal([]byte(captured), data) {
		t.Fatal("cat content mismatch")
	}

	if err := runShare(id, "", true); err == nil || !strings.Contains(err.Error(), "streamed") {
		t.Errorf("share of streamed file err = %v, want a streamed rejection", err)
	}
}
