// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquitano/aqt-sync/internal/api"
	"github.com/aquitano/aqt-sync/internal/crypto"
	"github.com/aquitano/aqt-sync/internal/identity"
	"github.com/aquitano/aqt-sync/internal/syncengine"
)

// A streamed file large enough that its chunk list overflows the resource blob must
// store the list indirectly (as sealed segments) and still round-trip byte-for-byte
// through the two-phase pull.
func TestStreamingIndirectChunkListPushPull(t *testing.T) {
	newE2E(t)

	src := filepath.Join(t.TempDir(), "huge.bin")
	// 64 MiB is ~256 chunks at the large profile's 256K average, comfortably past
	// the 128-record indirection threshold. 40 MiB sat right on the boundary:
	// content-defined chunking of random data landed at 127 chunks on one CI run,
	// making the "must be indirect" assertion flaky.
	data := make([]byte, 64<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pushQuiet(src, pushOptions{noClip: true}); err != nil {
		t.Fatalf("push: %v", err)
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
		if r.Name == "huge.bin" {
			id = r.ID
		}
	}
	if id == "" {
		t.Fatalf("pushed file not in listing; rows=%+v", rows)
	}

	// The stored root must actually be indirect, else this test is vacuous.
	res, err := cl.GetResource(id)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := crypto.UnwrapKey(*res.WrappedKey, [crypto.KeySize]byte(mk))
	if err != nil {
		t.Fatal(err)
	}
	root, err := syncengine.OpenFileRoot(res.Blob, ck, id)
	if err != nil {
		t.Fatal(err)
	}
	if !root.Indirect() {
		t.Fatalf("expected an indirect chunk list for a 40 MiB file, got %d inline chunks", len(root.Chunks))
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
		t.Fatal("indirect pull content mismatch")
	}
}

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

	if err := pushQuiet(src, pushOptions{noClip: true}); err != nil {
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
}
