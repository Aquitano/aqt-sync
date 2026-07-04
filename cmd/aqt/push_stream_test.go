package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
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
	// ~40 MiB is >128 chunks at the large profile's 256K average, so the chunk list
	// crosses the indirection threshold.
	data := make([]byte, 40<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runPush(src, pushOptions{noClip: true, quiet: true}); err != nil {
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
	root, err := syncengine.OpenFileRoot(res.Blob, ck)
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

// Rotating the content key of a streamed file would re-PUT its root blob with no
// ChunkRefs, dropping the GC roots that keep its chunk objects alive. runPrivate must
// refuse it, and the file must remain pullable byte-for-byte.
func TestPrivateRefusedOnStreamedFile(t *testing.T) {
	newE2E(t)

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
		}
	}
	if id == "" {
		t.Fatalf("pushed file not in listing; rows=%+v", rows)
	}

	if err := runPrivate(id); err == nil || !strings.Contains(err.Error(), "streamed") {
		t.Fatalf("private of streamed file err = %v, want a refusal", err)
	}

	out := filepath.Join(t.TempDir(), "out.bin")
	if err := runPull(id, out, "", false, false); err != nil {
		t.Fatalf("pull after refused private: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("streamed file content changed after a refused private")
	}
}
